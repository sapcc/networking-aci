# Copyright 2016 SAP SE
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import signal
import time

from neutron_lib.agent import topics
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron.agent import rpc as agent_rpc
from neutron.db import db_base_plugin_v2 as db
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from stevedore import driver

from networking_aci._i18n import _LI, _LE
from networking_aci.plugins.ml2.drivers.mech_aci import cobra_manager
from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const
from networking_aci.plugins.ml2.drivers.mech_aci import rpc_api

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class AciNeutronAgent(rpc_api.ACIRpcAPI):
    target = oslo_messaging.Target(version='1.4')

    def __init__(self,
                 minimize_polling=False,
                 quitting_rpc_timeout=None,
                 conf=None,
                 aci_monitor_respawn_interval=aci_const.DEFAULT_ACI_RESPAWN):
        self.tenant_manager = driver.DriverManager(namespace='aci.tenant.managers', name=CONF.ml2_aci.tenant_manager,
                                                   invoke_on_load=True).driver

        self.db = db.NeutronDbPluginV2()

        self.aci_monitor_respawn_interval = aci_monitor_respawn_interval
        self.minimize_polling = minimize_polling,
        self.polling_interval = CONF.ml2_aci.polling_interval
        self.sync_batch_size = CONF.ml2_aci.sync_batch_size
        self.sync_marker = ""

        self.sync_active = CONF.ml2_aci.sync_active
        self.prune_orphans = CONF.ml2_aci.prune_orphans
        self.iter_num = 0
        self.run_daemon_loop = True
        self.quitting_rpc_timeout = quitting_rpc_timeout
        self.catch_sigterm = False

        self.agent_id = 'aci-agent-%s' % CONF.host

        self.setup_rpc()

        self.agent_state = {
            'binary': 'neutron-aci-agent',
            'host': CONF.host,
            'topic': n_const.L2_AGENT_TOPIC,
            'configurations': {},
            'agent_type': aci_const.ACI_AGENT_TYPE,
            'start_flag': True}

        self.aci_manager = cobra_manager.CobraManager(self.agent_rpc, self.tenant_manager)
        self.connection.consume_in_threads()

        non_epg_syncloop = loopingcall.FixedIntervalLoopingCall(self._run_non_epg_syncloop)
        non_epg_syncloop.start(interval=CONF.ml2_aci.non_epg_syncloop_interval,
                               stop_on_exception=False)

    # Start RPC callbacks

    @log_helpers.log_method_call
    def bind_port_postcommit(self, port, host_config, segment, next_segment):
        self.aci_manager.ensure_static_bindings_configured(port['network_id'], host_config,
                                                           encap=next_segment['segmentation_id'])

    @log_helpers.log_method_call
    def delete_port(self, context, port, host_config, clearable_phys_doms, clearable_bm_entities=None,
                    reset_bindings_to_infra=False):
        self.aci_manager.ensure_static_bindings_configured(port['network_id'], host_config, encap=1, delete=True,
                                                           physdoms_to_clear=clearable_phys_doms)

        if reset_bindings_to_infra:
            # sync infra mode - hostgroup is in baremetal mode so we have to override some values
            host_config['hostgroup_mode'] = aci_const.MODE_INFRA
            host_config['pc_policy_group'] = host_config['infra_pc_policy_group']
            self.aci_manager.ensure_hostgroup_mode_config(host_config, source="via port delete cleanup")

        if clearable_bm_entities:
            for bm_entity in clearable_bm_entities:
                self.aci_manager.clean_baremetal_objects(bm_entity)

    @log_helpers.log_method_call
    def create_network(self, context, network, external=False):
        self.aci_manager.ensure_domain_and_epg(context, network['id'], external=external)

    @log_helpers.log_method_call
    def delete_network(self, context, network):
        self.aci_manager.delete_domain_and_epg(network['id'])

    @log_helpers.log_method_call
    def create_subnet(self, context, subnet, external, address_scope_name, network_az):
        self.aci_manager.create_subnet(subnet, external=external, address_scope_name=address_scope_name,
                                       network_az=network_az)

    @log_helpers.log_method_call
    def delete_subnet(self, context, subnet, external, address_scope_name, network_az, last_on_network):
        self.aci_manager.delete_subnet(subnet, external=external, address_scope_name=address_scope_name,
                                       network_az=network_az, last_on_network=last_on_network)

    @log_helpers.log_method_call
    def clean_baremetal_objects(self, context, resource_name):
        self.aci_manager.clean_baremetal_objects(resource_name)

    @log_helpers.log_method_call
    def sync_direct_mode_config(self, context, host_config):
        self.aci_manager.ensure_hostgroup_mode_config(host_config, source="via rpc api")

    @log_helpers.log_method_call
    def sync_network(self, context, network):
        return self.aci_manager.sync_network(context, network)

    @log_helpers.log_method_call
    def sync_network_id(self, context, network_id):
        LOG.info("Grabbing data to sync network %s", network_id)
        network = self.agent_rpc.get_network(context, network_id)
        LOG.info("Data fetched, executing sync for network %s", network_id)
        return self.aci_manager.sync_network(context, network)

    # End RPC callbacks

    # Start Agent mechanics

    def setup_rpc(self):
        # RPC network init
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_rpc = rpc_api.AgentRpcClientAPI()

        # Define the listening consumers for the agent
        consumers = [[aci_const.ACI_TOPIC, topics.CREATE],
                     [aci_const.ACI_TOPIC, topics.UPDATE],
                     [aci_const.ACI_TOPIC, topics.DELETE]]

        self.connection = agent_rpc.create_consumers([self],
                                                     topics.AGENT,
                                                     consumers,
                                                     start_listening=False)

        report_interval = 30  # self.conf.AGENT.report_interval
        heartbeat = loopingcall.FixedIntervalLoopingCall(self._report_state)
        heartbeat.start(interval=report_interval, stop_on_exception=False)

    def _report_state(self):
        ctx = context.get_admin_context_without_session()
        try:
            self.state_rpc.report_state(ctx, self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def _check_and_handle_signal(self):
        if self.catch_sigterm:
            LOG.info(_LI("Agent caught SIGTERM, quitting daemon loop."))
            self.run_daemon_loop = False
            self.catch_sigterm = False
        return self.run_daemon_loop

    def _handle_sigterm(self, signum, frame):
        self.catch_sigterm = True
        if self.quitting_rpc_timeout:
            self.set_rpc_timeout(self.quitting_rpc_timeout)

    # End Agent mechanics

    def _run_non_epg_syncloop(self):
        ctx = context.get_admin_context_without_session()
        LOG.info("Starting periodic non-epg syncloop")
        if CONF.ml2_aci.enable_az_aware_subnet_routes_sync:
            try:
                self.sync_az_aware_subnet_routes(ctx)
            except Exception as e:
                LOG.exception("Sync of AZ aware subnet routes failed: %s %s",
                              e.__class__.__name__, e)
        else:
            LOG.info("AZ aware subnet routes syncloop is currently disabled")

        if CONF.ml2_aci.enable_nullroute_sync:
            try:
                self.sync_nullroutes(ctx)
            except Exception as e:
                LOG.exception("Sync of nullroutes failed: %s %s",
                              e.__class__.__name__, e)
        else:
            LOG.info("Nullroute syncloop is currently disabled")
        LOG.info("Periodic non-epg syncloop done")

    def sync_az_aware_subnet_routes(self, context):
        LOG.info("Starting AZ aware subnet route sync")
        subnets = self.agent_rpc.get_az_aware_subnet_routes(context)
        LOG.debug("Data fetched for az aware subnet route sync")
        self.aci_manager.sync_az_aware_subnet_routes(subnets)
        LOG.info("AZ aware subnet route sync done")

    def sync_nullroutes(self, context):
        LOG.info("Starting nullroute sync")
        data = self.agent_rpc.get_leaf_nullroutes(context)
        LOG.debug("Data fetched for nullroute sync, executing sync")
        self.aci_manager.sync_nullroutes(data)
        LOG.info("Nullroute sync done")

    def loop_count_and_wait(self, start_time):
        # sleep till end of polling interval
        elapsed = time.time() - start_time
        LOG.debug("CI Agent rpc_loop - iteration:%(iter_num)d "
                  "completed. Elapsed:%(elapsed).3f",
                  {'iter_num': self.iter_num,
                   'elapsed': elapsed})

        if elapsed < self.polling_interval:
            time.sleep(self.polling_interval - elapsed)
        else:
            LOG.debug("Loop iteration exceeded interval "
                      "(%(polling_interval)s vs. %(elapsed)s)!",
                      {'polling_interval': self.polling_interval,
                       'elapsed': elapsed})
            return

        self.iter_num = self.iter_num + 1

    def rpc_loop(self):
        start = time.time()

        if self.sync_active:
            while self._check_and_handle_signal():
                # create a new context for each sync loop run
                ctx = context.get_admin_context_without_session()
                try:
                    start = time.time()
                    neutron_binding_count = self.agent_rpc.get_binding_count(ctx)

                    if neutron_binding_count == 0:
                        LOG.warning("Skipping RPC loop due to zero binding count")
                    else:
                        LOG.warning("Total binding count {}".format(neutron_binding_count))

                        bds = self.aci_manager.get_all_bridge_domains()
                        epgs = self.aci_manager.get_all_epgs()
                        neutron_network_ids = self.agent_rpc.get_network_ids(ctx)
                        neutron_network_count = self.agent_rpc.get_networks_count(ctx)

                        LOG.info("Currently managing {} neutron networks and {} Bridge domains and {} EPGS"
                                 .format(neutron_network_count, len(bds), len(epgs)))

                        bd_names = []
                        for bd in bds:
                            bd_names.append(bd.name)

                        epg_names = []
                        for epg in epgs:
                            epg_names.append(epg.name)

                        # Orphaned  - so network ids in ACI but not neutron
                        orphaned = []
                        for bd_name in bd_names:
                            if(bd_name not in neutron_network_ids and bd_name not in orphaned):
                                orphaned.append(bd_name)

                        for epg_name in epg_names:
                            if(epg_name not in neutron_network_ids and epg_name not in orphaned):
                                orphaned.append(epg_name)

                        LOG.info("EPG/BD check orphaned {}".format(orphaned))

                        if self.prune_orphans and neutron_network_count > 0:
                            LOG.info("Deleting Orphaned resources")
                            for network_id in orphaned:
                                LOG.info("Deleting EPG and BD for network %s", network_id)
                                self.aci_manager.delete_domain_and_epg(network_id)

                        neutron_networks = self.agent_rpc.get_networks(ctx, limit=str(self.sync_batch_size),
                                                                       marker=self.sync_marker)

                        if len(neutron_networks) == 0:
                            self.sync_marker = None
                            continue

                        for network in neutron_networks:
                            try:
                                self.aci_manager.sync_network(ctx, network)
                            except Exception:
                                LOG.exception("Error while attempting to apply configuration to network %s",
                                              network.get('id'))

                        LOG.info("Scan and fix %s networks in %s seconds", len(neutron_networks), time.time() - start)
                        self.sync_marker = neutron_networks[-1]['id']

                except Exception:
                    LOG.exception(_LE("Error while in rpc loop"))

                self.loop_count_and_wait(start)

    def daemon_loop(self):
        # Start everything.
        LOG.info(_LI("ACI Agent initialized successfully, now running... "))
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        self.rpc_loop()
