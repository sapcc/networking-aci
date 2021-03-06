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

from neutron_lib import constants as n_const
from neutron_lib import context
from neutron.agent import rpc as agent_rpc
from neutron.common import config
from neutron.common import topics
from neutron.db import db_base_plugin_v2 as db
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from stevedore import driver

from networking_aci._i18n import _LI, _LE
from networking_aci.plugins.ml2.drivers.mech_aci import cobra_manager
from networking_aci.plugins.ml2.drivers.mech_aci import config as aci_config
from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_constants
from networking_aci.plugins.ml2.drivers.mech_aci import rpc_api

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class AciNeutronAgent(rpc_api.ACIRpcAPI):
    target = oslo_messaging.Target(version='1.4')

    def __init__(self,
                 minimize_polling=False,
                 quitting_rpc_timeout=None,
                 conf=None,
                 aci_monitor_respawn_interval=(
                         aci_constants.DEFAULT_ACI_RESPAWN)):

        self.conf = aci_config.CONF

        self.aci_config = self.conf.ml2_aci

        self.fixed_bindings = aci_config.create_fixed_bindings_dictionary()

        self.network_config = {
            'hostgroup_dict': aci_config.create_hostgroup_dictionary(),
            'address_scope_dict': aci_config.create_addressscope_dictionary(),
            'fixed_bindings_dict': self.fixed_bindings
        }

        self.host_group_config = self.network_config['hostgroup_dict']
        self.tenant_manager = driver.DriverManager(namespace='aci.tenant.managers', name=self.aci_config.tenant_manager,
                                                   invoke_on_load=True).driver

        self.db = db.NeutronDbPluginV2()

        self.aci_monitor_respawn_interval = aci_monitor_respawn_interval
        self.minimize_polling = minimize_polling,
        self.polling_interval = self.aci_config.polling_interval
        self.sync_batch_size = self.aci_config.sync_batch_size
        self.sync_marker = ""

        self.sync_active = self.aci_config.sync_active
        self.prune_orphans = self.aci_config.prune_orphans
        self.iter_num = 0
        self.run_daemon_loop = True
        self.quitting_rpc_timeout = quitting_rpc_timeout
        self.catch_sigterm = False
        self.catch_sighup = False

        host = self.conf.host
        self.agent_id = 'aci-agent-%s' % host

        self.setup_rpc()

        self.agent_state = {
            'binary': 'neutron-aci-agent',
            'host': host,
            'topic': n_const.L2_AGENT_TOPIC,
            'configurations': {},
            'agent_type': aci_constants.ACI_AGENT_TYPE,
            'start_flag': True}

        self.aci_manager = cobra_manager.CobraManager(self.agent_rpc, self.network_config, self.aci_config,
                                                      self.tenant_manager)
        self.connection.consume_in_threads()

    # Start RPC callbacks

    @log_helpers.log_method_call
    def bind_port_postcommit(self, port, host_config, segment, next_segment):
        self.aci_manager.ensure_static_bindings_configured(port['network_id'], host_config,
                                                           encap=next_segment['segmentation_id'])

    @log_helpers.log_method_call
    def delete_port_postcommit(self, port, host_config, physdoms_to_clear):
        self.aci_manager.ensure_static_bindings_configured(port['network_id'], host_config, encap=1, delete=True,
                                                           physdoms_to_clear=physdoms_to_clear)

    @log_helpers.log_method_call
    def create_network_postcommit(self, network, external):
        self.aci_manager.ensure_domain_and_epg(network['id'], external=external)

    @log_helpers.log_method_call
    def delete_network_postcommit(self, network, **kwargs):
        self.aci_manager.delete_domain_and_epg(network['id'])

    @log_helpers.log_method_call
    def create_subnet_postcommit(self, subnet, external, address_scope_name):
        self.aci_manager.create_subnet(subnet, external=external, address_scope_name=address_scope_name,)

    @log_helpers.log_method_call
    def delete_subnet_postcommit(self, subnet, external, address_scope_name, last_on_network):
        self.aci_manager.delete_subnet(subnet, external=external, address_scope_name=address_scope_name,
                                       last_on_network=last_on_network)

    # End RPC callbacks

    # Start Agent mechanics

    def setup_rpc(self):
        # RPC network init
        self.context = context.get_admin_context()
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_rpc = rpc_api.AgentRpcClientAPI(self.context)

        # Define the listening consumers for the agent
        consumers = [[aci_constants.ACI_TOPIC, topics.CREATE],
                     [aci_constants.ACI_TOPIC, topics.UPDATE],
                     [aci_constants.ACI_TOPIC, topics.DELETE]]

        self.connection = agent_rpc.create_consumers([self],
                                                     topics.AGENT,
                                                     consumers,
                                                     start_listening=False)

        report_interval = 30  # self.conf.AGENT.report_interval
        heartbeat = loopingcall.FixedIntervalLoopingCall(self._report_state)
        heartbeat.start(interval=report_interval, stop_on_exception=False)

    def _report_state(self):
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def _check_and_handle_signal(self):
        if self.catch_sigterm:
            LOG.info(_LI("Agent caught SIGTERM, quitting daemon loop."))
            self.run_daemon_loop = False
            self.catch_sigterm = False
        if self.catch_sighup:
            LOG.info(_LI("Agent caught SIGHUP, resetting."))
            self.conf.reload_config_files()
            config.setup_logging()
            LOG.debug('Full set of CONF:')
            self.conf.log_opt_values(LOG, logging.DEBUG)
            self.catch_sighup = False
        return self.run_daemon_loop

    def _handle_sigterm(self, signum, frame):
        self.catch_sigterm = True
        if self.quitting_rpc_timeout:
            self.set_rpc_timeout(self.quitting_rpc_timeout)

    def _handle_sighup(self, signum, frame):
        self.catch_sighup = True

    # End Agent mechanics

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
                try:
                    start = time.time()
                    neutron_binding_count = self.agent_rpc.get_binding_count()

                    if neutron_binding_count == 0:
                        LOG.warning("Skipping RPC loop due to zero binding count")
                    else:
                        LOG.warning("Total binding count {}".format(neutron_binding_count))

                        bds = self.aci_manager.get_all_bridge_domains()
                        epgs = self.aci_manager.get_all_epgs()
                        neutron_network_ids = self.agent_rpc.get_network_ids()
                        neutron_network_count = self.agent_rpc.get_networks_count()

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

                        neutron_networks = self.agent_rpc.get_networks(limit=str(self.sync_batch_size),
                                                                       marker=self.sync_marker)

                        if len(neutron_networks) == 0:
                            self.sync_marker = None
                            continue

                        for network in neutron_networks:
                            try:
                                self.aci_manager.clean_subnets(network)
                                self.aci_manager.clean_physdoms(network)
                                self.aci_manager.clean_bindings(network)

                                self.aci_manager.ensure_domain_and_epg(network.get('id'),
                                                                       external=network.get('router:external'))

                                for subnet in network.get('subnets'):
                                    self.aci_manager.create_subnet(subnet,
                                                                   network.get('router:external'),
                                                                   subnet.get('address_scope_name'))

                                for binding in network.get('bindings'):
                                    if binding.get('host_config'):
                                        self.aci_manager.ensure_static_bindings_configured(network.get('id'),
                                                                                           binding.get('host_config'),
                                                                                           encap=binding.get('encap'))
                                    else:
                                        LOG.warning("No host configuration found in binding %s", binding)

                                fixed_bindings = network.get('fixed_bindings')

                                for fixed_binding in fixed_bindings:
                                    encap = fixed_binding.get('segment_id', None)
                                    self.aci_manager.ensure_static_bindings_configured(network.get('id'), fixed_binding,
                                                                       encap=encap)
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
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, self._handle_sighup)
            self.rpc_loop()
