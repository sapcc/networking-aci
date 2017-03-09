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

import netaddr
import collections
import signal
import time

from oslo_config import cfg
from oslo_log import log as logging
from neutron.i18n import _LI, _LW
import oslo_messaging
from oslo_service import loopingcall

from stevedore import driver

from neutron.services.tag import tag_plugin
from neutron.common import config
from neutron.agent import rpc as agent_rpc
from neutron.common import constants as n_const
from neutron.common import topics
from neutron.i18n import _LE
from neutron.db import db_base_plugin_v2 as db
from neutron import context

from networking_aci.plugins.ml2.drivers.mech_aci import cobra_manager
from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_constants
from networking_aci.plugins.ml2.drivers.mech_aci import rpc_api
from networking_aci.plugins.ml2.drivers.mech_aci import config as aci_config



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


        self.network_config = {
            'hostgroup_dict': aci_config.create_hostgroup_dictionary(),
            'address_scope_dict': aci_config.create_addressscope_dictionary()
        }

        self.host_group_config = self.network_config['hostgroup_dict']
        self.tenant_manager = driver.DriverManager(namespace='aci.tenant.managers', name=self.aci_config.tenant_manager,invoke_on_load=True).driver

        self.db = db.NeutronDbPluginV2()
        self.tag_plugin = tag_plugin.TagPlugin()

        self.aci_manager = cobra_manager.CobraManager(self.network_config, self.aci_config,self.tenant_manager)

        self.aci_monitor_respawn_interval = aci_monitor_respawn_interval
        self.minimize_polling = minimize_polling,
        self.polling_interval = 10
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

        self.connection.consume_in_threads()



    # Start RPC callbacks

    def bind_port_postcommit(self, port, host_config, segment, next_segment):
        self.aci_manager.ensure_static_bindings_configured(port['network_id'], host_config,
                                                           encap=next_segment['segmentation_id'])

    def delete_port_postcommit(self, port, host_config, clear_phys_dom):
        self.aci_manager.ensure_static_bindings_configured(port['network_id'], host_config, encap=1, delete=True, clear_phys_dom=clear_phys_dom)

    def create_network_postcommit(self, network):
        self.aci_manager.ensure_domain_and_epg(network['id'])
        self.tag_plugin.update_tag(self.context, 'networks', network['id'],"monsoon3::aci::tenant::{}".format(self.tenant_manager.get_tenant_name(network['id'])))

    def delete_network_postcommit(self, network, **kwargs):
        self.aci_manager.delete_domain_and_epg(network['id'])

    def create_subnet_postcommit(self, subnet, external, address_scope_name):
        self._configure_subnet(subnet, external=external, address_scope_name=address_scope_name, delete=False)

    def delete_subnet_postcommit(self, subnet, external, address_scope_name):
        self._configure_subnet(subnet, external=external, address_scope_name=address_scope_name, delete=True)

    # End RPC callbacks

    # Start Agent mechanics

    def setup_rpc(self):

        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # RPC network init
        self.context = context.get_admin_context()


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
        heartbeat.start(interval=report_interval)

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

    def loop_count_and_wait(self, start_time, ):
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
        self.iter_num = self.iter_num + 1

    def rpc_loop(self):

        while self._check_and_handle_signal():
            start = time.time()

            try:

                # for tenant_name in self.tenant_manager.all_tenant_names():
                #     tenant = self.aci_manager.apic.get_full_tenant(tenant_name)
                #     if tenant:
                #         LOG.info("Checking tenant {}".format(tenant.name))
                #
                #         bds = tenant.BD
                #         aps = tenant.ap
                #
                #         for bd in bds:
                #             LOG.info("Checking bridge domain {}".format(bd.name))
                #             LOG.info("Subnets {}".format(len(bd.subnet)))
                #
                #         for ap in aps:
                #             LOG.info("Checking EPGs in application {}".format(ap.name))
                #             for epg in ap.epg:
                #                 LOG.info("Checking EPG {}".format(epg.name))
                #                 for binding in epg.rspathAtt:
                #                     LOG.info("Checking binding {}".format(binding.dn))
                #                 for contract in epg.ctrctCtxdefDn:
                #                     LOG.info("Checking contract {}".format(contract.dn))
                #
                #
                #
                #
                # # bds = self.aci_manager.get_all_bridge_domains()
                # # epgs = self.aci_manager.get_all_epgs()
                # # LOG.info("Managing {} Bridge domains and {} EPGS".format(len(bds),len(epgs)))
                #
                # all_ports = self.db.get_ports(self.context, filters={})
                #all_networks = self.db.get_networks(self.context, filters={})

                 #LOG.info("Managing {} Networks and {} Ports".format(len(all_networks), len(all_ports)))

                #for network in all_networks:
                #  self.tag_plugin.update_tag(self.context, 'networks', network['id'],"monsoon3::aci::tenant::{}".format(self.tenant_manager.get_tenant_name(network['id'])))

                #     if self.tenant_manager.managed(network['id']):
                #         LOG.info("Network {} is managed by this agent".format(network['id']))
                #         self.create_network_postcommit(network)

                pass

                # TO try and avoid concurrent issues, build a canddate list in the first pass and then execute on the next.


                # get dead BD's
                # get dead EPGs
                # get dead subnets
                # get dead bindings

                # get alive networks
                # get alive subnets
                # get alive ports





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

    # Start Helper Methods

    def _configure_subnet(self, subnet, external=False, address_scope_name=None, delete=False):
        network_id = subnet['network_id']

        LOG.info("****** configure subnet called with ")

        if external:
            cidr = netaddr.IPNetwork(subnet['cidr'])
            gateway_ip = '%s/%s' % (subnet['gateway_ip'],
                                    str(cidr.prefixlen))

            self.aci_manager.ensure_external_network_configured(network_id, address_scope_name, delete)

            if delete:
                # TODO handle multiple subnet case ?
                self.aci_manager.ensure_subnet_deleted(network_id, gateway_ip)

            else:
                self.aci_manager.ensure_subnet_created(network_id, address_scope_name, gateway_ip)



        else:
            self.aci_manager.ensure_internal_network_configured(network_id, delete)

            # End Helper Methods
