# Copyright 2016 SAP SE
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
import ast

from neutron_lib import context
from neutron_lib.plugins.ml2 import api
from neutron.db import api as db_api
from neutron.db.models import segment as segment_model
from neutron.common import rpc as n_rpc
from neutron.plugins.ml2 import models
from oslo_log import log as logging
from oslo_log import helpers as log_helpers

from networking_aci._i18n import _LI, _LW
from networking_aci.plugins.ml2.drivers.mech_aci import allocations_manager as allocations
from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_constants
from networking_aci.plugins.ml2.drivers.mech_aci import common
import rpc_api

LOG = logging.getLogger(__name__)


class CiscoACIMechanismDriver(api.MechanismDriver):
    def __init__(self):
        LOG.info(_LI("ACI mechanism driver initializing..."))
        self.topic = None
        self.conn = None
        self.network_config = common.get_network_config()
        self.host_group_config = self.network_config['hostgroup_dict']
        self.allocations_manager = allocations.AllocationsManager(self.network_config)

        self.context = context.get_admin_context_without_session()
        self.rpc_notifier = rpc_api.ACIRpcClientAPI(self.context)
        self.start_rpc_listeners()

    def initialize(self):
        pass

    def _setup_rpc(self):
        """Initialize components to support agent communication."""
        self.endpoints = [
            rpc_api.AgentRpcCallback(),
        ]

    @log_helpers.log_method_call
    def start_rpc_listeners(self):
        """Start the RPC loop to let the plugin communicate with agents."""
        self._setup_rpc()
        self.topic = aci_constants.ACI_TOPIC
        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)

        return self.conn.consume_in_threads()

    def bind_port(self, context):
        port = context.current
        network = context.network.current
        network_id = network['id']
        host = context.host
        binding_profile = context.current.get('binding:profile')
        switch = CiscoACIMechanismDriver.switch_from_local_link(binding_profile)

        if switch:
            host = switch

        LOG.info("Using binding host %s for binding port %s", host, port['id'])
        host_id, host_config = self._host_or_host_group(host)

        if not host_config:
            return False

        segment_type = host_config.get('segment_type', 'vlan')
        segment_physnet = host_config.get('physical_network', None)

        for segment in context.segments_to_bind:
            if context.binding_levels is None:
                # For now we assume only two levels in hierarchy. The top level VXLAN/VLAN and
                # one dynamically allocated segment at level 1
                level = 1
                allocation = self.allocations_manager.allocate_segment(network, host_id, level, host_config)

                if not allocation:
                    LOG.error("Binding failed, could not allocate a segment for further binding levels "
                              "for port %(port)s",
                              {'port': context.current['id']})
                    return False

                next_segment = {
                    'segmentation_id': allocation.segmentation_id,
                    'network_id': network_id,
                    'network_type': segment_type,
                    'physical_network': segment_physnet,
                    'id': allocation.segment_id,
                    'is_dynamic': False,
                    'segment_index': level
                }

                LOG.info("Next segment to bind for port %s: %s", port['id'], next_segment)
                self.rpc_notifier.bind_port(port, host_config, segment, next_segment)
                context.continue_binding(segment["id"], [next_segment])

                return True

    # Network callbacks
    def create_network_postcommit(self, context):
        external = self._network_external(context)
        self.rpc_notifier.create_network(context.current, external=external)

    def delete_network_postcommit(self, context):
        self.rpc_notifier.delete_network(context.current)

    def create_subnet_postcommit(self, context):
        address_scope_name = None

        external = self._subnet_external(context)
        if external:
            subnetpool_id = context.current['subnetpool_id']

            if subnetpool_id is None:
                # TODO Set network to Down
                LOG.warn(_LW("Subnet {} is attached to an external network but is not using a subnet pool, "
                             "further configuration of this network in ACI is not possible"
                             .format(context.current['id'])))
                return

            address_scope_name = common.get_address_scope_name(context._plugin_context, subnetpool_id)
            if address_scope_name is None:
                # TODO Set network to Down
                LOG.warn(_LW("Subnet {} is attached to an external network but in an address scope, "
                             "further configuration of this network in ACI is not possible"
                             .format(context.current['id'])))
                return

        self.rpc_notifier.create_subnet(context.current, external=external, address_scope_name=address_scope_name)

    def delete_subnet_postcommit(self, context):
        network_id = context.current['network_id']
        subnetpool_id = context.current['subnetpool_id']
        if subnetpool_id is None:
            LOG.warn(_LW("Subnet {} is attached to an external network but is not using a subnet pool, "
                         "further configuration of this network in ACI is not possible"
                         .format(context.current['id'])))
            return

        address_scope_name = common.get_address_scope_name(context._plugin_context, subnetpool_id)
        external = self._subnet_external(context)
        subnets = context._plugin.get_subnets_by_network(context._plugin_context, network_id)
        last_on_network = len(subnets) == 0
        self.rpc_notifier.delete_subnet(context.current, external=external, address_scope_name=address_scope_name,
                                        last_on_network=last_on_network)

    # Port callbacks
    def delete_port_postcommit(self, context):
        # For now we look only at the bottom bound segment - works for this use case
        # but will need some review if we ever have several dynamically bound segements
        # network_id = context.network.current['id']
        segment = context.bottom_bound_segment
        host = context.host
        binding_profile = context.current.get('binding:profile')
        switch = CiscoACIMechanismDriver.switch_from_local_link(binding_profile)

        if switch:
            host = switch
        host_id, host_config = self._host_or_host_group(host)

        if not host_config:
            return False

        if segment:
            # Get segment from ml2_port_binding_levels based on segment_id and host
            # if no ports on this segment for host we can remove the aci allocation
            released = self.allocations_manager.release_segment(context.network.current, host_config, 1, segment)

            # Call to ACI to delete port if the segment is released i.e.
            # port is the last for the network one on the host
            if released:
                # Check if physical domain should be cleared
                clear_phys_dom = self._clear_phys_dom(context.network.current, host_config, 1, segment)
                self.rpc_notifier.delete_port(context.current, host_config, clear_phys_dom)

    def _clear_phys_dom(self, network, host_config, level, segment):
        # TODO check that no other segment on the network is configure
        # to use the same phys_dom as this segment. If not we can
        # clear the phys dom on the EPG.
        LOG.info("Checking if phys dom can be cleared for segment %(segment)s", {"segment": segment})
        session = db_api.get_reader_session()
        segments = session.query(segment_model.NetworkSegment).filter_by(network_id=network['id'])

        for other_segment in segments:
            bindings = session.query(models.PortBindingLevel).filter_by(segment_id=other_segment['id'], level=level)

            for binding in bindings:
                binding_host_id, binding_host_config = self._host_or_host_group(binding['host'])

                if binding_host_config['physical_domain'] == host_config['physical_domain']:
                    LOG.info(
                        "Checked if phys dom can be cleared for segment %(segment)s "
                        "it is in use in segment %(other_segment)s",
                        {"segment": segment['id'], "other_segment": other_segment['id']})
                    return False

        LOG.info("Checked if phys dom can be cleared for segment %(segment)s, its not used can will be cleared",
                 {"segment": segment['id']})

        return True

    def _host_or_host_group(self, host_id):
        return common.get_host_or_host_group(host_id, self.host_group_config)

    @staticmethod
    def switch_from_local_link(binding_profile):
        if binding_profile:
            try:
                if not isinstance(binding_profile, dict):
                    binding_profile = ast.literal_eval(binding_profile)

                lli = binding_profile.get('local_link_information')
                # TODO validate assumption that we have 1 lli in list.
                if lli and lli[0] and isinstance(lli[0], dict):
                    switch = lli[0].get('switch_info', None) or lli[0].get('switch_id', None)
                    if switch:
                        LOG.info("Using link local information for binding host %s", switch)
                        return switch
                    else:
                        LOG.error("Cannot determine switch for local link info %s in binding profile %s.",
                                  lli[0], binding_profile)
                else:
                    LOG.error("Local information %s is invalid in binding profile %s.",
                              lli, binding_profile)
            except ValueError:
                LOG.info("binding Profile %s cannot be parsed", binding_profile)

    @staticmethod
    def _network_external(context):
        current = context.current
        network_id = current['id']
        network = context._plugin.get_network(context._plugin_context, network_id)

        if network.get('router:external'):
            return True

        return False

    @staticmethod
    def _subnet_external(context):
        subnet = context.current
        network_id = subnet['network_id']
        network = context._plugin.get_network(context._plugin_context, network_id)

        if network.get('router:external'):
            return True

        return False

    @staticmethod
    def _get_subnet_pool_name(context, subnet_pool_id):
        pool = context._plugin.get_subnetpool(context._plugin_context, subnet_pool_id)

        if not pool:
            LOG.warn(_LW("Pool {} does not exist".format(subnet_pool_id)))
            return

        return pool['name']
