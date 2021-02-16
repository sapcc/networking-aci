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
from networking_aci.plugins.ml2.drivers.mech_aci.config import ACI_CONFIG
import rpc_api

LOG = logging.getLogger(__name__)


class CiscoACIMechanismDriver(api.MechanismDriver):
    def __init__(self):
        LOG.info(_LI("ACI mechanism driver initializing..."))
        self.topic = None
        self.conn = None
        self.allocations_manager = allocations.AllocationsManager()

        self.db = common.DBPlugin()
        self.context = context.get_admin_context_without_session()
        self.rpc_notifier = rpc_api.ACIRpcClientAPI(self.context)
        self.start_rpc_listeners()

    def initialize(self):
        pass

    def _setup_rpc(self):
        """Initialize components to support agent communication."""
        self.endpoints = [
            rpc_api.AgentRpcCallback(self.db),
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
        host = common.get_host_from_profile(context.current.get('binding:profile'), context.host)

        LOG.info("Using binding host %s for binding port %s", host, port['id'])
        host_group_name, host_config = ACI_CONFIG.get_hostgroup_by_host(host)

        if not host_config:
            return False

        segment_type = host_config.get('segment_type', 'vlan')
        segment_physnet = host_config.get('physical_network')
        if not segment_physnet:
            LOG.error("Cannot bind port %s: Hostgroup %s has no physical_network set, cannot allocate segment",
                      port['id'], host_group_name)
            return

        for segment in context.segments_to_bind:
            if context.binding_levels is None:
                # For now we assume only two levels in hierarchy. The top level VXLAN/VLAN and
                # one dynamically allocated segment at level 1
                level = 1
                allocation = self.allocations_manager.allocate_segment(network, segment_physnet, level, host_config)

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

            address_scope_name = self.db.get_address_scope_name(context._plugin_context, subnetpool_id)
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

        address_scope_name = self.db.get_address_scope_name(context._plugin_context, subnetpool_id)
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
        host = common.get_host_from_profile(context.current.get('binding:profile'), context.host)

        _, host_config = ACI_CONFIG.get_hostgroup_by_host(host)

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
                clearable_phys_doms = self._get_clearable_phys_doms(context.network.current, segment, host_config)
                self.rpc_notifier.delete_port(context.current, host_config, clearable_phys_doms)

    def _get_clearable_phys_doms(self, network, local_segment, host_config):
        # start out with all physdoms in use by the local segment
        clearable = set(host_config['physical_domain'])

        # query out all binding_hosts (hosts) that are on any segment in this network that is not local_segment
        # select from networksegments where network_id matches, local_segment id does not match
        #   join with ml2_portbinding_levels, filter for level=1
        #       get host
        session = db_api.get_reader_session()
        with session.begin():
            other_bindings = (session.query(models.PortBindingLevel.host, models.PortBindingLevel.segment_id)
                                     .join(segment_model.NetworkSegment,
                                           segment_model.NetworkSegment.id == models.PortBindingLevel.segment_id)
                                     .filter(segment_model.NetworkSegment.network_id == network['id'],
                                             models.PortBindingLevel.level == 1,
                                             models.PortBindingLevel.segment_id != local_segment['id'])
                                     .distinct())

        for other_binding in other_bindings:
            _, other_binding_host_config = ACI_CONFIG.get_hostgroup_by_host(other_binding.host)
            other_physdoms = set(other_binding_host_config['physical_domain'])
            for physdom in clearable & other_physdoms:
                LOG.debug("Not clearing physdom %s from epg %s for segment %s as it is still in use by segment %s",
                          physdom, network['id'], local_segment['id'], other_binding.segment_id)
            clearable -= other_physdoms

            if not clearable:
                break

        LOG.debug("Found %d clearable physdoms for network %s segment %s (%s)",
                  len(clearable), network['id'], local_segment['id'], ", ".join(clearable) or "<none>")

        return list(clearable)

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
