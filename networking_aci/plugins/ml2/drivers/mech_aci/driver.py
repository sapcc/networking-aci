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




from oslo_config import cfg
from oslo_log import log as logging
from neutron import context
from neutron.i18n import _LI
from neutron.i18n import _LW
from neutron.plugins.ml2 import driver_api as api
from neutron.db import api as db_api
from neutron.plugins.ml2 import models as ml2_models
from networking_aci.plugins.ml2.drivers.mech_aci import config
from networking_aci.plugins.ml2.drivers.mech_aci import allocations_manager as allocations
from networking_aci.plugins.ml2.drivers.mech_aci import rpc_api

LOG = logging.getLogger(__name__)


class CiscoACIMechanismDriver(api.MechanismDriver):
    def __init__(self):
        LOG.info(_LI("ACI mechanism driver initializing..."))


        self.network_config = {
            'hostgroup_dict': config.create_hostgroup_dictionary(),
            'address_scope_dict': config.create_addressscope_dictionary()
        }

        self.host_group_config = self.network_config['hostgroup_dict']

        self.allocations_manager = allocations.AllocationsManager(self.network_config)

        self.context = context.get_admin_context_without_session()
        self.rpc_notifier = rpc_api.ACIRpcClientAPI(self.context)

    def initialize(self):

        pass

    def bind_port(self, context):
        port = context.current
        network = context.network.current
        network_id = network['id']
        host = context.host


        # binding:profile       | {"local_link_information": [{"switch_info": "sw-hec01-243", "port_id": "Ethernet3", "switch_id": "00:1c:73:a3:81:c9"}]}

        binding_profile = context.current.get('binding:profile')
        if binding_profile:
            lli = binding_profile.get('local_link_information')
            # TODO validate assumption that we have 1 lli in list.
            if lli[0]:
                host = lli[0].get('switch_info')
                LOG.info("Using link local information for binding host %s", host)

        LOG.info("Using binding host %s", host)


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
                    LOG.error('Binding failed, could not allocate a segment for further binding levels for port %()s',
                              {'port': context.current['id']})
                    return False

                next_segment = {}
                next_segment['segmentation_id'] = allocation.segmentation_id
                next_segment['network_id'] = network_id
                next_segment['network_type'] = segment_type
                next_segment['physical_network'] = segment_physnet
                next_segment['id'] = allocation.segment_id
                # next_segment['is_dynamic'] = True
                next_segment['segment_index'] = level

                LOG.info("****** Next segment to bind")
                LOG.info(next_segment)

                self.rpc_notifier.bind_port(port, host_config, segment, next_segment)

                context.continue_binding(segment["id"], [next_segment])

                return True
            else:
                pass

    # Network callbacks
    def create_network_postcommit(self, context):
        self.rpc_notifier.create_network(context.current)

    def delete_network_postcommit(self, context):
        self.rpc_notifier.delete_network(context.current)

    def create_subnet_postcommit(self, context):

        LOG.info("*****************************")
        LOG.info("Create subnet post commit pre RPC")
        LOG.info("*****************************")

        address_scope_name = None

        external = self._subnet_external(context)
        if external:
            subnetpool_id = context.current['subnetpool_id']

            if subnetpool_id == None:
                # TODO Set network to Down
                LOG.warn(_LW(
                    "Subnet {} is attached to an external network but is not using a subnet pool, further configuration of this network in ACI is not possible".format(
                            context.current['id'])))
                return

            address_scope_name = self._get_address_scope_name(context, subnetpool_id)

            if address_scope_name == None:
                # TODO Set network to Down
                LOG.warn(_LW(
                    "Subnet {} is attached to an external network but in an address scope, further configuration of this network in ACI is not possible".format(
                            context.current['id'])))
                return

        self.rpc_notifier.create_subnet(context.current, external=external, address_scope_name=address_scope_name)

    def delete_subnet_postcommit(self, context):
        subnetpool_id = context.current['subnetpool_id']
        if subnetpool_id == None:
            LOG.warn(_LW(
                "Subnet {} is attached to an external network but is not using a subnet pool, further configuration of this network in ACI is not possible".format(
                        context.current['id'])))
            return
        address_scope_name = self._get_address_scope_name(context, subnetpool_id)
        external = self._subnet_external(context)

        self.rpc_notifier.delete_subnet(context.current, external=external, address_scope_name=address_scope_name)

    # Port callbacks

    def delete_port_postcommit(self, context):
        # For now we look only at the bottom bound segment - works for this use case
        # but will need some review if we ever have several dynamically bound segements

        network_id = context.network.current['id']
        segment = context.bottom_bound_segment
        host_id, host_config = self._host_or_host_group(context.host)

        if not host_config:
            return False

        if segment:
            # Get segment from ml2_port_binding_levels based on segment_id and host
            # if no ports on this segment for host we can remove the aci allocation

            released = self.allocations_manager.release_segment(context.network.current, host_config, 1, segment)

            # Call to ACI to delete port if the segment is released i.e. port is the last for the network one on the host
            if released:
                #Check if physical domain should be cleared
                clear_phys_dom = self._clear_phys_dom(context.network.current, host_config, 1, segment)
                self.rpc_notifier.delete_port(context.current, host_config,clear_phys_dom)

    def _clear_phys_dom(self, network, host_config, level, segment):
        # TODO check that no other segment on the network is configure
        # to use the same phys_dom as this segment. If not we can
        # clear the phys dom on the EPG.

        LOG.info("Checking if phys dom can be cleared for segment %(segment)s",{"segment":segment})
        session = db_api.get_session()

        segments = session.query(ml2_models.NetworkSegment).filter_by(network_id=network['id'])

        for other_segment in segments:

            bindings = session.query(ml2_models.PortBindingLevel).filter_by(segment_id=other_segment['id'], level=level)

            for binding in bindings:
                binding_host_id, binding_host_config = self._host_or_host_group(binding['host'])

                if binding_host_config['physical_domain']==host_config['physical_domain']:
                    LOG.info("Checked if phys dom can be cleared for segment %(segment)s it is in use in segment %(other_segment)s",{"segment":segment['id'],"other_segment":other_segment['id']})
                    return False



        LOG.info("Checked if phys dom can be cleared for segment %(segment)s, its not used can will be cleared",{"segment":segment['id']})

        return True


    def _host_or_host_group(self, host_id):
        for hostgroup, hostgroup_config in self.host_group_config.iteritems():
            if host_id in hostgroup_config['hosts']:
                return hostgroup, hostgroup_config

        return host_id, None

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

    @staticmethod
    def _get_address_scope_name(context, subnet_pool_id):

        pool = context._plugin.get_subnetpool(context._plugin_context, subnet_pool_id)

        if not pool:
            LOG.warn(_LW("Subnet pool {} does not exist".format(subnet_pool_id)))
            return

        scope = context._plugin.get_address_scope(context._plugin_context, pool['address_scope_id'])

        if not scope:
            LOG.warn(_LW("Address scope {} does not exist".format(['pool.address_scope_id'])))
            return

        return scope['name']
