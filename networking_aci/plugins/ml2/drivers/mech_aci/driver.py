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
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins.ml2 import api
from neutron_lib import rpc as n_rpc
from oslo_log import log as logging
from oslo_log import helpers as log_helpers

from networking_aci._i18n import _LI, _LW
from networking_aci.extensions.acioperations import Acioperations  # noqa, import enables extension
from networking_aci.plugins.ml2.drivers.mech_aci import allocations_manager as allocations
from networking_aci.plugins.ml2.drivers.mech_aci import common
from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const
from networking_aci.plugins.ml2.drivers.mech_aci.config import ACI_CONFIG, CONF
from networking_aci.plugins.ml2.drivers.mech_aci import rpc_api
from networking_aci.plugins.ml2.drivers.mech_aci.trunk import ACITrunkDriver

LOG = logging.getLogger(__name__)


class CiscoACIMechanismDriver(api.MechanismDriver):
    def __init__(self):
        LOG.info(_LI("ACI mechanism driver initializing..."))
        self.topic = None
        self.conn = None
        self.db = common.DBPlugin()
        self.allocations_manager = allocations.AllocationsManager(self.db)

        ACI_CONFIG.db = self.db
        self.context = context.get_admin_context_without_session()
        self.rpc_notifier = rpc_api.ACIRpcClientAPI(self.context)
        self.start_rpc_listeners()
        self.trunk_driver = ACITrunkDriver.create()

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
        self.topic = aci_const.ACI_TOPIC
        self.conn = n_rpc.Connection()
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)

        return self.conn.consume_in_threads()

    def bind_port(self, context):
        port = context.current
        host = common.get_host_from_profile(context.current.get('binding:profile'), context.host)

        LOG.debug("Using binding host %s for binding port %s", host, port['id'])
        hostgroup_name, hostgroup = ACI_CONFIG.get_hostgroup_by_host(host)

        if not hostgroup:
            LOG.warning("No aci config found for binding host %s while binding port %s", host, port['id'])
            return

        if len(context.segments_to_bind) < 1:
            LOG.warning("No segments found for port %s with host %s - very unusual", port['id'], host)
            return

        # direct baremetal-on-aci needs to be annotated with physnet (and other stuff)
        if hostgroup['direct_mode']:
            ACI_CONFIG.annotate_baremetal_info(hostgroup, context.network.current['id'],
                                               override_project_id=port['project_id'])

        # hierarchical or direct?
        if not context.binding_levels:
            self._bind_port_hierarchical(context, port, hostgroup_name, hostgroup)
        elif hostgroup['direct_mode'] and \
                hostgroup['hostgroup_mode'] in (aci_const.MODE_BAREMETAL, aci_const.MODE_INFRA):
            # direct binding for a) baremetal on aci and b) infra mode (2nd level)
            self._bind_port_direct(context, port, hostgroup_name, hostgroup)

    def _bind_port_hierarchical(self, context, port, hostgroup_name, hostgroup):
        # find the top segment (no physnet, type vxlan); there should be only one, but who knows
        for segment in context.segments_to_bind:
            if segment[api.NETWORK_TYPE] == 'vxlan' and segment['physical_network'] is None:
                break
        else:
            LOG.error("No usable segment found for hierarchical portbinding, candidates were: %s",
                      context.segments_to_bind)
            return

        segment_physnet = hostgroup.get('physical_network')
        if not segment_physnet:
            LOG.error("Cannot bind port %s: Hostgroup %s has no physical_network set, cannot allocate segment",
                      port['id'], hostgroup_name)
            return

        # For now we assume only two levels in hierarchy. The top level VXLAN/VLAN and
        # one dynamically allocated segment at level 1
        level = 1

        network = context.network.current
        segment_type = hostgroup.get('segment_type', 'vlan')
        if hostgroup.get('hostgroup_mode') != aci_const.MODE_BAREMETAL:
            # VM mode
            allocation = self.allocations_manager.allocate_segment(network, segment_physnet, level, hostgroup)
            segmentation_id = allocation.segmentation_id
            segment_id = allocation.segment_id
        else:
            # baremetal objects use a different physnet and gets allocated to its own segment
            # check that no baremetal-on-aci port from another project is in this network
            segment_prefix = "{}-".format(CONF.ml2_aci.baremetal_resource_prefix)
            for seg_port in self.db.get_ports_on_network_by_physnet_prefix(context._plugin_context,
                                                                           network['id'], segment_prefix):
                if seg_port['project_id'] != port['project_id']:
                    msg = ("Cannot bind port {}: Hostgroup {} has baremetal port {} belonging to project {}, "
                           "new port is from project {} - aborting binding"
                           .format(port['id'], hostgroup['name'], seg_port['port_id'], seg_port['project_id'],
                                   port['project_id']))
                    LOG.error(msg)
                    raise n_exc.NeutronException(msg)

            ACI_CONFIG.annotate_baremetal_info(hostgroup, network['id'], override_project_id=port['project_id'])
            if aci_const.TRUNK_PROFILE in port['binding:profile']:
                segmentation_id = port['binding:profile'][aci_const.TRUNK_PROFILE].get('segmentation_id', 1)
            else:
                segmentation_id = None  # let the allocater choose a vlan
            allocation = self.allocations_manager.allocate_baremetal_segment(network, hostgroup, level, segmentation_id)
            segment_id = allocation.id
            segmentation_id = allocation.segmentation_id

        if not allocation:
            LOG.error("Binding failed, could not allocate a segment for further binding levels "
                      "for port %(port)s",
                      {'port': context.current['id']})
            return

        next_segment = {
            'segmentation_id': segmentation_id,
            'network_id': network['id'],
            'network_type': segment_type,
            'physical_network': segment_physnet,
            'id': segment_id,
            'is_dynamic': False,
            'segment_index': level
        }

        LOG.info("Next segment to bind for port %s on %s: %s", port['id'], segment["id"], next_segment)
        if not hostgroup['direct_mode']:
            # for direct mode the rpc call will be made by the next level binding
            ACI_CONFIG.clean_bindings(hostgroup, allocation.segment_id, level=level)
            self.rpc_notifier.bind_port(port, hostgroup, segment, next_segment)
        context.continue_binding(segment["id"], [next_segment])

    def _bind_port_direct(self, context, port, hostgroup_name, hostgroup):
        segment_physnet = hostgroup.get('physical_network')

        for segment in context.segments_to_bind:
            if segment[api.PHYSICAL_NETWORK] == segment_physnet:
                vif_details = {
                    'aci_directly_bound': True,
                }
                next_segment = {
                    'segmentation_id': segment['segmentation_id'],
                }

                # annotate baremetal resource name for baremetal group (if necessary)
                network = context.network.current
                ACI_CONFIG.annotate_baremetal_info(hostgroup, network['id'], override_project_id=port['project_id'])

                if hostgroup['hostgroup_mode'] == aci_const.MODE_BAREMETAL and \
                        aci_const.TRUNK_PROFILE in port['binding:profile']:
                    port_type_str = "trunk port"
                else:
                    port_type_str = "access port"

                self.rpc_notifier.bind_port(port, hostgroup, segment, next_segment)
                context.set_binding(segment['id'], aci_const.VIF_TYPE_ACI, vif_details, n_const.ACTIVE)
                LOG.info("Directly bound port %s to hostgroup %s with segment %s vlan %s (%s)",
                         port['id'], hostgroup_name, segment['id'], segment['segmentation_id'], port_type_str)

                return

        LOG.error("ACI driver tried to directly bind port %s to segment %s, but it could not be found, options: %s",
                  port['id'], segment_physnet,
                  ", ".join(seg[api.PHYSICAL_NETWORK] for seg in context.segments_to_bind))

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
    def update_port_postcommit(self, context):
        orig_host = common.get_host_from_profile(context.original['binding:profile'],
                                                 context.original['binding:host_id'])
        curr_host = common.get_host_from_profile(context.current['binding:profile'],
                                                 context.current['binding:host_id'])

        if orig_host != curr_host:
            # binding host differs, find out if:
            # * old binding host is valid
            # * new binding host is either invalid or valid AND belongs to a diffrent hostgroup
            orig_hostgroup_name, orig_hostgroup = ACI_CONFIG.get_hostgroup_by_host(orig_host)
            curr_hostgroup_name, curr_hostgroup = ACI_CONFIG.get_hostgroup_by_host(curr_host)

            if orig_hostgroup and \
                    (curr_hostgroup is None or (curr_hostgroup and orig_hostgroup_name != curr_hostgroup_name)):
                if CONF.ml2_aci.handle_port_update_for_non_baremetal or \
                        orig_hostgroup['direct_mode'] and orig_hostgroup['hostgroup_mode'] == aci_const.MODE_BAREMETAL:
                    # handle port update
                    LOG.info('Calling cleanup for port %s (hostgroup transition from "%s" to "%s")',
                             context.current['id'], orig_hostgroup_name, curr_hostgroup_name)

                    # apparently context.network.original is not set, but the ml2_plugin always fetches
                    # the original port's network, so context.current should work. nevertheless, safeguarding this
                    if context.original['network_id'] != context.network.current['id']:
                        LOG.error("Port %s original port has network id %s, context.network.current is %s, omitting!",
                                  context.current['id'], context.current['network_id'], context.network.current['id'])
                        return

                    self.cleanup_segment_if_needed(context._plugin_context, context.original, context.network.current,
                                                   context.original_binding_levels,
                                                   context.original_bottom_bound_segment)
                else:
                    LOG.info("Ignoring host transition for port %s from host %s hostgroups %s to host %s hostgroup %s",
                             context.current['id'], orig_host, orig_hostgroup_name, curr_host, curr_hostgroup_name)

    def delete_port_postcommit(self, context):
        # For now we look only at the bottom bound segment - works for this use case
        # but will need some review if we ever have several dynamically bound segements
        # network_id = context.network.current['id']
        self.cleanup_segment_if_needed(context._plugin_context, context.current, context.network.current,
                                       context.binding_levels, context.bottom_bound_segment)

    def cleanup_segment_if_needed(self, context, port, network, binding_levels, segment):
        if not segment:
            return

        # only handle cleanup for ports bound by the aci driver as top segment
        if not binding_levels or binding_levels[0][api.BOUND_DRIVER] != aci_const.ACI_DRIVER_NAME:
            return

        host = common.get_host_from_profile(port['binding:profile'], port['binding:host_id'])
        _, hostgroup = ACI_CONFIG.get_hostgroup_by_host(host)
        if not hostgroup:
            return

        # Get segment from ml2_port_binding_levels based on segment_id and host
        # if no ports on this segment for host we can remove the aci allocation.
        # In baremetal mode we need to call cleanup when the hostgroup is no longer on the physnet
        released = self.allocations_manager.release_segment(network, hostgroup, 1, segment)
        if not released and not (hostgroup['direct_mode'] and hostgroup['hostgroup_mode'] == aci_const.MODE_BAREMETAL):
            return

        # Call to ACI to delete port if the segment is released i.e.
        # port is the last for the network one on the host
        # Check if physical domain should be cleared
        ACI_CONFIG.annotate_baremetal_info(hostgroup, network['id'], override_project_id=port['project_id'])
        clearable_physdoms = []
        if released:
            # physdoms will only be removed on segment removal
            clearable_physdoms = self._get_clearable_phys_doms(context, network['id'],
                                                               segment, hostgroup, port['project_id'])

        clearable_bm_entities = []
        reset_bindings_to_infra = False
        if hostgroup['direct_mode'] and hostgroup['hostgroup_mode'] == aci_const.MODE_BAREMETAL:
            # if this hostgroup has hosts left we cancel the removal
            hosts_on_network = self.db.get_hosts_on_network(context, network['id'], level=1)
            if any(host in hosts_on_network for host in hostgroup['hosts']):
                return

            # if this hostgroup has no host left on the physnet we can reset the VPC/bindings
            hosts_on_physnet = self.db.get_hosts_on_physnet(context, hostgroup['physical_network'], level=1)
            if not any(host in hosts_on_physnet for host in hostgroup['hosts']):
                reset_bindings_to_infra = True

            # if this port is the last from a project we clear out the bm entities on ACI
            seg_prefix = ACI_CONFIG.baremetal_resource_prefix
            projects_on_physnets = self.db.get_bound_projects_by_physnet_prefix(context, seg_prefix)
            if port['project_id'] not in projects_on_physnets:
                clearable_bm_entities.append(ACI_CONFIG.gen_bm_resource_name(port['project_id']))

        LOG.debug("Sending RPC delete_port for port %s hostgroup %s with clearable physdoms %s "
                  "clearable bm-entities %s and reset-bindings-to-infra %s",
                  port['id'], hostgroup['name'], clearable_physdoms, clearable_bm_entities, reset_bindings_to_infra)
        self.rpc_notifier.delete_port(port, hostgroup, clearable_physdoms, clearable_bm_entities,
                                      reset_bindings_to_infra)

    def _get_clearable_phys_doms(self, context, network_id, local_segment, host_config, project_id):
        clearable_physdoms = set(host_config['physical_domain'])
        for other_segment in common.get_segments(context, network_id):
            if other_segment['physical_network'] is None:
                continue
            other_physdoms = ACI_CONFIG.get_physdoms_by_physnet(other_segment['physical_network'], network_id,
                                                                project_id)
            if not other_physdoms:
                LOG.warning("No config found for segment %s physical network %s in network %s",
                            local_segment['id'], other_segment['physical_network'], network_id)
                continue
            other_physdoms = set(other_physdoms)
            for physdom in clearable_physdoms & other_physdoms:
                LOG.debug("Not clearing physdom %s from epg %s for segment %s as it is still in use by segment %s",
                          physdom, network_id, local_segment['id'], other_segment['id'])
            clearable_physdoms -= other_physdoms
            if not clearable_physdoms:
                break

        LOG.debug("Found %d clearable physdoms for network %s segment %s (%s)",
                  len(clearable_physdoms), network_id, local_segment['id'],
                  ", ".join(clearable_physdoms) or "<none>")

        return clearable_physdoms

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
