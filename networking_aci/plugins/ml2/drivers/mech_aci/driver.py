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
from neutron import service
from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.definitions import external_net as extnet_def
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from neutron_lib.api.definitions import portbindings
from neutron_lib import rpc as n_rpc
from oslo_log import log as logging
from oslo_log import helpers as log_helpers

from networking_aci._i18n import _LI, _LW
from networking_aci.extensions.acioperations import Acioperations  # noqa, import enables extension
from networking_aci.plugins.ml2.drivers.mech_aci import allocations_manager as allocations
from networking_aci.plugins.ml2.drivers.mech_aci import common
from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const
from networking_aci.plugins.ml2.drivers.mech_aci import exceptions as aci_exc
from networking_aci.plugins.ml2.drivers.mech_aci.config import ACI_CONFIG, CONF
from networking_aci.plugins.ml2.drivers.mech_aci import rpc_api
from networking_aci.plugins.ml2.drivers.mech_aci.trunk import ACITrunkDriver

LOG = logging.getLogger(__name__)


@registry.has_registry_receivers
class CiscoACIMechanismDriver(api.MechanismDriver):
    def __init__(self):
        LOG.info(_LI("ACI mechanism driver initializing..."))
        self.topic = None
        self.conn = None
        self._plugin_property = None
        self.db = common.DBPlugin()
        self.rpc_api = rpc_api.AgentRpcCallback(self.db)
        self.allocations_manager = allocations.AllocationsManager(self.db)

        ACI_CONFIG.db = self.db
        self.rpc_notifier = rpc_api.ACIRpcClientAPI()
        self.trunk_driver = ACITrunkDriver.create()
        self.vif_details = {
            portbindings.VIF_DETAILS_CONNECTIVITY: self.connectivity
        }

    def initialize(self):
        pass

    @property
    def connectivity(self):
        return portbindings.CONNECTIVITY_L2

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    def _setup_rpc(self):
        """Initialize components to support agent communication."""
        self.endpoints = [
            self.rpc_api,
        ]

    @log_helpers.log_method_call
    def start_rpc_listeners(self):
        """Start the RPC loop to let the plugin communicate with agents."""
        self._setup_rpc()
        self.topic = aci_const.ACI_TOPIC
        self.conn = n_rpc.Connection()
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)

        return self.conn.consume_in_threads()

    def get_workers(self):
        return [service.RpcWorker([self], worker_process_count=0)]

    def bind_port(self, context):
        port = context.current
        host = common.get_host_from_profile(context.current.get('binding:profile'), context.host)

        LOG.debug("Using binding host %s for binding port %s", host, port['id'])
        hostgroup_name, hostgroup = ACI_CONFIG.get_hostgroup_by_host(context._plugin_context, host)

        if not hostgroup:
            LOG.warning("No aci config found for binding host %s while binding port %s", host, port['id'])
            return

        if hostgroup['fabric_transit']:
            raise aci_exc.TransitBindingProhibited(port_id=port['id'], host=host)

        if len(context.segments_to_bind) < 1:
            LOG.warning("No segments found for port %s with host %s - very unusual", port['id'], host)
            return

        # direct baremetal-on-aci needs to be annotated with physnet (and other stuff)
        if hostgroup['direct_mode']:
            ACI_CONFIG.annotate_baremetal_info(context._plugin_context, hostgroup, context.network.current['id'],
                                               override_project_id=port['project_id'])

        # hierarchical or direct?
        if not context.binding_levels:
            self._bind_port_hierarchical(context, port, hostgroup_name, hostgroup)
        elif hostgroup['finalize_binding'] or \
                (hostgroup['direct_mode'] and
                 hostgroup['hostgroup_mode'] in (aci_const.MODE_BAREMETAL, aci_const.MODE_INFRA)):
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

            ACI_CONFIG.annotate_baremetal_info(context._plugin_context, hostgroup, network['id'],
                                               override_project_id=port['project_id'])
            if aci_const.TRUNK_PROFILE in port['binding:profile']:
                segmentation_id = port['binding:profile'][aci_const.TRUNK_PROFILE].get('segmentation_id', 1)
            else:
                segmentation_id = None  # let the allocater choose a vlan
            allocation = self.allocations_manager.allocate_baremetal_segment(context._plugin_context, network,
                                                                             hostgroup, level, segmentation_id)
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
            ACI_CONFIG.clean_bindings(context._plugin_context, hostgroup, allocation.segment_id, level=level)
            self.rpc_notifier.bind_port(context._plugin_context, port, hostgroup, segment, next_segment)
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
                if not hostgroup['finalize_binding']:
                    # annotate baremetal resource name for baremetal group (if necessary)
                    network = context.network.current
                    ACI_CONFIG.annotate_baremetal_info(context._plugin_context, hostgroup, network['id'],
                                                       override_project_id=port['project_id'])

                    if hostgroup['hostgroup_mode'] == aci_const.MODE_BAREMETAL and \
                            aci_const.TRUNK_PROFILE in port['binding:profile']:
                        port_type_str = "trunk port"
                    else:
                        port_type_str = "access port"

                    self.rpc_notifier.bind_port(context._plugin_context, port, hostgroup, segment, next_segment)
                else:
                    port_type_str = "finalized portbinding w/o direct-mode set"
                    vif_details['aci_finalized_binding'] = True
                context.set_binding(segment['id'], aci_const.VIF_TYPE_ACI, vif_details, n_const.ACTIVE)
                LOG.info("Directly bound port %s to hostgroup %s with segment %s vlan %s (%s)",
                         port['id'], hostgroup_name, segment['id'], segment['segmentation_id'], port_type_str)

                return

        LOG.error("ACI driver tried to directly bind port %s to segment %s, but it could not be found, options: %s",
                  port['id'], segment_physnet,
                  ", ".join(seg[api.PHYSICAL_NETWORK] for seg in context.segments_to_bind))

    # Network callbacks
    def create_network_precommit(self, context):
        az_hints = context.current.get(az_def.AZ_HINTS)
        if len(az_hints) > 1:
            raise aci_exc.OnlyOneAZHintAllowed()

    def create_network_postcommit(self, context):
        external = self._network_external(context)
        self.rpc_notifier.create_network(context._plugin_context, context.current, external=external)

    def delete_network_postcommit(self, context):
        self.rpc_notifier.delete_network(context._plugin_context, context.current)

    def create_subnet_postcommit(self, context):
        if not CONF.ml2_aci.handle_all_l3_gateways or \
                aci_const.CC_FABRIC_L3_GATEWAY_TAG in context.network.current['tags']:
            return

        address_scope_name = None

        network = context._plugin.get_network(context._plugin_context, context.current['network_id'])
        external = bool(network.get('router:external'))
        network_az = None
        if network.get(az_def.AZ_HINTS):
            network_az = network[az_def.AZ_HINTS][0]

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

        self.rpc_notifier.create_subnet(context._plugin_context, context.current, external=external,
                                        address_scope_name=address_scope_name, network_az=network_az)

    def delete_subnet_postcommit(self, context):
        if not CONF.ml2_aci.handle_all_l3_gateways or \
                aci_const.CC_FABRIC_L3_GATEWAY_TAG in context.network.current['tags']:
            return

        network_id = context.current['network_id']
        subnetpool_id = context.current['subnetpool_id']
        if subnetpool_id is None:
            LOG.warn(_LW("Subnet {} is attached to an external network but is not using a subnet pool, "
                         "further configuration of this network in ACI is not possible"
                         .format(context.current['id'])))
            return

        address_scope_name = self.db.get_address_scope_name(context._plugin_context, subnetpool_id)
        network = context._plugin.get_network(context._plugin_context, network_id)
        external = bool(network.get('router:external'))
        network_az = None
        if network.get(az_def.AZ_HINTS):
            network_az = network[az_def.AZ_HINTS][0]
        subnets = context._plugin.get_subnets_by_network(context._plugin_context, network_id)
        last_on_network = len(subnets) == 0
        self.rpc_notifier.delete_subnet(context._plugin_context, context.current, external=external,
                                        address_scope_name=address_scope_name, network_az=network_az,
                                        last_on_network=last_on_network)

    @registry.receives(aci_const.CC_FABRIC_TRANSIT, [events.AFTER_CREATE])
    def on_fabric_transit_created(self, resource, event, trigger, payload):
        network_id = payload.metadata['network_id']
        host = payload.metadata['host']
        LOG.info("Got transit creation notification for transit host %s network %s, syncing network",
                 host, network_id)

        # get network sync data
        try:
            network = self._plugin.get_network(payload.context, network_id)
        except n_exc.NetworkNotFound as e:
            LOG.error("Could not sync transit %s network %s - network does not exist! (Error was %s)",
                      host, network_id, e)
            return

        sync_data = self.rpc_api._get_network(payload.context, network)

        # send to agent
        self.rpc_notifier.sync_network(payload.context, sync_data)

    @registry.receives(aci_const.CC_FABRIC_NET_GW, [events.BEFORE_UPDATE])
    def on_network_gateway_move(self, resource, event, trigger, payload):
        network_id = payload.metadata['network_id']
        if not payload.metadata['move-to-cc-fabric']:
            LOG.warning("Moving a gateway _away_ from cc-fabric is not supported by ACI yet (for network %s)",
                        network_id)
            return

        LOG.info("Got request to move l3 gateway away from ACI for network %s", network_id)

        try:
            network = self._plugin.get_network(payload.context, network_id)
        except n_exc.NetworkNotFound as e:
            LOG.error("Could not find network %s - network does not exist! (Error was %s)",
                      network_id, e)
            return

        if not network[extnet_def.EXTERNAL]:
            LOG.error("Got event to move gateway of network %s, which is NOT an external network!", network_id)
            return

        subnets_to_delete = []
        for subnet_id in network['subnets']:
            subnet = self._plugin.get_subnet(payload.context, subnet_id)
            subnetpool_id = subnet['subnetpool_id']
            address_scope_name = self.db.get_address_scope_name(payload.context, subnetpool_id)
            if address_scope_name is None:
                continue
            subnets_to_delete.append((subnet, address_scope_name))

        for n, (subnet, address_scope_name) in enumerate(subnets_to_delete):
            last_on_network = n + 1 == len(network['subnets'])
            self.rpc_notifier.delete_subnet(payload.context, subnet, external=True,
                                            address_scope_name=address_scope_name, last_on_network=last_on_network)

    # Port callbacks
    def create_port_precommit(self, context):
        self._check_port_az_affinity(context._plugin_context, context.network.current, context.current)

    def update_port_precommit(self, context):
        # only check AZ again if binding host changed
        orig_host = common.get_host_from_profile(context.original['binding:profile'],
                                                 context.original['binding:host_id'])
        curr_host = common.get_host_from_profile(context.current['binding:profile'],
                                                 context.current['binding:host_id'])
        if orig_host != curr_host:
            curr_hostgroup_name, curr_hostgroup = ACI_CONFIG.get_hostgroup_by_host(context._plugin_context, curr_host)
            if curr_hostgroup_name is not None:
                self._check_port_az_affinity(context._plugin_context, context.network.current, context.current)

    def _check_port_az_affinity(self, context, network, port):
        host = common.get_host_from_profile(port['binding:profile'], port['binding:host_id'])
        hostgroup_name, hostgroup = ACI_CONFIG.get_hostgroup_by_host(context, host)
        if not hostgroup:
            return  # ignore unknown binding_hosts

        # no checks are done for external networks, as these can be stretched across AZs
        if network[extnet_def.EXTERNAL]:
            return

        az_hints = network.get(az_def.AZ_HINTS)
        if az_hints:
            az_hint = az_hints[0]
            hg_az = [hostgroup['host_azs'][host]] if host in hostgroup['host_azs'] else hostgroup['availability_zones']
            if len(hg_az) != 1 or az_hint != hg_az[0]:
                exc = aci_exc.HostgroupNetworkAZAffinityError(port_id=port['id'], hostgroup_name=hostgroup_name,
                                                              host=host, hostgroup_az=", ".join(hg_az),
                                                              network_az=az_hint)
                if CONF.ml2_aci.az_checks_enabled:
                    raise exc
                else:
                    LOG.warning("Binding port with non-matching AZ: %s", exc)

    def update_port_postcommit(self, context):
        orig_host = common.get_host_from_profile(context.original['binding:profile'],
                                                 context.original['binding:host_id'])
        curr_host = common.get_host_from_profile(context.current['binding:profile'],
                                                 context.current['binding:host_id'])

        if orig_host != curr_host:
            # binding host differs, find out if:
            # * old binding host is valid
            # * new binding host is either invalid or valid AND belongs to a diffrent hostgroup
            orig_hostgroup_name, orig_hostgroup = ACI_CONFIG.get_hostgroup_by_host(context._plugin_context, orig_host)
            curr_hostgroup_name, curr_hostgroup = ACI_CONFIG.get_hostgroup_by_host(context._plugin_context, curr_host)

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

    def create_subnet_precommit(self, context):
        """Allocate resources for a new subnet.

        :param context: SubnetContext instance describing the new
            subnet.

        Create a new subnet, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        self._check_subnet_and_subnetpool_az_match(context)

    def _check_subnet_and_subnetpool_az_match(self, context):
        if not CONF.ml2_aci.subnet_subnetpool_az_check_enabled:
            return

        # check if a subnet's subnetpool and a subnet's network are in the same AZ
        # network needs to be external, subnet needs to have a subnetpool
        snp_id = context.current['subnetpool_id']
        net = context.network.current
        if snp_id is None or not net[extnet_def.EXTERNAL]:
            return

        # network az hint must match subnetpool az tag
        net_az_hints = net[az_def.AZ_HINTS]
        net_az_hint = net_az_hints[0] if net_az_hints else None

        snp_details = self.db.get_subnetpool_details(context._plugin_context,
                                                     [context.current['subnetpool_id']])

        # if the subnetpool has no address scope we ignore it
        if snp_id not in snp_details:
            return

        snp_az = snp_details[snp_id]['az']

        # net and snp az need to match. they need to either be None or an AZ
        if net_az_hint != snp_az:
            raise aci_exc.SubnetSubnetPoolAZAffinityError(network_id=net['id'], net_az_hint=net_az_hint,
                                                          subnetpool_id=context.current['subnetpool_id'],
                                                          subnetpool_az=snp_az)

    def cleanup_segment_if_needed(self, context, port, network, binding_levels, segment):
        if not segment:
            return

        # only handle cleanup for ports bound by the aci driver as top segment
        if not binding_levels or binding_levels[0][api.BOUND_DRIVER] != aci_const.ACI_DRIVER_NAME:
            return

        host = common.get_host_from_profile(port['binding:profile'], port['binding:host_id'])
        _, hostgroup = ACI_CONFIG.get_hostgroup_by_host(context, host)
        if not hostgroup:
            return

        # Get segment from ml2_port_binding_levels based on segment_id and host
        # if no ports on this segment for host we can remove the aci allocation.
        # In baremetal mode we need to call cleanup when the hostgroup is no longer on the physnet
        released = self.allocations_manager.release_segment(network, hostgroup, 1, segment)
        if not (released or hostgroup['direct_mode']):
            return

        # Call to ACI to delete port if the segment is released i.e.
        # port is the last for the network one on the host
        # Check if physical domain should be cleared
        ACI_CONFIG.annotate_baremetal_info(context, hostgroup, network['id'], override_project_id=port['project_id'])
        clearable_physdoms = []
        if released:
            # physdoms will only be removed on segment removal
            clearable_physdoms = self._get_clearable_phys_doms(context, network['id'],
                                                               segment, hostgroup, port['project_id'])

        clearable_bm_entities = []
        reset_bindings_to_infra = False
        if hostgroup['direct_mode']:
            # if this hostgroup has hosts left we cancel the removal
            hosts_on_network = self.db.get_hosts_on_network(context, network['id'], level=1)
            if any(host in hosts_on_network for host in hostgroup['hosts']):
                return

            # if this is a infra-mode binding make sure no VM port is bound before removing it
            # (this should never be the case)
            if hostgroup['hostgroup_mode'] == aci_const.MODE_INFRA:
                parent_hostgroup = ACI_CONFIG.get_hostgroup(context, hostgroup['parent_hostgroup'])
                if any(host in hosts_on_network for host in parent_hostgroup['hosts']):
                    # parent group has still a binding, we might have set one of the VPCs to access mode
                    # therefore we need to resync the binding. As this might interfere with other ports
                    # joining/leaving the network we do a network sync here
                    ACI_CONFIG.clean_bindings(context, parent_hostgroup, segment['id'], level=1)
                    LOG.debug("Port %s in network %s is in hostgroup %s, parent hostgroup %s, which needs a resync, "
                              "as this network has the parent hostgroup as member, but not the child anymore",
                              port['id'], network['id'], hostgroup['name'], parent_hostgroup['name'])

                    self.rpc_notifier.sync_network_id(context, network['id'])
                    return

        if hostgroup['direct_mode'] and hostgroup['hostgroup_mode'] == aci_const.MODE_BAREMETAL:
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
        self.rpc_notifier.delete_port(context, port, hostgroup, clearable_physdoms, clearable_bm_entities,
                                      reset_bindings_to_infra)

    def _get_clearable_phys_doms(self, context, network_id, local_segment, host_config, project_id):
        clearable_physdoms = set(host_config['physical_domain'])
        for other_segment in common.get_segments(context, network_id):
            if other_segment['physical_network'] is None:
                continue
            other_physdoms = ACI_CONFIG.get_physdoms_by_physnet(context, other_segment['physical_network'], network_id,
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
    def _get_subnet_pool_name(context, subnet_pool_id):
        pool = context._plugin.get_subnetpool(context._plugin_context, subnet_pool_id)

        if not pool:
            LOG.warn(_LW("Pool {} does not exist".format(subnet_pool_id)))
            return

        return pool['name']
