import logging

from neutron_lib.callbacks import events, registry, resources
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib.plugins import directory
from neutron_lib.exceptions import NeutronException
from neutron_lib.api.definitions import port as p_api
from neutron_lib.api.definitions import portbindings
from neutron_lib.services.trunk import constants as trunk_const
from neutron.services.trunk.drivers import base
from oslo_config import cfg

from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const
from networking_aci.plugins.ml2.drivers.mech_aci import common
from networking_aci.plugins.ml2.drivers.mech_aci.config import ACI_CONFIG
from networking_aci.plugins.ml2.drivers.mech_aci.exceptions import TrunkHostgroupNotInBaremetalMode
from networking_aci.plugins.ml2.drivers.mech_aci.exceptions import TrunkCannotAllocateReservedVlan
from networking_aci.plugins.ml2.drivers.mech_aci.exceptions import TrunkSegmentationIdNotInAllowedRange
from networking_aci.plugins.ml2.drivers.mech_aci.exceptions import TrunkSegmentationNotConsistentInProject


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

NAME = 'aci'
SUPPORTED_INTERFACES = (
    aci_const.VIF_TYPE_ACI,
)
SUPPORTED_SEGMENTATION_TYPES = (
    trunk_const.SEGMENTATION_TYPE_VLAN,
)


class ACITrunkDriver(base.DriverBase):
    @property
    def is_loaded(self):
        try:
            return aci_const.ACI_DRIVER_NAME in cfg.CONF.ml2.mechanism_drivers
        except cfg.NoSuchOptError:
            return False

    @classmethod
    def create(cls):
        return cls(NAME, SUPPORTED_INTERFACES, SUPPORTED_SEGMENTATION_TYPES,
                   can_trunk_bound_port=True)

    @registry.receives(resources.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        super(ACITrunkDriver, self).register(resource, event, trigger, payload)

        self.core_plugin = directory.get_plugin()

        registry.subscribe(self.trunk_check_valid, resources.TRUNK, events.PRECOMMIT_CREATE)
        registry.subscribe(self.trunk_create, resources.TRUNK, events.AFTER_CREATE)
        registry.subscribe(self.trunk_delete, resources.TRUNK, events.AFTER_DELETE)
        registry.subscribe(self.trunk_check_valid, resources.SUBPORTS, events.PRECOMMIT_CREATE)
        registry.subscribe(self.subport_create, resources.SUBPORTS, events.AFTER_CREATE)
        registry.subscribe(self.subport_delete, resources.SUBPORTS, events.AFTER_DELETE)

    def _get_context_and_parent_port(self, parent_port_id):
        """Get admin context and parent port

        Return None, None if this driver is not responsible for this trunk/port
        """
        ctx = context.get_admin_context()
        parent = self.core_plugin.get_port(ctx, parent_port_id)
        if not self.is_interface_compatible(parent[portbindings.VIF_TYPE]):
            return None, None
        return ctx, parent

    def trunk_check_valid(self, resource, event, trunk_plugin, payload):
        if resource == resources.TRUNK:
            # Trunk resource contains desires_state
            # Event: https://github.com/sapcc/neutron/blob/e49485f2aa7dd48f57f2d94080a37c49306e87d4/neutron/services/trunk/plugin.py#L255
            current_state = payload.desired_state
        elif resource == resources.SUBPORTS:
            # Subports resource contains states
            # Event: https://github.com/sapcc/neutron/blob/e49485f2aa7dd48f57f2d94080a37c49306e87d4/neutron/services/trunk/plugin.py#L362
            current_state = payload.states[0]
        else:
            raise NeutronException("Unsupported type of resource {}".format(resource))
        ctx, parent = self._get_context_and_parent_port(current_state.port_id)
        if not parent:
            return

        parent_host = common.get_host_from_profile(parent['binding:profile'], parent['binding:host_id'])
        LOG.debug("Trunk check valid called, got port %s with host %s", parent['id'], parent_host)

        hostgroup_name, hostgroup = ACI_CONFIG.get_hostgroup_by_host(parent_host)
        if not hostgroup:
            raise NeutronException("No hostgroup config found for port {} host {}"
                                   .format(current_state.port_id, parent_host))

        if not (hostgroup['direct_mode'] and hostgroup['hostgroup_mode'] == aci_const.MODE_BAREMETAL):
            raise TrunkHostgroupNotInBaremetalMode(port_id=current_state.port_id, hostgroup=hostgroup_name)

        if resource != resources.SUBPORTS or 'subports' not in payload.metadata:
            # Only subports resource contains metadata with information
            # Event: https://github.com/sapcc/neutron/blob/e49485f2aa7dd48f57f2d94080a37c49306e87d4/neutron/services/trunk/plugin.py#L373
            return

        vlan_map = ACI_CONFIG.db.get_trunk_vlan_usage_on_project(ctx, parent['project_id'])
        bm_access_ranges = common.get_set_from_ranges(hostgroup['baremetal_access_vlan_ranges'])
        for subport in payload.metadata['subports']:
            if subport.segmentation_id in ACI_CONFIG.baremetal_reserved_vlans or \
                    subport.segmentation_id in bm_access_ranges:
                raise TrunkCannotAllocateReservedVlan(segmentation_id=subport.segmentation_id)

            # check that we are part of the actual allocated vlan pool
            if subport.segmentation_id not in range(CONF.ml2_aci.baremetal_encap_blk_start,
                                                    CONF.ml2_aci.baremetal_encap_blk_end):
                raise TrunkSegmentationIdNotInAllowedRange(segmentation_id=subport.segmentation_id,
                                                           segmentation_start=CONF.ml2_aci.baremetal_encap_blk_start,
                                                           segmentation_end=CONF.ml2_aci.baremetal_encap_blk_end)

            # check if any subport's segmentation id violates vlan consistency
            # --> in the subport's project no other network is allowed to use the segmentation id
            if subport.segmentation_id in vlan_map:
                port = self.core_plugin.get_port(ctx, subport.port_id)
                nets = vlan_map[subport.segmentation_id]
                if nets and port['network_id'] not in nets:
                    raise TrunkSegmentationNotConsistentInProject(segmentation_id=subport.segmentation_id,
                                                                  project_id=parent['project_id'],
                                                                  port_id=subport.port_id,
                                                                  network_id=port['network_id'])

    def trunk_create(self, resource, event, trunk_plugin, payload):
        ctx, parent = self._get_context_and_parent_port(payload.states[0].port_id)
        if not parent:
            return

        LOG.info("Trunk create called, resource %s payload %s trunk id %s",
                 resource, payload, payload.resource_id)
        self._bind_subports(ctx, parent, payload.states[0], payload.states[0].sub_ports)
        payload.states[0].update(status=trunk_const.TRUNK_ACTIVE_STATUS)

    def trunk_delete(self, resource, event, trunk_plugin, payload):
        ctx, parent = self._get_context_and_parent_port(payload.states[0].port_id)
        if not parent:
            return

        LOG.info("Trunk %s delete called", payload.resource_id)
        self._bind_subports(ctx, parent, payload.states[0], payload.states[0].sub_ports, delete=True)

    def subport_create(self, resource, event, trunk_plugin, payload):
        ctx, parent = self._get_context_and_parent_port(payload.states[0].port_id)
        if not parent:
            return

        self._bind_subports(ctx, parent, payload.states[0], payload.metadata['subports'])

    def subport_delete(self, resource, event, trunk_plugin, payload):
        ctx, parent = self._get_context_and_parent_port(payload.states[0].port_id)
        if not parent:
            return

        self._bind_subports(ctx, parent, payload.states[0], payload.metadata['subports'], delete=True)

    def _bind_subports(self, ctx, parent, trunk, subports, delete=False):
        for subport in subports:
            LOG.info("%s parent %s for subport %s on trunk %s",
                     "Setting" if not delete else "Unsetting",
                     trunk.port_id, subport.port_id, trunk.id)
            if not delete:
                binding_profile = parent.get(portbindings.PROFILE)
                binding_profile[aci_const.TRUNK_PROFILE] = {
                    'segmentation_type': subport.segmentation_type,
                    'segmentation_id': subport.segmentation_id,
                }

                port_data = {
                    p_api.RESOURCE_NAME: {
                        portbindings.HOST_ID: parent.get(portbindings.HOST_ID),
                        portbindings.VNIC_TYPE: parent.get(portbindings.VNIC_TYPE),
                        portbindings.PROFILE: binding_profile,
                        # 'device_owner': parent.get('device_owner'),
                        'device_owner': trunk_const.TRUNK_SUBPORT_OWNER,
                        'device_id': parent.get('device_id'),
                        # do not set port to active, the driver can do this!
                        # 'status': n_const.PORT_STATUS_ACTIVE,
                    },
                }
            else:
                port_data = {
                    p_api.RESOURCE_NAME: {
                        portbindings.HOST_ID: None,
                        portbindings.VNIC_TYPE: None,
                        portbindings.PROFILE: None,
                        'device_owner': '',
                        'device_id': '',
                        'status': n_const.PORT_STATUS_DOWN,
                    },
                }
            self.core_plugin.update_port(ctx, subport.port_id, port_data)

        num_deleted_subports = len(subports) if delete else 0
        if len(trunk.sub_ports) - num_deleted_subports > 0:
            trunk.update(status=trunk_const.TRUNK_ACTIVE_STATUS)
        else:
            # trunk is automatically set to DOWN on change. if we don't change that it will stay that way
            LOG.info("Last subport was removed from trunk %s, setting it to state DOWN", trunk.id)
