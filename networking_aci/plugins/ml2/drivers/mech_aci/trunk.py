import logging

from neutron_lib.callbacks import events, registry
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib.plugins import directory
from neutron_lib.exceptions import NeutronException
from neutron_lib.api.definitions import port as p_api
from neutron_lib.api.definitions import portbindings
from neutron.services.trunk import constants as trunk_const
from neutron.services.trunk.drivers import base
from oslo_config import cfg

from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const
from networking_aci.plugins.ml2.drivers.mech_aci import common
from networking_aci.plugins.ml2.drivers.mech_aci.exceptions import TrunkHostgroupNotInBaremetalMode


LOG = logging.getLogger(__name__)

NAME = 'aci'
SUPPORTED_INTERFACES = (
    aci_const.VIF_TYPE_ACI,
)
SUPPORTED_SEGMENTATION_TYPES = (
    trunk_const.VLAN,
)


class ACITrunkDriver(base.DriverBase):
    def __init__(self, host_group_config, *args, **kwargs):
        self._host_group_config = host_group_config
        super(ACITrunkDriver, self).__init__(*args, **kwargs)

    @property
    def is_loaded(self):
        try:
            return aci_const.ACI_DRIVER_NAME in cfg.CONF.ml2.mechanism_drivers
        except cfg.NoSuchOptError:
            return False

    @classmethod
    def create(cls, host_group_config):
        return cls(host_group_config, NAME, SUPPORTED_INTERFACES, SUPPORTED_SEGMENTATION_TYPES,
                   can_trunk_bound_port=True)

    @registry.receives(trunk_const.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        super(ACITrunkDriver, self).register(resource, event, trigger, payload)

        self.core_plugin = directory.get_plugin()

        registry.subscribe(self.trunk_check_valid, trunk_const.TRUNK, events.PRECOMMIT_CREATE)
        registry.subscribe(self.trunk_create, trunk_const.TRUNK, events.AFTER_CREATE)
        registry.subscribe(self.trunk_update, trunk_const.TRUNK, events.AFTER_UPDATE)
        registry.subscribe(self.trunk_delete, trunk_const.TRUNK, events.AFTER_DELETE)
        registry.subscribe(self.subport_create, trunk_const.SUBPORTS, events.AFTER_CREATE)
        registry.subscribe(self.subport_delete, trunk_const.SUBPORTS, events.AFTER_DELETE)

    def trunk_check_valid(self, resource, event, trunk_plugin, payload):
        ctx = context.get_admin_context()
        parent = self.core_plugin.get_port(ctx, payload.current_trunk.port_id)
        parent_host = common.get_host_from_port(parent)
        LOG.debug("Trunk check valid called, got port %s with host %s", parent, parent_host)
        host_group, host_config = common.get_host_or_host_group(parent_host, self._host_group_config)
        if not host_config:
            raise NeutronException("No host config for port {} host {}"
                                   .format(payload.current_trunk.port_id, parent_host))
        if host_config['bm_mode'] != aci_const.ACI_BM_CUSTOMER:
            raise TrunkHostgroupNotInBaremetalMode(port_id=payload.current_trunk.port_id, host_group=host_group)

    def trunk_create(self, resource, event, trunk_plugin, payload):
        LOG.info("Trunk create called, resource %s payload %s trunk id %s",
                 resource, payload, payload.trunk_id)
        self._bind_subports(payload.current_trunk, payload.current_trunk.sub_ports)
        payload.current_trunk.update(status=trunk_const.ACTIVE_STATUS)

    def trunk_update(self, resource, event, trunk_plugin, payload):
        LOG.info("Trunk %s update called", payload.trunk_id)

    def trunk_delete(self, resource, event, trunk_plugin, payload):
        LOG.info("Trunk %s delete called", payload.trunk_id)
        self._bind_subports(payload.original_trunk, payload.original_trunk.sub_ports, delete=True)

    def subport_create(self, resource, event, trunk_plugin, payload):
        self._bind_subports(payload.current_trunk, payload.subports)

    def subport_delete(self, resource, event, trunk_plugin, payload):
        self._bind_subports(payload.current_trunk, payload.subports, delete=True)

    def _bind_subports(self, trunk, subports, delete=False):
        ctx = context.get_admin_context()
        parent = self.core_plugin.get_port(ctx, trunk.port_id)

        for subport in subports:
            LOG.debug("%s parent %s for subport %s on trunk %s",
                      "Setting" if not delete else "Unsetting",
                      trunk.port_id, subport.port_id, trunk.id)
            if not delete:
                binding_profile = parent.get(portbindings.PROFILE)
                binding_profile['aci_trunk'] = {
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

        if len(trunk.sub_ports) > 0:
            trunk.update(status=trunk_const.ACTIVE_STATUS)
        else:
            # trunk is automatically set to DOWN on change. if we don't change that it will stay that way
            LOG.info("Last subport was removed from trunk %s, setting it to state DOWN", trunk.id)
