import logging

from neutron_lib.callbacks import events, registry
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib.plugins import directory
from neutron_lib.api.definitions import port as p_api
from neutron_lib.api.definitions import portbindings
# from neutron_lib.callbacks import resources
# from neutron_lib.services.trunk import constants as trunk_const
from neutron.services.trunk import constants as trunk_const
from neutron.services.trunk.drivers import base
# from neutron.objects import ports as port_obj
from oslo_config import cfg

from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const


LOG = logging.getLogger(__name__)

NAME = 'aci'
SUPPORTED_INTERFACES = (
    aci_const.VIF_TYPE_ACI,
)
SUPPORTED_SEGMENTATION_TYPES = (
    trunk_const.VLAN,
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
        return cls(NAME, SUPPORTED_INTERFACES, SUPPORTED_SEGMENTATION_TYPES, can_trunk_bound_port=True)

    # @registry.receives(resources.TRUNK_PLUGIN, [events.AFTER_INIT])
    @registry.receives(trunk_const.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        super(ACITrunkDriver, self).register(resource, event, trigger, payload)

        self.core_plugin = directory.get_plugin()

        # registry.subscribe(self.trunk_create, resources.TRUNK, events.AFTER_CREATE)
        # registry.subscribe(self.trunk_update, resources.TRUNK, events.AFTER_UPDATE)
        # registry.subscribe(self.trunk_delete, resources.TRUNK, events.AFTER_DELETE)
        # registry.subscribe(self.subport_create, resources.SUBPORT, events.AFTER_CREATE)
        # registry.subscribe(self.subport_delete, resources.SUBPORT, events.AFTER_DELETE)

        registry.subscribe(self.trunk_create, trunk_const.TRUNK, events.AFTER_CREATE)
        registry.subscribe(self.trunk_update, trunk_const.TRUNK, events.AFTER_UPDATE)
        registry.subscribe(self.trunk_delete, trunk_const.TRUNK, events.AFTER_DELETE)
        registry.subscribe(self.subport_create, trunk_const.SUBPORTS, events.AFTER_CREATE)
        registry.subscribe(self.subport_delete, trunk_const.SUBPORTS, events.AFTER_DELETE)

    def trunk_create(self, resource, event, trunk_plugin, payload):
        LOG.info("(trunk plugin) Trunk created, resource %s payload %s trunk id %s",
                 resource, payload, payload.trunk_id)
        payload.current_trunk.update(status=trunk_const.ACTIVE_STATUS)

    def trunk_update(self, resource, event, trunk_plugin, payload):
        LOG.info("(trunk plugin) Trunk updated, resource %s payload %s plugin type %s",
                 resource, payload, type(trunk_plugin))
        LOG.info("(trunk plugin) payload dict %s", payload.__dict__)
        self._update_trunk(payload)

    def trunk_delete(self, resource, event, trunk_plugin, payload):
        LOG.info("(trunk plugin) Trunk deleted, resource %s payload %s", resource, payload)

    def subport_create(self, resource, event, trunk_plugin, payload):
        LOG.info("(trunk plugin) Subport created, resource %s payload %s", resource, payload)
        self._bind_subports(payload.current_trunk, payload.subports)

    def subport_delete(self, resource, event, trunk_plugin, payload):
        LOG.info("(trunk plugin) Subport deleted, resource %s payload %s", resource, payload)
        self._bind_subports(payload.current_trunk, payload.subports, delete=True)

    def _update_trunk(self, payload, subports=None):
        trunk = payload.current_trunk
        subports = subports or trunk.sub_ports
        LOG.info("Creating / updating trunk %s on port %s with %d subports in update",
                 trunk.id, trunk.port_id, len(subports))
        # self._bind_subports(trunk, subports)
        if not trunk.status == trunk_const.ACTIVE_STATUS:
            trunk.update(status=trunk_const.ACTIVE_STATUS)

    def _bind_subports(self, trunk, subports, delete=False):
        ctx = context.get_admin_context()
        parent = self.core_plugin.get_port(ctx, trunk.port_id)

        for subport in subports:
            LOG.debug("Setting parent %s for subport %s (delete=%s)",
                      trunk.port_id, subport.port_id, delete)
            if not delete:
                binding_profile = parent.get(portbindings.PROFILE)
                binding_profile['aci_trunk'] = {
                    'segmentation_type': subport.segmentation_type,
                    'segmentation_id': subport.segmentation_id
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
