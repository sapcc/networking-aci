# Copyright 2021 SAP SE
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
import functools

from neutron.api import extensions
from neutron.api.v2.resource import Resource
from neutron import policy
from neutron import wsgi
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import faults
from neutron_lib.plugins import directory
from oslo_log import log
from webob import exc as web_exc

import networking_aci.extensions
from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const
from networking_aci.plugins.ml2.drivers.mech_aci.common import DBPlugin
from networking_aci.plugins.ml2.drivers.mech_aci.config import ACI_CONFIG
from networking_aci.plugins.ml2.drivers.mech_aci import rpc_api

LOG = log.getLogger(__name__)

# NOTE: For this extension to be registered this file needs to be imported from somewhere

ACCESS_RULE = "context_is_cloud_admin"


def check_cloud_admin(f):
    @functools.wraps(f)
    def wrapper(self, request, *args, **kwargs):
        if not policy.check(request.context, ACCESS_RULE, {'project_id': request.context.project_id}):
            raise web_exc.HTTPUnauthorized("{} required for access".format(ACCESS_RULE))
        return f(self, request, *args, **kwargs)

    return wrapper


class Acioperations(api_extensions.ExtensionDescriptor):
    """ACI ml2 driver API extensions"""
    # class name cannot be camelcase, needs to be just capitalized

    @classmethod
    def get_name(self):
        return "ACI ml2 API"

    @classmethod
    def get_alias(self):
        return "aci-ml2-api"

    @classmethod
    def get_description(self):
        return "ACI ml2 API for extra driver operations"

    @classmethod
    def get_updated(self):
        """The timestamp when the extension was last updated."""
        return "2021-02-05T12:15:23+01:00"

    @classmethod
    def get_resources(self):
        """List of extensions.ResourceExtension extension objects.

        Resources define new nouns, and are accessible through URLs.
        """
        plugin = directory.get_plugin()
        db = DBPlugin()
        endpoints = []
        rpc_notifier = rpc_api.ACIRpcClientAPI()

        # config endpoint
        # dump hostgroup dict / aci config
        res = Resource(ConfigController(), faults.FAULT_MAP)
        config_endpoint = extensions.ResourceExtension('aci-ml2/config', res)
        endpoints.append(config_endpoint)

        # hostgroup_mode endpoint
        res = Resource(HostgroupModeController(db, rpc_notifier), faults.FAULT_MAP)
        hg_mode_endpoint = extensions.ResourceExtension('aci-ml2/hostgroup-modes', res)
        endpoints.append(hg_mode_endpoint)

        # networks endpoint
        res = Resource(NetworksController(plugin, db, rpc_notifier), faults.FAULT_MAP)
        networks_endpoint = extensions.ResourceExtension('aci-ml2/networks', res)
        endpoints.append(networks_endpoint)

        # nullroutes endpoint
        res = Resource(NullroutesController(plugin, db, rpc_notifier), faults.FAULT_MAP)
        nullroutes_endpoint = extensions.ResourceExtension('aci-ml2/nullroutes', res,
                                                           collection_actions=NullroutesController.COLLECTION_ACTIONS)
        endpoints.append(nullroutes_endpoint)

        # az_aware_subnet_routes endpoint
        res = Resource(AZAwareSubnetRoutes(plugin, db, rpc_notifier), faults.FAULT_MAP)
        az_a_sr_endpoint = extensions.ResourceExtension('aci-ml2/az_aware_subnet_routes', res,
                                                        collection_actions=NullroutesController.COLLECTION_ACTIONS)
        endpoints.append(az_a_sr_endpoint)

        return endpoints


# make sure this plugin gets autodiscovered and disable api-support checks
# we need to do it this way because we do not have our own plugin that we associate with
extensions.register_custom_supported_check(Acioperations.get_alias(), lambda: True, True)
extensions.append_api_extensions_path(networking_aci.extensions.__path__)


class ConfigController(wsgi.Controller):
    @check_cloud_admin
    def index(self, request, **kwargs):
        """Show all hostgroup, fixed bindings and address scopes"""
        if request.GET.get("raw", False):
            hostgroups = ACI_CONFIG.hostgroups
        else:
            hostgroups = {}
            for hg_name in ACI_CONFIG.hostgroups:
                hostgroups[hg_name] = ACI_CONFIG.get_hostgroup(request.context, hg_name)

        return {
            'hostgroups': hostgroups,
            'fixed_bindings': ACI_CONFIG.fixed_bindings,
            'address_scopes': ACI_CONFIG.address_scopes,
        }

    @check_cloud_admin
    def show(self, request, **kwargs):
        """Show a single hostgroup"""
        hostgroup_name = kwargs.pop('id')
        if request.GET.get("raw", False):
            hostgroup = ACI_CONFIG.hostgroups.get(hostgroup_name)
        else:
            hostgroup = ACI_CONFIG.get_hostgroup(request.context, hostgroup_name)

        if not hostgroup:
            raise web_exc.HTTPNotFound('Hostgroup "{}" does not exist'.format(hostgroup_name))

        return hostgroup


class HostgroupModeController(wsgi.Controller):
    def __init__(self, db, rpc_notifier):
        super(HostgroupModeController, self).__init__()
        self.db = db
        self.rpc_notifier = rpc_notifier

    @check_cloud_admin
    def index(self, request, **kwargs):
        return dict(hostgroup_modes=self.db.get_hostgroup_modes(request.context))

    @check_cloud_admin
    def show(self, request, **kwargs):
        hostgroup_name = kwargs.pop('id')
        return dict(hostgroup_name=hostgroup_name, hostgroup_mode=self._get_mode(request.context, hostgroup_name))

    @check_cloud_admin
    def update(self, request, **kwargs):
        hostgroup_name = kwargs.pop('id')
        new_mode = kwargs.get("body", {}).get("mode")
        if new_mode not in (aci_const.MODE_INFRA, aci_const.MODE_BAREMETAL):
            raise web_exc.HTTPBadRequest("Specify a mode that is either {} or {} (given mode was '{}')"
                                         .format(aci_const.MODE_INFRA, aci_const.MODE_BAREMETAL, new_mode))

        curr_mode = self._get_mode(request.context, hostgroup_name)
        if curr_mode == new_mode:
            raise web_exc.HTTPBadRequest("{} is already in {} mode".format(hostgroup_name, new_mode))

        # check if there are still ports on this hostgroup
        hg_config = ACI_CONFIG.get_hostgroup(request.context, hostgroup_name)
        if not hg_config:
            raise web_exc.HTTPBadRequest("Hostgroup {} has no config associated with it".format(hostgroup_name))

        if curr_mode == aci_const.MODE_BAREMETAL:
            # for baremetal switchover we need to check all baremetal segments for active portbindings
            physnet_to_check = "{}%".format(ACI_CONFIG.baremetal_resource_prefix)
            fuzzy = True
        else:
            # for infra switchover active portbindings can only be on one physnet
            physnet_to_check = hg_config['physical_network']
            fuzzy = False

        for segment_id in self.db.get_segment_ids_by_physnet(request.context, physnet_to_check, fuzzy_match=fuzzy):
            hosts = self.db.get_hosts_on_segment(request.context, segment_id)
            for host in hg_config['hosts']:
                if host in hosts:
                    LOG.error("Denied API request to switch hostgroup %s to %s mode, host %s still bound in segment %s",
                              hostgroup_name, new_mode, host, segment_id)
                    raise web_exc.HTTPConflict("Could not switch, there is still a portbinding for host {} "
                                               "present in segment {}"
                                               .format(host, segment_id))

        if self.db.set_hostgroup_mode(request.context, hostgroup_name, new_mode):
            LOG.info("Hostgroup %s set to mode %s", hostgroup_name, new_mode)

            hg_config = ACI_CONFIG.get_hostgroup(request.context, hostgroup_name)
            aci_objects_update_succeeded = False
            if hg_config['hostgroup_mode'] == aci_const.MODE_INFRA:
                # on switch from baremetal --> infra: switching policy group of port selectors, etc.
                try:
                    self.rpc_notifier.sync_direct_mode_config(request.context, hg_config)
                    aci_objects_update_succeeded = True
                except Exception:
                    LOG.exception("Could not update bindings on ACI, rpc call failed")
            else:
                # nothing to update, huge success
                aci_objects_update_succeeded = True

            return {
                "success": True,
                "aci_objects_update_succeeded": aci_objects_update_succeeded,
            }
        else:
            LOG.error("Failed to set hostgroup %s to mode %s - no DB entry?", hostgroup_name, new_mode)
            raise web_exc.HTTPConflict("Could not set hostmode of hostgroup %s - DB entry could not be found",
                                       hostgroup_name)

    def _get_mode(self, ctx, hostgroup_name):
        modes = self.db.get_hostgroup_modes(ctx, [hostgroup_name])
        if hostgroup_name not in modes:
            raise web_exc.HTTPNotFound('Hostgroup "{}" does not exist or is not a direct-mode hostgroup'
                                       .format(hostgroup_name))
        return modes[hostgroup_name]


class NetworksController(wsgi.Controller):
    def __init__(self, plugin, db, rpc_notifier):
        super().__init__()
        self.plugin = plugin
        self.db = db
        self.rpc_notifier = rpc_notifier
        self.rpc_api = rpc_api.AgentRpcCallback(self.db)

    @check_cloud_admin
    def index(self, request, **kwargs):
        raise web_exc.HTTPBadRequest("Listing networks is not implemented")

    @check_cloud_admin
    def show(self, request, **kwargs):
        network_id = kwargs.pop('id')
        network = self.plugin.get_network(request.context, network_id)
        # NOTE: This is where we could fetch state from the ACI about this network / EPG
        return {'id': network['id'], 'name': network['name']}

    @check_cloud_admin
    def update(self, request, **kwargs):
        network_id = kwargs.pop('id')
        network = self.plugin.get_network(request.context, network_id)
        sync_data = self.rpc_api._get_network(request.context, network)
        self.rpc_notifier.sync_network(request.context, sync_data)

        return {'sync_sent': True}


class NullroutesController(wsgi.Controller):
    COLLECTION_ACTIONS = {'sync': 'PUT', 'db_data': 'GET'}

    def __init__(self, plugin, db, rpc_notifier):
        super().__init__()
        self.plugin = plugin
        self.db = db
        self.rpc_notifier = rpc_notifier
        self.rpc_api = rpc_api.AgentRpcCallback(self.db)

    @check_cloud_admin
    def index(self, request, **kwargs):
        return self.rpc_api.get_leaf_nullroutes(request.context)

    @check_cloud_admin
    def show(self, request, **kwargs):
        raise web_exc.HTTPBadRequest("Showing details is not implemented")

    @check_cloud_admin
    def db_data(self, request, **kwargs):
        data = self.db.get_external_subnet_nullroute_mapping(request.context)
        for net in data.values():
            net['hosts'] = list(net['hosts'])
        return data

    @check_cloud_admin
    def sync(self, request, **kwargs):
        self.rpc_notifier.sync_nullroutes(request.context)
        return {'sync_sent': True}


class AZAwareSubnetRoutes(wsgi.Controller):
    COLLECTION_ACTIONS = {'sync': 'PUT', 'db_data': 'GET'}

    def __init__(self, plugin, db, rpc_notifier):
        super().__init__()
        self.plugin = plugin
        self.db = db
        self.rpc_notifier = rpc_notifier
        self.rpc_api = rpc_api.AgentRpcCallback(self.db)

    @check_cloud_admin
    def index(self, request, **kwargs):
        return self.rpc_api.get_az_aware_subnet_routes(request.context)

    @check_cloud_admin
    def show(self, request, **kwargs):
        raise web_exc.HTTPBadRequest("Showing details is not implemented")

    @check_cloud_admin
    def db_data(self, request, **kwargs):
        return self.db.get_az_aware_external_subnets(request.context)

    @check_cloud_admin
    def sync(self, request, **kwargs):
        self.rpc_notifier.sync_az_aware_subnet_routes(request.context)
        return {'sync_sent': True}
