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
from neutron_lib import context
from neutron_lib.plugins import constants as plugin_constants
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
        plugin = directory.get_plugin(plugin_constants.L3)
        db = DBPlugin()
        endpoints = []
        rpc_context = context.get_admin_context_without_session()
        rpc_notifier = rpc_api.ACIRpcClientAPI(rpc_context)

        # config endpoint
        # dump hostgroup dict / aci config
        res = Resource(ConfigController(plugin, db), faults.FAULT_MAP)
        config_endpoint = extensions.ResourceExtension('aci-ml2/config', res)
        endpoints.append(config_endpoint)

        # hostgroup_mode endpoint
        res = Resource(HostgroupModeController(plugin, db, rpc_notifier), faults.FAULT_MAP)
        hg_mode_endpoint = extensions.ResourceExtension('aci-ml2/hostgroup-modes', res)
        endpoints.append(hg_mode_endpoint)

        return endpoints


# make sure this plugin gets autodiscovered and disable api-support checks
# we need to do it this way because we do not have our own plugin that we associate with
extensions.register_custom_supported_check(Acioperations.get_alias(), lambda: True, True)
extensions.append_api_extensions_path(networking_aci.extensions.__path__)


class ConfigController(wsgi.Controller):
    def __init__(self, plugin, db):
        super(ConfigController, self).__init__()
        self.plugin = plugin

    @check_cloud_admin
    def index(self, request, **kwargs):
        """Show all hostgroup, fixed bindings and address scopes"""
        if request.GET.get("raw", False):
            hostgroups = ACI_CONFIG.hostgroups
        else:
            hostgroups = {}
            for hg_name in ACI_CONFIG.hostgroups:
                hostgroups[hg_name] = ACI_CONFIG.get_hostgroup(hg_name)

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
            hostgroup = ACI_CONFIG.get_hostgroup(hostgroup_name)

        if not hostgroup:
            raise web_exc.HTTPNotFound('Hostgroup "{}" does not exist'.format(hostgroup_name))

        return hostgroup


class HostgroupModeController(wsgi.Controller):
    def __init__(self, plugin, db, rpc_notifier):
        super(HostgroupModeController, self).__init__()
        self.plugin = plugin
        self.db = db
        self.rpc_notifier = rpc_notifier

    @check_cloud_admin
    def index(self, request, **kwargs):
        ctx = context.get_admin_context()
        return dict(hostgroup_modes=self.db.get_hostgroup_modes(ctx))

    @check_cloud_admin
    def show(self, request, **kwargs):
        hostgroup_name = kwargs.pop('id')
        ctx = context.get_admin_context()
        return dict(hostgroup_name=hostgroup_name, hostgroup_mode=self._get_mode(ctx, hostgroup_name))

    @check_cloud_admin
    def update(self, request, **kwargs):
        hostgroup_name = kwargs.pop('id')
        new_mode = kwargs.get("body", {}).get("mode")
        if new_mode not in (aci_const.MODE_INFRA, aci_const.MODE_BAREMETAL):
            raise web_exc.HTTPBadRequest("Specify a mode that is either {} or {} (given mode was '{}')"
                                         .format(aci_const.MODE_INFRA, aci_const.MODE_BAREMETAL, new_mode))

        ctx = context.get_admin_context()
        curr_mode = self._get_mode(ctx, hostgroup_name)
        if curr_mode == new_mode:
            raise web_exc.HTTPBadRequest("{} is already in {} mode".format(hostgroup_name, new_mode))

        # check if there are still ports on this hostgroup
        hg_config = ACI_CONFIG.get_hostgroup(hostgroup_name)
        if not hg_config:
            raise web_exc.HTTPBadRequest("Hostgroup {} has no config associated with it".format(hostgroup_name))

        for segment_id in self.db.get_segment_ids_by_physnet(ctx, hg_config['physical_network']):
            hosts = self.db.get_hosts_on_segment(ctx, segment_id)
            for host in hg_config['hosts']:
                if host in hosts:
                    LOG.error("Denied API request to switch hostgroup %s to %s mode, host %s still bound in segment %s",
                              hostgroup_name, new_mode, host, segment_id)
                    raise web_exc.HTTPConflict("Could not switch, there is still a portbinding for host {} "
                                               "present in segment {}"
                                               .format(host, segment_id))

        # cleanup old baremetal objects when switching away from baremetal mode
        baremetal_bindings_cleaned = False
        if hg_config['hostgroup_mode'] == aci_const.MODE_BAREMETAL:
            LOG.info("Cleaning baremetal objects for %s from device", hostgroup_name)
            try:
                self.rpc_notifier.clean_baremetal_objects(hg_config)
                baremetal_bindings_cleaned = True
            except Exception:
                LOG.exception("Could not clean baremetal bindings from ACI, cleaning will have to be done manually")

        if self.db.set_hostgroup_mode(ctx, hostgroup_name, new_mode):
            LOG.info("Hostgroup %s set to mode %s", hostgroup_name, new_mode)

            hg_config = ACI_CONFIG.get_hostgroup(hostgroup_name)
            aci_objects_update_succeeded = False
            try:
                # switching policy group of port selectors, etc.
                self.rpc_notifier.sync_direct_mode_config(hg_config)
                aci_objects_update_succeeded = True
            except Exception:
                LOG.exception("Could not update bindings on ACI, rpc call failed")

            return {
                "success": True,
                "baremetal_bindings_cleaned": baremetal_bindings_cleaned,
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