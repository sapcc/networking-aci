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
from oslo_log import log as logging
from neutron.db import db_base_plugin_v2
from neutron.db import address_scope_db
from neutron.db import external_net_db
from neutron.db import portbindings_db
from neutron.plugins.ml2 import db as ml2_db
from networking_aci.plugins.ml2.drivers.mech_aci import config

LOG = logging.getLogger(__name__)

class DBPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                portbindings_db.PortBindingMixin,
                address_scope_db.AddressScopeDbMixin,
                external_net_db.External_net_db_mixin,
                ):

    def __init__(self):
        pass


def get_network_config():
    return {
            'hostgroup_dict': config.create_hostgroup_dictionary(),
            'address_scope_dict': config.create_addressscope_dictionary()
            }

def get_host_or_host_group(host_id,host_group_config):
    for hostgroup, hostgroup_config in host_group_config.iteritems():
        if host_id in hostgroup_config['hosts']:
            return hostgroup, hostgroup_config

    return host_id, None



def get_address_scope_name(context, subnet_pool_id):

    plugin = DBPlugin()

    pool = plugin.get_subnetpool(context, subnet_pool_id)

    if not pool:
        LOG.warn("Subnet pool {} does not exist".format(subnet_pool_id))
        return

    scope = plugin.get_address_scope(context, pool['address_scope_id'])

    if not scope:
        LOG.warn("Address scope {} does not exist".format(['pool.address_scope_id']))
        return

    return scope.get('name')


def get_segments(context,network_id):
    return ml2_db.get_network_segments(context.session,network_id)
