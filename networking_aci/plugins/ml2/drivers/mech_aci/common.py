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
from neutron_lib.exceptions import address_scope as ext_address_scope
from neutron.db import address_scope_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import segments_db as ml2_db
from neutron.plugins.ml2 import models as ml2_models
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class DBPlugin(db_base_plugin_v2.NeutronDbPluginV2,
               address_scope_db.AddressScopeDbMixin,
               external_net_db.External_net_db_mixin):

    def __init__(self):
        pass

    def get_ports_with_binding(self, context, network_id):
        with context.session.begin(subtransactions=True):
            query = context.session.query(models_v2.Port)
            query1 = query.join(ml2_models.PortBinding)
            bind_ports = query1.filter(models_v2.Port.network_id == network_id)

            return bind_ports

    def get_network_ids(self, context):
        result = []
        query = context.session.query(models_v2.Network.id).order_by(models_v2.Network.id)
        for network in query:
            result.append(network.id)

        return result

    def get_address_scope_name(self, context, subnet_pool_id):
        pool = self.get_subnetpool(context, subnet_pool_id)

        if not pool:
            LOG.warn("Subnet pool {} does not exist".format(subnet_pool_id))
            return

        try:
            scope = self.get_address_scope(context, pool['address_scope_id'])
        except ext_address_scope.AddressScopeNotFound:
            LOG.warn("Address scope {} does could not be found, check ACI config for correct configuration"
                     .format(['pool.address_scope_id']))
            return

        # This may not be needed no address scope not found is caught
        if not scope:
            LOG.warn("Address scope {} does not exist, check ACI config for correct configuration"
                     .format(['pool.address_scope_id']))
            return

        return scope.get('name')


def get_segments(context, network_id):
    return ml2_db.get_network_segments(context, network_id)
