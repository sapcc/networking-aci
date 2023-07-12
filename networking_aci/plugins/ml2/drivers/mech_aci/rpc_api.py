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
import time

from neutron_lib.agent import topics
from neutron_lib.exceptions import NetworkNotFound
from neutron_lib import rpc as n_rpc
from neutron.extensions import tagging
from neutron.services.tag import tag_plugin
from oslo_log import log as logging
from oslo_log import helpers as log_helpers
import oslo_messaging
from sqlalchemy.orm import exc as orm_exc

from networking_aci.plugins.ml2.drivers.mech_aci import common
from networking_aci.plugins.ml2.drivers.mech_aci.config import ACI_CONFIG
from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const

LOG = logging.getLogger(__name__)


class ACIRpcAPI(object):
    def bind_port(self, context, port, host_config, segment, next_segment):
        self.bind_port_postcommit(port, host_config, segment, next_segment)

    def delete_port(self, context, port, host_config, clearable_phys_doms, clearable_bm_entities,
                    reset_bindings_to_infra):
        raise NotImplementedError

    def create_network(self, context, network, external=False):
        raise NotImplementedError

    def delete_network(self, context, network):
        raise NotImplementedError

    def create_subnet(self, context, subnet, external, address_scope_name):
        raise NotImplementedError

    def delete_subnet(self, context, subnet, external, address_scope_name, last_on_network):
        raise NotImplementedError

    def clean_baremetal_objects(self, context, resource_name):
        raise NotImplementedError

    def sync_direct_mode_config(self, context, host_config):
        raise NotImplementedError

    def sync_network(self, context, network):
        raise NotImplementedError

    def sync_network_id(self, context, network_id):
        raise NotImplementedError


class AgentRpcCallback(object):

    def __init__(self, db):
        self.db = db
        self.tag_plugin = tag_plugin.TagPlugin()

    @log_helpers.log_method_call
    def get_binding_count(self, rpc_context):
        return len(ACI_CONFIG.hostgroups) + len(ACI_CONFIG.fixed_bindings)

    @log_helpers.log_method_call
    def get_network(self, rpc_context, network_id):
        network = self.db.get_network(rpc_context, network_id)
        return self._get_network(rpc_context, network)

    @log_helpers.log_method_call
    def get_networks(self, rpc_context, limit=None, marker=None):
        LOG.debug("limit %s marker %s", limit, marker)
        result = []
        try:
            networks = self.db.get_networks(rpc_context, sorts=[('id', 'desc')], limit=limit, marker=marker)
            for network in networks:
                result.append(self._get_network(rpc_context, network))
        except NetworkNotFound:
            LOG.debug("Network marker not found: %s", marker)

        LOG.debug("networks len %s", len(result))

        return result

    @log_helpers.log_method_call
    def get_network_ids(self, rpc_context):
        return self.db.get_network_ids(rpc_context)

    @log_helpers.log_method_call
    def get_networks_count(self, rpc_context):
        return self.db.get_networks_count(rpc_context)

    def _get_network(self, context, network):
        start = time.time()
        network_id = network['id']

        result = {
            'id': network_id,
            'name': network.get('name'),
            'router:external': network.get('router:external'),
            'subnets': [],
            'bindings': [],
            'fixed_bindings': [],
        }

        # fixed bindings
        try:
            tags = self.tag_plugin.get_tags(context, 'networks', network_id).get('tags', [])
        except tagging.TagResourceNotFound:
            LOG.warning("Cannot find network {} while attempting to check static binding tag".format(network_id))
            tags = []
        result['tags'] = tags

        for tag in tags:
            network_fixed_binding = ACI_CONFIG.get_fixed_binding_by_tag(tag)
            if network_fixed_binding:
                result['fixed_bindings'].append(network_fixed_binding)

        # subnets
        subnets = self.db.get_subnets_by_network(context, network.get('id'))
        for subnet in subnets:
            pool_id = subnet.get('subnetpool_id')
            address_scope_name = None

            if pool_id:
                address_scope_name = self.db.get_address_scope_name(context, pool_id)
            result['subnets'].append({
                'id': subnet.get('id'),
                'network_id': network_id,
                'cidr': subnet.get('cidr'),
                'address_scope_name': address_scope_name,
                'gateway_ip': subnet.get('gateway_ip')
            })

        # bindings
        segments = common.get_segments(context, network_id)
        segment_dict = {}
        for segment in segments:
            segment_dict[segment.get('id')] = segment

        processed_hostgroups = []
        transit_hgs = ACI_CONFIG.get_transit_hostgroups()
        host_segments = self.db.get_hosts_on_network(context, network_id, level=1, with_segment=True,
                                                     transit_hostgroups=transit_hgs)
        for host, segment_id in host_segments:
            hostgroup_name = ACI_CONFIG.get_hostgroup_name_by_host(host)
            if not hostgroup_name or hostgroup_name in processed_hostgroups:
                continue

            hostgroup = ACI_CONFIG.get_hostgroup(context, hostgroup_name, segment_id, level=1)
            if not hostgroup:
                LOG.error("Found hostgroup %s for host %s but not present in dictionary - will not be bound in %s",
                          hostgroup_name, host, network_id)
                continue

            # for mode baremetal: override baremetal_resource_name
            ACI_CONFIG.annotate_baremetal_info(context, hostgroup, network_id)

            segment = segment_dict[segment_id]
            result['bindings'].append({
                'binding:host_id': host,
                'host_config': hostgroup,
                'encap': segment.get('segmentation_id'),
                'network_type': segment.get('network_type'),
                'physical_network': segment.get('physical_network')
            })
            processed_hostgroups.append(hostgroup_name)

        LOG.info("get network %s: %0.2fs", network_id, (time.time() - start))
        return result

    @log_helpers.log_method_call
    def tag_network(self, rpc_context, network_id, tag):
        try:
            self.tag_plugin.update_tag(rpc_context, 'networks', network_id, tag)
        except tagging.TagResourceNotFound:
            LOG.info("Tagging attempt made on missing network {} , network may have been deleted concurrently."
                     .format(network_id))
        except orm_exc.StaleDataError:
            LOG.info("Tagging attempt resulted in stale data error on DB access for network {}, "
                     "network may have been deleted concurrently."
                     .format(network_id))


class ACIRpcClientAPI(object):
    version = '1.0'

    def __init__(self):
        target = oslo_messaging.Target(topic=aci_const.ACI_TOPIC, version='1.0')
        self.client = n_rpc.get_client(target)

    def _topic(self, action=topics.CREATE, host=None):
        return topics.get_topic_name(topics.AGENT, aci_const.ACI_TOPIC, action, host)

    def _fanout(self):
        return self.client.prepare(version=self.version, topic=self._topic(), fanout=True)

    def bind_port(self, context, port, host_config, segment, next_segment):
        self._fanout().cast(context, 'bind_port', port=port, host_config=host_config, segment=segment,
                            next_segment=next_segment)

    def delete_port(self, context, port, host_config, clearable_phys_doms, clearable_bm_entities,
                    reset_bindings_to_infra):
        self._fanout().cast(context, 'delete_port', port=port, host_config=host_config,
                            clearable_phys_doms=clearable_phys_doms, clearable_bm_entities=clearable_bm_entities,
                            reset_bindings_to_infra=reset_bindings_to_infra)

    def create_network(self, context, network, external):
        self._fanout().cast(context, 'create_network', network=network, external=external)

    def delete_network(self, context, network):
        self._fanout().cast(context, 'delete_network', network=network)

    def create_subnet(self, context, subnet, external=False, address_scope_name=None):
        self._fanout().cast(context, 'create_subnet', subnet=subnet, external=external,
                            address_scope_name=address_scope_name)

    def delete_subnet(self, context, subnet, external=False, address_scope_name=None, last_on_network=None):
        self._fanout().cast(context, 'delete_subnet', subnet=subnet, external=external,
                            address_scope_name=address_scope_name, last_on_network=last_on_network)

    def clean_baremetal_objects(self, context, resource_name):
        self._fanout().cast(context, 'clean_baremetal_objects', resource_name=resource_name)

    def sync_direct_mode_config(self, context, host_config):
        self._fanout().cast(context, 'sync_direct_mode_config', host_config=host_config)

    def sync_network(self, context, network):
        self._fanout().cast(context, 'sync_network', network=network)

    def sync_network_id(self, context, network_id):
        self._fanout().cast(context, 'sync_network_id', network_id=network_id)


class AgentRpcClientAPI(object):
    version = '1.0'

    def __init__(self):
        target = oslo_messaging.Target(topic=aci_const.ACI_TOPIC, version='1.0')
        self.client = n_rpc.get_client(target)

    def _fanout(self):
        return self.client.prepare(version=self.version, topic=aci_const.ACI_TOPIC, fanout=False)

    def get_network(self, context, network_id):
        return self._fanout().call(context, 'get_network', network_id=network_id)

    def get_networks_count(self, context):
        return self._fanout().call(context, 'get_networks_count')

    def get_networks(self, context, limit=None, marker=None):
        return self._fanout().call(context, 'get_networks', limit=limit, marker=marker)

    def get_network_ids(self, context):
        return self._fanout().call(context, 'get_network_ids',)

    def get_binding_count(self, context):
        return self._fanout().call(context, 'get_binding_count')

    def tag_network(self, context, network_id, tag):
        return self._fanout().call(context, 'tag_network', network_id=network_id, tag=tag)
