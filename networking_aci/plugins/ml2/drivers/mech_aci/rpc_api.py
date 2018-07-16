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
import oslo_messaging
from oslo_log import log as logging
from oslo_log import helpers as log_helpers
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron_lib import context
from neutron.plugins.ml2 import db as ml2_db
from neutron.services.tag import tag_plugin
from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_constants
from networking_aci.plugins.ml2.drivers.mech_aci import common
import driver


LOG = logging.getLogger(__name__)

class ACIRpcAPI(object):
    def bind_port(self, rpc_context, port, host_config, segment, next_segment):
        self.bind_port_postcommit(port, host_config, segment, next_segment)

    @log_helpers.log_method_call
    def delete_port(self, rpc_context, port, host_config, clear_phys_dom):
        self.delete_port_postcommit(port, host_config, clear_phys_dom)

    def create_network(self, rpc_context, network, external=False):
        self.create_network_postcommit(network,external)

    def delete_network(self, rpc_context, network):
        self.delete_network_postcommit(network)

    def create_subnet(self, rpc_context, subnet, external, address_scope_name):
        self.create_subnet_postcommit(subnet, external, address_scope_name)

    def delete_subnet(self, rpc_context, subnet, external, address_scope_name,last_on_network):
        self.delete_subnet_postcommit(subnet, external, address_scope_name,last_on_network)


class AgentRpcCallback(object):

    def __init__(self):
        self.db = common.DBPlugin()
        self.context = context.get_admin_context()
        self.tag_plugin = tag_plugin.TagPlugin()

    @log_helpers.log_method_call
    def get_network(self, rpc_context, network_id):
        network = self.db.get_network(self.context, network_id)
        return self._get_network(network)


    @log_helpers.log_method_call
    def get_networks(self, rpc_context, limit=None, marker=None):
        LOG.debug("limit %s marker %s",limit,marker)
        result=[]
        networks = self.db.get_networks(self.context, sorts=[('id','desc')], limit=limit, marker=marker)

        for network in networks:
            result.append(self._get_network(network))

        LOG.debug("networks len %s",len(result))

        return result


    @log_helpers.log_method_call
    def get_network_ids(self, rpc_context):
        networks =  self.db.get_networks(self.context,fields=['id'])

        result = []
        for network in networks:
            result.append(network.get('id'))

        return result


    @log_helpers.log_method_call
    def get_networks_count(self, rpc_context):
        return self.db.get_networks_count(self.context)

    def _get_network(self, network):
        start = time.time()
        network_id = network.get('id')
        host_group_config = common.get_network_config()['hostgroup_dict']
        fixed_binding_config = common.get_network_config()['fixed_bindings_dict']
        segments = common.get_segments(self.context, network_id)


        tags = self.tag_plugin.get_tags(self.context, 'networks',network_id).get('tags',[])

        network_fixed_bindings = []
        for tag in tags:
            network_fixed_binding = fixed_binding_config.get(tag, None)
            if network_fixed_binding:
                network_fixed_bindings.append(network_fixed_binding)

        segment_dict = {}

        for segment in segments:
            segment_dict[segment.get('id')] = {'id':segment.get('id'),'segmentation_id':segment.get('segmentation_id'),'physical_network':segment.get('physical_network'), 'network_type':segment.get('network_type')}

        result = {'id': network_id, 'name': network.get('name'), 'router:external': network.get('router:external'),'subnets':[],'bindings':[],'fixed_bindings': network_fixed_bindings}

        subnets = self.db.get_subnets_by_network(self.context,network.get('id'))

        for subnet in subnets:
            pool_id = subnet.get('subnetpool_id')
            address_scope_name = None

            if pool_id:
                address_scope_name = common.get_address_scope_name(self.context, pool_id)
            result['subnets'].append({'id':subnet.get('id'), 'network_id':network_id, 'cidr':subnet.get('cidr'), 'address_scope_name': address_scope_name, 'gateway_ip': subnet.get('gateway_ip')})

        ports = self.db.get_ports_with_binding(self.context, network_id)

        processed_hosts =[]

        for port in ports:
            port_binding = port.port_binding


            binding_host = ml2_db.get_port_binding_host(self.context, port['id'])

            config_host =port_binding.get('host')

            if binding_host not in processed_hosts:
                binding_profile = port_binding.get('profile')


                if binding_profile:
                    switch = driver.CiscoACIMechanismDriver.switch_from_local_link(binding_profile)

                    if switch:
                        config_host = switch

                binding_levels = ml2_db.get_binding_levels(self.context.session, port['id'],binding_host)

                host_id, host_config = common.get_host_or_host_group(config_host,host_group_config)

                if binding_levels:
                    #for now we use binding level one
                    for binding in binding_levels:

                        if binding.level==1 :
                            # Store one binding for each binding host
                            segment = segment_dict.get(binding.segment_id)
                            if segment:
                                result['bindings'].append({'binding:host_id':binding_host,'host_config':host_config,'encap':segment.get('segmentation_id'),'network_type':segment.get('network_type'),'physical_network':segment.get('physical_network')})
                                processed_hosts.append(binding_host)

        LOG.info("get network %s :  %s seconds", network_id, (time.time() - start))
        return result


class ACIRpcClientAPI(object):
    version = '1.0'

    def __init__(self, rpc_context):
        target = oslo_messaging.Target(topic=aci_constants.ACI_TOPIC, version='1.0')
        self.client = n_rpc.get_client(target)
        self.rpc_context = rpc_context

    def _topic(self, action=topics.CREATE, host=None):
        return topics.get_topic_name(topics.AGENT, aci_constants.ACI_TOPIC, action, host)

    def _fanout(self):
        return self.client.prepare(version=self.version, topic=self._topic(), fanout=True)

    def bind_port(self, port, host_config, segment, next_segment):
        self._fanout().cast(self.rpc_context, 'bind_port', port=port, host_config=host_config, segment=segment,
                            next_segment=next_segment)

    def delete_port(self, port, host_config, clear_phys_dom):
        self._fanout().cast(self.rpc_context, 'delete_port', port=port, host_config=host_config, clear_phys_dom=clear_phys_dom)

    def create_network(self, network, external):
        self._fanout().cast(self.rpc_context, 'create_network', network=network, external=external)

    def delete_network(self, network):
        self._fanout().cast(self.rpc_context, 'delete_network', network=network)

    def create_subnet(self, subnet, external=False, address_scope_name=None):
        self._fanout().cast(self.rpc_context, 'create_subnet', subnet=subnet, external=external,
                            address_scope_name=address_scope_name)

    def delete_subnet(self, subnet, external=False, address_scope_name=None, last_on_network=None):
        self._fanout().cast(self.rpc_context, 'delete_subnet', subnet=subnet, external=external,
                            address_scope_name=address_scope_name,last_on_network=last_on_network)

class AgentRpcClientAPI(object):
    version = '1.0'


    def __init__(self, rpc_context):
        target = oslo_messaging.Target(topic=aci_constants.ACI_TOPIC, version='1.0')
        self.client = n_rpc.get_client(target)
        self.rpc_context = rpc_context


    def _fanout(self):
        return self.client.prepare(version=self.version, topic=aci_constants.ACI_TOPIC, fanout=False)


    def get_network(self, network_id):
        return self._fanout().call(self.rpc_context, 'get_network', network_id=network_id)

    def get_networks_count(self):
        return self._fanout().call(self.rpc_context, 'get_networks_count')


    def get_networks(self,limit=None , marker=None):
        return self._fanout().call(self.rpc_context, 'get_networks',limit=limit , marker=marker)

    def get_network_ids(self):
        return self._fanout().call(self.rpc_context, 'get_network_ids',)