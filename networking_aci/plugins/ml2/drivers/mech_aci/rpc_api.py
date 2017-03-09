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

import oslo_messaging
from neutron.common import rpc as n_rpc
from neutron.common import topics

from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_constants


class ACIRpcAPI(object):
    def bind_port(self, rpc_context, port, host_config, segment, next_segment):
        self.bind_port_postcommit(port, host_config, segment, next_segment)

    def delete_port(self, rpc_context, port, host_config, clear_phys_dom):
        self.delete_port_postcommit(port, host_config, clear_phys_dom)

    def create_network(self, rpc_context, network):
        self.create_network_postcommit(network)

    def delete_network(self, rpc_context, network):
        self.delete_network_postcommit(network)

    def create_subnet(self, rpc_context, subnet, external, address_scope_name):
        self.create_subnet_postcommit(subnet, external, address_scope_name)

    def delete_subnet(self, rpc_context, subnet, external, address_scope_name):
        self.delete_subnet_postcommit(subnet, external, address_scope_name)


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

    def create_network(self, network):
        self._fanout().cast(self.rpc_context, 'create_network', network=network)

    def delete_network(self, network):
        self._fanout().cast(self.rpc_context, 'delete_network', network=network)

    def create_subnet(self, subnet, external=False, address_scope_name=None):
        self._fanout().cast(self.rpc_context, 'create_subnet', subnet=subnet, external=external,
                            address_scope_name=address_scope_name)

    def delete_subnet(self, subnet, external=False, address_scope_name=None):
        self._fanout().cast(self.rpc_context, 'delete_subnet', subnet=subnet, external=external,
                            address_scope_name=address_scope_name)
