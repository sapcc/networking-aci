# Copyright 2016 SAP SE
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
ACI_AGENT_TYPE = 'ACI Agent'
ACI_TOPIC = "ACI"
DEFAULT_ACI_RESPAWN = 30
VIF_TYPE_ACI = 'aci'
ACI_DRIVER_NAME = 'aci'  # same as setup.cfg aci = ... in entry_points

MODE_BAREMETAL = 'baremetal'
MODE_INFRA = 'infra'

TRUNK_PROFILE = 'aci_trunk'

CC_FABRIC_TRANSIT = 'cc-fabric-transit'  # needs to be aligned with networking-ccloud
CC_FABRIC_NET_GW = 'cc-fabric-network-gateway'

CC_FABRIC_L3_GATEWAY_TAG = 'gateway-host::cc-fabric'
