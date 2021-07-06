# Copyright 2020 SAP SE
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

from neutron_lib import exceptions


class NoAllocationFoundInMaximumAllowedAttempts(exceptions.NeutronException):
    message = "No free allocation could be found within the maximum number of allowed attempts"


class ACIOpenStackConfigurationError(exceptions.NeutronException):
    message = "%(reason)s"


class TrunkHostgroupNotInBaremetalMode(exceptions.NeutronException):
    message = "Cannot create trunk on for port %(port_id)s: Hostgroup %(hostgroup)s is not in baremetal mode"


class TrunkCannotAllocateReservedVlan(exceptions.NeutronException):
    message = "VLAN %(segmentation_id)s is reserved and cannot be allocated by users"


class TrunkSegmentationIdNotInAllowedRange(exceptions.NeutronException):
    message = ("VLAN %(segmentation_id)s is not inside predefined VLAN range "
               "(needs to be between %(segmentation_start)s and %(segmentation_end)s)")


class TrunkSegmentationNotConsistentInProject(exceptions.NeutronException):
    message = ("Cannot bind subport %(port_id)s: VLAN %(segmentation_id)s is already used in project %(project_id)s in "
               "network %(network_id)s - you need to provide VLAN consistency inside your project for all "
               "ACI-connected baremetal servers.")


class NetworkHasBoundTrunkPorts(exceptions.NeutronException):
    message = ("Cannot bind access port in network %(network_id)s as segment %(segment_id)s is already present with "
               "trunk segmentation id %(segmentation_id)s")


class NetworkUsesDifferentTrunkId(exceptions.NeutronException):
    message = ("Network %(network_id)s has already trunk ports present with id %(segmentation_id)s, please use this id "
               "to provide VLAN consistency")


class TrunkSegmentIdAlreadyInUse(exceptions.NeutronException):
    message = ("Segmentation id %(segmentation_id)s is already in use by network segment %(segment_id)s, "
               "cannot repurpose it")


class HostAlreadyHasAccessBinding(exceptions.NeutronException):
    message = ("Host %(host)s already has existing access binding with segmentation id %(segmentation_id)s "
               "on segment %(segment_id)s")


class AccessSegmentationIdAllocationPoolExhausted(exceptions.NeutronException):
    message = ("Cannot allocate segmentation id for %(hostgroup_name)s - "
               "the access segmentation id pool for physical network %(physical_network)s is exhausted")
