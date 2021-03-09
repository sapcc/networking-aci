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


class SegmentExistsWithDifferentSegmentationId(exceptions.NeutronException):
    message = ("Segmentation id %(segmentation_id)s already in use by segment %(segment_id)s for "
               "network %(network_id)s and physnet %(physnet)s")


class ACIOpenStackConfigurationError(exceptions.NeutronException):
    message = "%(reason)s"
