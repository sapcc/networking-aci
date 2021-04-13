# Copyright 2018 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from neutron.tests import base

from networking_aci.plugins.ml2.drivers.mech_aci.allocations_manager import AllocationsManager


class AciNeutronAgentTest(base.BaseTestCase):
    def test_segmentation_ids(self):
        # test single range
        r = AllocationsManager._segmentation_ids({'segment_range': [(100, 110)]})
        self.assertEqual({100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110}, r)

        # test range with one element
        r = AllocationsManager._segmentation_ids({'segment_range': [(100, 100)]})
        self.assertEqual({100}, r)

        # test multiple ranges
        r = AllocationsManager._segmentation_ids({'segment_range': [(100, 103), (110, 112)]})
        self.assertEqual({100, 101, 102, 103, 110, 111, 112}, r)

        # test overlapping range
        r = AllocationsManager._segmentation_ids({'segment_range': [(100, 102), (101, 103)]})
        self.assertEqual({100, 101, 102, 103}, r)
