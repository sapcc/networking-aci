# Copyright 2021 SAP SE
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
from oslo_config import cfg

from networking_aci.plugins.ml2.drivers.mech_aci.tenant_managers.hash_ring_manager import HashRingTenantManager


class HashRingTenantManagerTest(base.BaseTestCase):
    def setUp(self):
        super(HashRingTenantManagerTest, self).setUp()
        cfg.CONF.set_override('tenant_ring_size', 60, group='ml2_aci')
        cfg.CONF.set_override('tenant_prefix', 'test', group='ml2_aci')

    def test_hash_consistency(self):
        """Test if the consistent hashing stays consistent

        We want to make sure that nothing changes in our hashring, as this
        could cause a massive movement of networks / EPGs between tenants
        """

        # generated with [hrtm.get_tenant_name(str(i)) for i in range(100)]
        reference = [
            'test-8', 'test-33', 'test-54', 'test-37', 'test-33', 'test-30', 'test-0', 'test-6', 'test-58',
            'test-28', 'test-42', 'test-38', 'test-58', 'test-50', 'test-33', 'test-3', 'test-25', 'test-26',
            'test-39', 'test-3', 'test-5', 'test-44', 'test-46', 'test-44', 'test-29', 'test-13', 'test-41',
            'test-48', 'test-47', 'test-22', 'test-25', 'test-17', 'test-37', 'test-39', 'test-0', 'test-33',
            'test-32', 'test-4', 'test-24', 'test-23', 'test-39', 'test-50', 'test-10', 'test-58', 'test-10',
            'test-57', 'test-9', 'test-24', 'test-22', 'test-53', 'test-39', 'test-17', 'test-16', 'test-55',
            'test-27', 'test-22', 'test-56', 'test-8', 'test-32', 'test-10', 'test-34', 'test-3', 'test-11',
            'test-30', 'test-0', 'test-46', 'test-10', 'test-23', 'test-12', 'test-8', 'test-0', 'test-40',
            'test-34', 'test-44', 'test-50', 'test-35', 'test-1', 'test-36', 'test-50', 'test-19', 'test-48',
            'test-5', 'test-55', 'test-43', 'test-6', 'test-36', 'test-9', 'test-13', 'test-14', 'test-7',
            'test-25', 'test-25', 'test-4', 'test-26', 'test-32', 'test-41', 'test-56', 'test-18', 'test-4',
            'test-27',
        ]

        hrtm = HashRingTenantManager()
        keys = [hrtm.get_tenant_name(str(i)) for i in range(100)]

        self.assertEqual(reference, keys)
