# Copyright 2020 SAP SE
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

import mock
from neutron_lib.plugins import directory
from oslo_config import cfg

import networking_aci.plugins.ml2.drivers.mech_aci.config  # noqa
from neutron.plugins.ml2.drivers import type_vlan  # noqa
from neutron.plugins.ml2.drivers import type_vxlan  # noqa
from neutron_lib.plugins.ml2 import api
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base

from neutron.tests.unit.plugins.ml2 import test_plugin

VIF_TYPE_TEST = 'vif_type_test'


class TestACIMechanismDriver(test_plugin.Ml2PluginV2TestCase):
    """Test mechanism driver for testing ACI mechanism driver api."""

    _mechanism_drivers = ['aci', 'logger']

    def setUp(self):
        cfg.CONF.set_override('tenant_network_types',
                              ['vxlan', 'vlan'],
                              group='ml2')
        cfg.CONF.set_override('network_vlan_ranges',
                              ['testcp:2000:3000'],
                              group='ml2_type_vlan')
        cfg.CONF.set_override('vni_ranges',
                              ['1:65536'],
                              group='ml2_type_vxlan')
        cfg.CONF.set_override('vni_ranges',
                              ['1:65536'],
                              group='ml2_type_vxlan')
        super(TestACIMechanismDriver, self).setUp()
        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['aci'].obj
        self.mech_driver.host_group_config = {
            'testgroup': {
                'hosts': ['host'],
                'physical_network': 'fake-physnet',
                'segment_type': 'vlan',
                'physical_domain': ['Basic_Domain']
            }
        }

    def _make_port_ctx(self, agents):
        segments = [{api.ID: 'local_segment_id', api.NETWORK_TYPE: 'local'}]
        return base.FakePortContext(self.AGENT_TYPE, agents, segments,
                                    vnic_type=self.VNIC_TYPE)

    def test_bind_port_host_not_found(self):
        fake_segments = [{'network_type': 'vxlan',
                          'physical_network': 'fake-physnet',
                          'segmentation_id': 23,
                          'id': 'test-id'},]
        context = self._test_bind_port(fake_segments, fake_host='unkown_host')
        context.continue_binding.assert_not_called()

    def test_bind_port_no_segments_to_bind(self):
        context = self._test_bind_port([])
        context.continue_binding.assert_not_called()

    def test_bind_port_physnet_not_found(self):
        fake_segments = [{'network_type': 'vlan',
                         'physical_network': 'unknown-physnet',
                         'segmentation_id': 23,
                          'id': 'test-id'}]
        context = self._test_bind_port(fake_segments)
        context.continue_binding.assert_not_called()

    def _test_bind_port(self, fake_segments, fake_host = 'host'):
        with mock.patch.object(base.FakePortContext, 'host', new=fake_host):
            fake_port_context = base.FakePortContext(
                None, None, fake_segments)
            fake_port_context.allocate_dynamic_segment = mock.Mock(return_value='somesegment')
            fake_port_context.continue_binding = mock.Mock()
            self.mech_driver.bind_port(fake_port_context)
        return fake_port_context

    def test_bind_port_dynamic_segment(self):
        fake_segments = [{'network_type': 'vxlan',
                          'physical_network': 'fake-physnet',
                          'segmentation_id': 23,
                          'id': 'test-id'},]
        context = self._test_bind_port(fake_segments)
        context.continue_binding.assert_called_once_with(
            fake_segments[0]['id'], ['somesegment'])

    def test_delete_port(self):
        fake_segments = [{'network_type': 'vxlan',
                          'physical_network': 'fake-physnet',
                          'segmentation_id': 23,
                          'id': 'test-id'},]

        fake_port_context = mock.MagicMock()
        fake_port_context.bottom_bound_segment = fake_segments[0]
        fake_port_context.network.current = {'id': 'network-test-id'}
        fake_port_context.host = 'host'
        fake_port_context._plugin.get_ports_count.side_effect = [1, 0]

        # Ports still existing, segment shouldn't be release
        self.mech_driver.delete_port_postcommit(fake_port_context)
        fake_port_context.release_dynamic_segment.assert_not_called()

        # Now segment should be released as well
        self.mech_driver.delete_port_postcommit(fake_port_context)
        fake_port_context.release_dynamic_segment.assert_called_once_with(fake_segments[0]['id'])
