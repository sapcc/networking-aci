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
from neutron.tests.unit import fake_resources as fakes
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

    def test_bind_port_unsupported_vnic_type(self):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'binding:vnic_type': 'unknown'}).info()
        fake_port_context = fakes.FakePortContext(fake_port, 'host', [])
        self.mech_driver.bind_port(fake_port_context)
        fake_port_context.set_binding.assert_not_called()

    def _test_bind_port_failed(self, fake_segments, fake_host = 'host'):
        fake_port = fakes.FakePort.create_one_port().info()
        fake_port_context = fakes.FakePortContext(
            fake_port, fake_host, fake_segments)
        self.mech_driver.bind_port(fake_port_context)
        fake_port_context.set_binding.assert_not_called()

    def test_bind_port_host_not_found(self):
        self._test_bind_port_failed([], fake_host='unknown')

    def test_bind_port_no_segments_to_bind(self):
        self._test_bind_port_failed([])

    def test_bind_port_physnet_not_found(self):
        segment_attrs = {'network_type': 'vlan',
                         'physical_network': 'unknown-physnet',
                         'segmentation_id': 23}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port_failed(fake_segments)

    def _test_bind_port(self, fake_segments):
        fake_port = fakes.FakePort.create_one_port().info()
        fake_host = 'host'
        fake_port_context = fakes.FakePortContext(
            fake_port, fake_host, fake_segments)
        fake_port_context.allocate_dynamic_segment = mock.Mock(return_value='somesegment')
        fake_port_context.continue_binding = mock.Mock()
        self.mech_driver.bind_port(fake_port_context)
        fake_port_context.continue_binding.assert_called_once_with(
            fake_segments[0]['id'], ['somesegment'])

    def test_bind_port_dynamic_segment(self):
        segment_attrs = {'network_type': 'vxlan',
                         'physical_network': 'fake-physnet',
                         'segmentation_id': 23}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port(fake_segments)

    def _get_fake_port_context(self, existing_ports):
        fake_port = fakes.FakePort.create_one_port().info()
        segment_attrs = {'network_type': 'vlan',
                         'physical_network': 'fake-physnet',
                         'segmentation_id': 23}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        fake_port_context = fakes.FakePortContext(
            fake_port, 'host', fake_segments)
        fake_port_context.bottom_bound_segment = fake_segments[0]
        fake_port_context.network = mock.Mock()
        fake_port_context.network.current = {'id': '1234-1234-1234-1234'}
        fake_port_context._plugin_context = None
        fake_port_context._plugin = mock.Mock()
        fake_port_context._plugin.get_ports_count.return_value = existing_ports
        fake_port_context.release_dynamic_segment = mock.Mock()
        return fake_port_context

    def test_delete_port(self):
        fake_port_context = self._get_fake_port_context(1)
        self.mech_driver.delete_port_postcommit(fake_port_context)
        fake_port_context.release_dynamic_segment.assert_not_called()

    def test_delete_port_and_release_segment(self):
        fake_port_context = self._get_fake_port_context(0)
        self.mech_driver.delete_port_postcommit(fake_port_context)
        fake_port_context.release_dynamic_segment.assert_called_once_with(
            fake_port_context.fake_segments_to_bind[0]['id'])
