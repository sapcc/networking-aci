# Copyright 2026 SAP SE
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
from unittest import mock

from neutron_lib import context

from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory
from neutron_lib.plugins.utils import is_valid_vlan_tag
from neutron.plugins.ml2 import models as ml2_models
from neutron.services.trunk import plugin as trunk_plugin
from oslo_config import cfg

from networking_aci.db.models import HostgroupModeModel
from networking_aci.plugins.ml2.drivers.mech_aci import config as aci_config
from networking_aci.plugins.ml2.drivers.mech_aci.config import ACI_CONFIG
from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const
from networking_aci.tests import base


class TestTrunkPlugin(base.NetworkingAciMechanismDriverTestBase):
    _mechanism_drivers = ['logger']

    def setUp(self):
        for group in list(cfg.CONF._groups):
            if group.startswith('aci-hostgroup:'):
                cfg.CONF.unregister_opts(aci_config.hostgroup_opts, group)
        ACI_CONFIG.reset_config()
        super().setUp()

        # SQLite transaction isolation issue: _extend_port_trunk_details calls
        # get_admin_context() inside an active transaction, creating a new session
        # that can't see uncommitted data and breaks the outer transaction.
        # See networking-ccloud/tests/unit/services/trunk/test_driver.py for details.
        re_patcher = mock.patch('neutron.services.trunk.plugin.TrunkPlugin._extend_port_trunk_details')
        self.addCleanup(re_patcher.stop)
        re_patcher.start()

        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        self.trunk_plugin.add_segmentation_type('vlan', is_valid_vlan_tag)
        directory.add_plugin('trunk', self.trunk_plugin)

        self._add_hostgroup('seagull', 'nova-compute-seagull',
                            bindings=[f"vpc/pod-1/1233-1234/bb123_node00{i}-seagull_LAG0" for i in range(1, 5)])

        cfg_patcher = mock.patch.object(cfg.CONF, 'list_all_sections',
                                        side_effect=lambda: list(cfg.CONF._groups))
        self.addCleanup(cfg_patcher.stop)
        cfg_patcher.start()

    def _add_hostgroup(self, hg_name, hosts, bindings=None, direct_mode=False, segment_type='vlan', hg_mode='infra',
                       **kwargs):
        if isinstance(hosts, str):
            hosts = [hosts]

        group = f"aci-hostgroup:{hg_name}"
        if not bindings:
            bindings = ["vpc/pod-1/1233-1234/bb123_LAG0"]

        cfg.CONF.register_opts(aci_config.hostgroup_opts, group)
        cfg.CONF.set_override('hosts', hosts, group=group)
        cfg.CONF.set_override('bindings', bindings, group=group)
        cfg.CONF.set_override('direct_mode', direct_mode, group=group)
        cfg.CONF.set_override('segment_type', segment_type, group=group)
        for key, value in kwargs.items():
            cfg.CONF.set_override(key, value, group=group)

        ctx = context.get_admin_context()
        with db_api.CONTEXT_WRITER.using(ctx):
            hg_mode = HostgroupModeModel(hostgroup=hg_name, mode=hg_mode)
            ctx.session.add(hg_mode)

    def _update_vif_type(self, ctx, port_or_port_id, host=None):
        if isinstance(port_or_port_id, dict):
            port_id = port_or_port_id['port']['id']
        else:
            port_id = port_or_port_id

        with ctx.session.begin():
            binding = (ctx.session.query(ml2_models.PortBinding)
                       .filter(ml2_models.PortBinding.port_id == port_id).first())
            binding.vif_type = 'aci'
            if host:
                binding.host = host
            ctx.session.add(binding)

    def test_create_trunk_baremetal(self):
        self._add_hostgroup('node001-seagull', 'node001-seagull', direct_mode=True, hg_mode='baremetal')
        with self.port(device_id='aaa-bbb-ccc') as trunk_port, self.port() as subport:
            ctx = context.get_admin_context()
            self._update_vif_type(ctx, trunk_port, host='node001-seagull')
            sp_dict = {'segmentation_type': 'vlan', 'segmentation_id': 1001, 'port_id': subport['port']['id']}
            trunk = {'port_id': trunk_port['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': [sp_dict]}
            resp = self.trunk_plugin.create_trunk(ctx, {'trunk': trunk})
            self.assertEqual('ACTIVE', resp['status'])

            subport_db = self.plugin.get_port(ctx, subport['port']['id'])
            self.assertEqual('node001-seagull', subport_db['binding:host_id'])
            self.assertEqual('trunk:subport', subport_db['device_owner'])
            self.assertEqual(trunk_port['port']['binding:vnic_type'], subport_db['binding:vnic_type'])
            self.assertEqual('aaa-bbb-ccc', subport_db['device_id'])
            self.assertEqual({'segmentation_type': 'vlan', 'segmentation_id': 1001},
                             subport_db['binding:profile'][aci_const.TRUNK_PROFILE])

    def test_create_trunk_baremetal_v2(self):
        self._add_hostgroup('node001-seagull', 'node001-seagull', direct_mode=True, hg_mode='baremetal_v2',
                            parent_hostgroup="seagull")
        with self.port(device_id='aaa-bbb-ccc') as trunk_port, self.port() as subport:
            ctx = context.get_admin_context()
            self._update_vif_type(ctx, trunk_port, host='node001-seagull')
            sp_dict = {'segmentation_type': 'vlan', 'segmentation_id': 23, 'port_id': subport['port']['id']}
            trunk = {'port_id': trunk_port['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': [sp_dict]}
            resp = self.trunk_plugin.create_trunk(ctx, {'trunk': trunk})
            self.assertEqual('ACTIVE', resp['status'])

            subport_db = self.plugin.get_port(ctx, subport['port']['id'])
            self.assertEqual('node001-seagull', subport_db['binding:host_id'])
            self.assertEqual('trunk:subport', subport_db['device_owner'])
            self.assertEqual(trunk_port['port']['binding:vnic_type'], subport_db['binding:vnic_type'])
            self.assertEqual('aaa-bbb-ccc', subport_db['device_id'])
            self.assertEqual({'segmentation_type': 'vlan', 'segmentation_id': -1},
                             subport_db['binding:profile'][aci_const.TRUNK_PROFILE])

    def test_create_trunk_baremetal_v2_add_subport(self):
        self._add_hostgroup('node001-seagull', 'node001-seagull', direct_mode=True, hg_mode='baremetal_v2',
                            parent_hostgroup="seagull")
        with self.port(device_id='aaa-bbb-ccc') as trunk_port, self.port() as subport_1, self.port() as subport_2:
            ctx = context.get_admin_context()
            self._update_vif_type(ctx, trunk_port, host='node001-seagull')
            sp1_dict = {'segmentation_type': 'vlan', 'segmentation_id': 23, 'port_id': subport_1['port']['id']}
            trunk = {'port_id': trunk_port['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': [sp1_dict]}
            resp = self.trunk_plugin.create_trunk(ctx, {'trunk': trunk})
            trunk_id = resp['id']
            self.assertEqual({-1}, {sp['segmentation_id'] for sp in resp['sub_ports']})

            # add extra subport
            sp2_dict = {'segmentation_type': 'vlan', 'segmentation_id': 1, 'port_id': subport_2['port']['id']}
            ctx = context.get_admin_context()
            resp = self.trunk_plugin.add_subports(ctx, trunk_id, {'sub_ports': [sp2_dict]})
            self.assertEqual({-1, -2}, {sp['segmentation_id'] for sp in resp['sub_ports']})

    def test_create_trunk_baremetal_v2_multiple_ports_on_create(self):
        self._add_hostgroup('node001-seagull', 'node001-seagull', direct_mode=True, hg_mode='baremetal_v2',
                            parent_hostgroup="seagull")
        with self.port(device_id='aaa-bbb-ccc') as trunk_port, self.port() as subport_1, \
                self.port() as subport_2, self.port() as subport_3:
            ctx = context.get_admin_context()
            self._update_vif_type(ctx, trunk_port, host='node001-seagull')
            sp1_dict = {'segmentation_type': 'vlan', 'segmentation_id': 1, 'port_id': subport_1['port']['id']}
            sp2_dict = {'segmentation_type': 'vlan', 'segmentation_id': 1, 'port_id': subport_2['port']['id']}
            trunk = {'port_id': trunk_port['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': [sp1_dict, sp2_dict]}
            resp = self.trunk_plugin.create_trunk(ctx, {'trunk': trunk})
            trunk_id = resp['id']
            self.assertEqual('ACTIVE', resp['status'])

            subport_db = self.plugin.get_port(ctx, subport_1['port']['id'])
            self.assertEqual('node001-seagull', subport_db['binding:host_id'])
            self.assertEqual('trunk:subport', subport_db['device_owner'])
            self.assertEqual(trunk_port['port']['binding:vnic_type'], subport_db['binding:vnic_type'])
            self.assertEqual('aaa-bbb-ccc', subport_db['device_id'])
            self.assertEqual({'segmentation_type': 'vlan', 'segmentation_id': -1},
                             subport_db['binding:profile'][aci_const.TRUNK_PROFILE])
            self.assertEqual({-1, -2}, {sp['segmentation_id'] for sp in resp['sub_ports']})

            # add extra subport
            sp3_dict = {'segmentation_type': 'vlan', 'segmentation_id': 1, 'port_id': subport_3['port']['id']}
            ctx = context.get_admin_context()
            resp = self.trunk_plugin.add_subports(ctx, trunk_id, {'sub_ports': [sp3_dict]})
            self.assertEqual({-1, -2, -3}, {sp['segmentation_id'] for sp in resp['sub_ports']})
