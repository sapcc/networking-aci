# Copyright 2024 SAP SE
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

import os
from pathlib import Path
import tempfile
from unittest import mock

from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron.tests.unit.db.test_db_base_plugin_v2 import NeutronDbPluginV2TestCase
from oslo_config import cfg

from networking_aci.db.models import AllocationsModel
from networking_aci.plugins.ml2.drivers.mech_aci.allocations_manager import AllocationsManager
from networking_aci.plugins.ml2.drivers.mech_aci import common
from networking_aci.plugins.ml2.drivers.mech_aci.config import ACI_CONFIG


class TestAllocationsManager(NeutronDbPluginV2TestCase):
    def test_sync_allocations(self):
        ctx = context.get_admin_context()
        net1 = self._make_network("json", "net1", True)['network']
        net2 = self._make_network("json", "net2", True)['network']
        net3 = self._make_network("json", "net3", True)['network']

        start_data = [
            ('seagull', 42, None),  # keep
            ('seagull', 43, net1['id']),  # keep
            ('seagull', 2323, None),  # delete (out of range)
            ('seagull', 2324, net2['id']),  # keep (out of range, has network)
            ('crow', 2323, None),  # delete (unknown hg)
            ('crow', 2324, net3['id']),  # keep (unknown hg, has network)
        ]

        expected_result = [
            ('crow', 2324, net3['id']),
            ('oystercatcher', 100, None),
            ('oystercatcher', 101, None),
            ('oystercatcher', 102, None),
            ('oystercatcher', 103, None),
            ('seagull', 42, None),
            ('seagull', 43, net1['id']),
            ('seagull', 44, None),
            ('seagull', 45, None),
            ('seagull', 2324, net2['id']),

            ('sentinel_1', 1, None),
            ('sentinel_2', 2, None),
        ]

        with db_api.CONTEXT_WRITER.using(ctx) as sess:
            for host, seg_id, net_id in start_data:
                sess.add(AllocationsModel(host=host, level=1, segment_type="vlan", segmentation_id=seg_id,
                                          network_id=net_id))

            # wrong level, should not be touched
            sess.add(AllocationsModel(host="sentinel_1", level=2, segment_type="vlan", segmentation_id=1))

            # wrong segment_type, should not be touched
            sess.add(AllocationsModel(host="sentinel_2", level=1, segment_type="foo", segmentation_id=2))

        db = common.DBPlugin()
        ACI_CONFIG.db = db

        hostgroups = {
            'seagull': {
                'direct_mode': False,
                'hosts': [],
                'segment_range': [(42, 45)],
                'segment_type': 'vlan',
            },
            'oystercatcher': {
                'direct_mode': False,
                'hosts': [],
                'segment_range': [(100, 103)],
                'segment_type': 'vlan',
            },
            'sparrow': {
                'direct_mode': True,
                'hosts': [],
                'segment_range': [(123, 234)],
                'segment_type': 'vlan',
            },
        }

        with mock.patch('networking_aci.plugins.ml2.drivers.mech_aci.config.ACIConfig.hostgroups',
                        new_callable=mock.PropertyMock, return_value=hostgroups):
            AllocationsManager(db)

        with db_api.CONTEXT_READER.using(ctx) as sess:
            db_result = [(a.host, a.segmentation_id, a.network_id) for a in sess.query(AllocationsModel).all()]

        self.assertEqual(sorted(expected_result), sorted(db_result))

    def test_sync_allocations_locking(self):
        db = common.DBPlugin()

        with mock.patch.object(AllocationsManager, '_sync_db') as sync_db_mock:
            AllocationsManager(db)
            sync_db_mock.assert_called_once()
            sync_db_mock.reset_mock()

            # repeated calls get repeated syncs
            AllocationsManager(db)
            sync_db_mock.assert_called_once()
            sync_db_mock.reset_mock()

            with tempfile.TemporaryDirectory() as tmpdir:
                sync_file = Path(tmpdir) / 'sync-done-file'
                cfg.CONF.set_override('sync_allocations_done_file_path', str(sync_file), group='ml2_aci')

                # sync, this time the file gets created
                AllocationsManager(db)
                sync_db_mock.assert_called_once()
                sync_db_mock.reset_mock()

                # sync not executed
                AllocationsManager(db)
                sync_db_mock.assert_not_called()

                self.assertEqual(open(sync_file).read(), str(os.getpid()))
