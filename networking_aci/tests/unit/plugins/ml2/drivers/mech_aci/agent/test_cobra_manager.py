# Copyright 2026 SAP SE
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
import sys
import threading
import time

import mock
from neutron.tests import base
from oslo_config import cfg

from networking_aci.tests.unit import utils


for mod in ['cobra', 'cobra.mit', 'cobra.mit.access', 'cobra.mit.session',
            'cobra.mit.request', 'cobra.model', 'cobra.model.fv',
            'cobra.model.fvns', 'cobra.model.infra', 'cobra.model.ip',
            'cobra.model.phys', 'cobra.model.rtctrl',
            'cobra.modelimpl.l3ext.out']:
    sys.modules.setdefault(mod, mock.MagicMock())

# import after cobra mocks
from networking_aci.plugins.ml2.drivers.mech_aci.agent.entry_point import register_options
from networking_aci.plugins.ml2.drivers.mech_aci.agent.cobra_manager import CobraManager


class TestCobraManager(base.BaseTestCase):
    def setUp(self):
        super().setUp()

        register_options()
        utils.setup_aci_config(cfg)

        with mock.patch('networking_aci.plugins.ml2.drivers.mech_aci.agent.cobra_client.CobraClient') as mock_client:
            self.mgr = CobraManager(agent_plugin=mock.MagicMock(), tenant_manager=mock.MagicMock())
        self.mgr.apic = mock_client.return_value

        self.host_config = {
            'name': 'herring-gull-hg',
            'hostgroup_mode': 'baremetal',
            'port_selectors': ['uni/infra/accportprof-hg1/hports-sel1-typ-range'],
            'pc_policy_group': 'bm-9001g',
            'baremetal_resource_name': 'hg1-bm',
            'baremetal_pc_policy_group': 'hg1-bm-bundle',
        }

    def test_setting_hostgroup_mode_calls_are_sequential(self):
        # testplan:
        #   get first thread into apic commit
        #   start second thread
        #   ...wait fixed amount of time
        #   release first thread from apic commit
        #   check if second thread actually waited for first thread
        first_commit = threading.Event()
        first_commit_cond = threading.Condition()
        commit_count = 0
        first_commit_time = None
        second_commit_time = None

        def apic_commit_mock(entities):
            nonlocal commit_count, first_commit_time, second_commit_time

            if commit_count == 0:
                commit_count += 1
                first_commit.set()
                with first_commit_cond:
                    first_commit_cond.wait()
                first_commit_time = time.monotonic()
            elif commit_count == 1:
                commit_count += 1
                second_commit_time = time.monotonic()
            else:
                raise Exception("Too many commits")

        self.mgr.apic.commit.side_effect = apic_commit_mock
        self.mgr.ensure_baremetal_entities = mock.MagicMock(return_value=True)
        self.mgr._gen_port_selector_entities = mock.MagicMock(return_value=['entity1'])

        def run():
            self.mgr.ensure_hostgroup_mode_config(self.host_config, source="the-beach")

        # start first thread, wait for it to be in apic.commit()
        t1 = threading.Thread(target=run, daemon=True)
        t1.start()
        first_commit.wait()

        # start second thread, give it a short time to run into the lock
        t2 = threading.Thread(target=run, daemon=True)
        t2.start()
        time.sleep(0.1)

        # release the first thread
        with first_commit_cond:
            first_commit_cond.notify()

        t1.join(timeout=5)
        t2.join(timeout=5)

        self.assertEqual(2, self.mgr.apic.commit.call_count)
        self.assertLess(first_commit_time, second_commit_time)
