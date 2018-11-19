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
import mock
import sys

from networking_aci.tests.unit import utils
from neutron.tests import base
from neutron_lib import exceptions as n_exc
from oslo_config import cfg

cfg.CONF.use_stderr = False
cfg.CONF(args=[])

class AciNeutronAgentTest(base.BaseTestCase):
    def setUp(self):
        super(AciNeutronAgentTest, self).setUp()
        # lets mock aci/cobra
        sys.modules['cobra'] = mock.MagicMock()
        sys.modules['cobra.mit'] = mock.MagicMock()
        sys.modules['cobra.mit.access'] = mock.MagicMock()
        sys.modules['cobra.mit.session'] = mock.MagicMock()
        sys.modules['cobra.mit.request'] = mock.MagicMock()
        sys.modules['cobra.model'] = mock.MagicMock()
        sys.modules['cobra.model.fv'] = mock.MagicMock()
        from networking_aci.plugins.ml2.drivers.mech_aci.agent.aci_agent import AciNeutronAgent

        self.aci_agent = AciNeutronAgent()

        self.aci_agent.agent_rpc = mock.MagicMock()
        self.aci_agent.aci_manager = mock.MagicMock()
        # Stop after one iteration

        self.aci_agent.agent_rpc.get_network_ids = mock.Mock(return_value=['abcd-efgh-ijkl'])
        self.aci_agent.agent_rpc.get_networks_count = mock.Mock(return_value=1)
        utils.setup_aci_config(cfg)


    def test_rpc_loop_race_condition(self):
        self.aci_agent._check_and_handle_signal = mock.Mock(side_effect=[True, False, False])
        self.aci_agent.agent_rpc.get_networks = mock.Mock(side_effect=n_exc.NetworkNotFound(net_id='non_existing_net_id'))
        self.aci_agent.sync_marker = 'non_existing_net_id'
        self.aci_agent.rpc_loop()
        self.assertIsNone(self.aci_agent.sync_marker, 'Sync marker should be none if network has been deleted meanwhile')

    def test_rpc_loop_race_condition_2(self):
        self.aci_agent._check_and_handle_signal = mock.Mock(side_effect=[True, False, False])
        self.aci_agent.agent_rpc.get_networks = mock.Mock(return_value=[])
        self.aci_agent.sync_marker = 'non_existing_net_id'
        self.aci_agent.rpc_loop()
        self.assertIsNone(self.aci_agent.sync_marker, 'Sync marker should be none if network has been deleted meanwhile')
