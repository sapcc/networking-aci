# Copyright 2016 SAP SE
# All Rights Reserved.
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
import argparse
import sys

from neutron.common import config as common_config
from neutron.conf.agent import common as config
from oslo_config import cfg
from oslo_log import log as logging

from networking_aci.plugins.ml2.drivers.mech_aci import config as aci_config
from networking_aci.plugins.ml2.drivers.mech_aci import consistency_check

LOG = logging.getLogger(__name__)


def register_options():
    config.register_agent_state_opts_helper(cfg.CONF)


def main():
    print((sys.argv))
    print((sys.argv[1:]))
    print((sys.argv))

    args = parse_args()
    register_options()
    conf = aci_config.CONF

    common_config.init(config_files(args.config_file))
    common_config.setup_logging()

    tool = AciTool(args, conf)
    tool.run()


def parse_args():
    parser = argparse.ArgumentParser(
        description='Utility to check and sync network state in ACI',
    )
    parser.add_argument(
        '--config-file', help="Path to f5-openstack-agent.ini",
        action='append',
        default=['/etc/neutron/neutron.conf', '/etc/neutron/plugins/ml2/ml2_conf.ini',
                 '/etc/neutron/plugins/ml2/ml2-conf-aci.ini'],
        required=False
    )

    parser.add_argument(
        '--network-id', help="Neutron network ID to sync",
        required=True
    )

    parser.add_argument(
        '--mode', help="Mode to use check or sync. 'check' evaluates inconsistences, "
                       "sync with sync neutron state to ACI",
        default=consistency_check.MODE_CHECK,
        required=False
    )
    return parser.parse_args()


def config_files(args):
    config_files = []
    for arg in args:
        config_files.append("--config-file")
        config_files.append(arg)
    return config_files


class AciTool(object):
    def __init__(self, args, conf):
        self.args = args
        self.conf = conf

    def run(self):
        cc = consistency_check.ConsistencyCheck(self.conf, self.args.network_id, self.args.mode)
        cc.run()
