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
import sys

from networking_aci._i18n import _LI
from networking_aci.plugins.ml2.drivers.mech_aci.agent import aci_agent
from neutron.common import config as common_config
from neutron.conf.agent import common as config
from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


def register_options():
    config.register_agent_state_opts_helper(cfg.CONF)


def main():
    register_options()
    common_config.init(sys.argv[1:])
    config.setup_logging()
    agent = aci_agent.AciNeutronAgent()

    # Start everything.
    LOG.info(_LI("ACI Agent initialized successfully, now running... "))
    agent.daemon_loop()
