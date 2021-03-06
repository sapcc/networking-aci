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
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def setup_aci_config(cfg):
    cfg.CONF.set_override('apic_hosts', ['test_apic.com'], "ml2_aci")
    cfg.CONF.set_override('apic_username', 'test_user', "ml2_aci")
    cfg.CONF.set_override('apic_password', 'test_password', "ml2_aci")
