import re

from neutron.db.models import address_scope as ascope_models
from neutron.db.models import tag as tag_models
from neutron.db import models_v2
from neutron_lib.api.definitions import external_net as extnet_api
from neutron_lib import context
from neutron.tests.common import helpers as neutron_test_helpers
from neutron.tests.unit.plugins.ml2 import test_plugin
from oslo_config import cfg

from networking_aci.tests import base


class NetworkingAciMechanismDriverSubnetPoolTest(base.NetworkingAciMechanismDriverTestBase):

    def _register_azs(self):
        self.agent1 = neutron_test_helpers.register_dhcp_agent(host='network-agent-a-1', az='qa-de-1a')
        self.agent2 = neutron_test_helpers.register_dhcp_agent(host='network-agent-b-1', az='qa-de-1b')
        self.agent3 = neutron_test_helpers.register_dhcp_agent(host='network-agent-c-1', az='qa-de-1c')

    def setUp(self):
        super().setUp()
        self._register_azs()
        ctx = context.get_admin_context()
        with ctx.session.begin(subtransactions=True):
            self._address_scope = ascope_models.AddressScope(name="the-open-sea", ip_version=4)
            ctx.session.add(self._address_scope)

    def test_create_subnet_az_hint_matches(self):
        net_kwargs = {'arg_list': (extnet_api.EXTERNAL,), extnet_api.EXTERNAL: True}
        with self.network(**net_kwargs) as network:
            with self.subnetpool(["1.1.0.0/16", "1.2.0.0/24"], name="foo", tenant_id="foo", admin=True) as snp:
                with self.subnet(network=network, cidr="1.1.1.0/24", gateway_ip="1.1.1.1",
                                 subnetpool_id=snp['subnetpool']['id']) as subnet:
                    self.assertIsNotNone(subnet)

    def test_create_subnet_network_az_snp_no_az_fails(self):
        net_kwargs = {'arg_list': (extnet_api.EXTERNAL,), extnet_api.EXTERNAL: True}
        with self.network(availability_zone_hints=["qa-de-1a"], **net_kwargs) as network:
            with self.subnetpool(["1.1.0.0/16", "1.2.0.0/24"], address_scope_id=self._address_scope['id'], name="foo",
                                 tenant_id="foo", admin=True) as snp:
                resp = self._create_subnet(self.fmt, cidr="1.1.1.0/24", gateway_ip="1.1.1.1",
                                           name="foo",
                                           net_id=network['network']['id'], tenant_id=network['network']['tenant_id'],
                                           subnetpool_id=snp['subnetpool']['id'])
                self.assertEqual(400, resp.status_code)
                self.assertEqual("SubnetSubnetPoolAZAffinityError", resp.json['NeutronError']['type'])
                self.assertIsNotNone(re.search(f"network {network['network']['id']} has AZ hint qa-de-1a,.*"
                                               f"{snp['subnetpool']['id']} has AZ None set, which do not match",
                                               resp.json['NeutronError']['message']))

    def test_create_subnet_network_no_az_snp_az_fails(self):
        net_kwargs = {'arg_list': (extnet_api.EXTERNAL,), extnet_api.EXTERNAL: True}
        with self.network(**net_kwargs) as network:
            with self.subnetpool(["1.1.0.0/16", "1.2.0.0/24"], address_scope_id=self._address_scope['id'], name="foo",
                                 tenant_id="foo", admin=True) as snp:
                ctx = context.get_admin_context()
                with ctx.session.begin():
                    snp_db = ctx.session.query(models_v2.SubnetPool).get(snp['subnetpool']['id'])
                    ctx.session.add(tag_models.Tag(standard_attr_id=snp_db.standard_attr_id,
                                    tag="availability-zone::qa-de-1a"))
                resp = self._create_subnet(self.fmt, cidr="1.1.1.0/24", gateway_ip="1.1.1.1",
                                           name="foo",
                                           net_id=network['network']['id'], tenant_id=network['network']['tenant_id'],
                                           subnetpool_id=snp['subnetpool']['id'])
                self.assertEqual(400, resp.status_code)
                self.assertEqual("SubnetSubnetPoolAZAffinityError", resp.json['NeutronError']['type'])
                self.assertIsNotNone(re.search(f"network {network['network']['id']} has AZ hint None,.*"
                                               f"{snp['subnetpool']['id']} has AZ qa-de-1a set, which do not match",
                                               resp.json['NeutronError']['message']))

    def test_create_subnet_network_snp_az_hint_works_when_turned_off(self):
        cfg.CONF.set_override('subnet_subnetpool_az_check_enabled', False, group='ml2_aci')
        net_kwargs = {'arg_list': (extnet_api.EXTERNAL,), extnet_api.EXTERNAL: True}
        with self.network(availability_zone_hints=["qa-de-1a"], **net_kwargs) as network:
            with self.subnetpool(["1.1.0.0/16", "1.2.0.0/24"], address_scope_id=self._address_scope['id'], name="foo",
                                 tenant_id="foo", admin=True) as snp:
                with self.subnet(network=network, cidr="1.1.1.0/24", gateway_ip="1.1.1.1",
                                 subnetpool_id=snp['subnetpool']['id']) as subnet:
                    self.assertIsNotNone(subnet)
