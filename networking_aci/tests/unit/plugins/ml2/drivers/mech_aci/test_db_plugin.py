from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron_lib import context
from neutron_lib.db import api as db_api
from oslotest import base

from networking_aci.db.models import HostgroupModeModel
from networking_aci.plugins.ml2.drivers.mech_aci.common import DBPlugin


class NetworkingDBPluginTests(test_plugin.Ml2PluginV2TestCase, base.BaseTestCase):

    def _create_hostgroup_mode(self, hostgroup, mode):
        ctx = context.get_admin_context()
        with db_api.CONTEXT_WRITER.using(ctx):
            self._hg_mode = HostgroupModeModel(hostgroup=hostgroup, mode=mode)
            ctx.session.add(self._hg_mode)

    def test_set_hostgroup_mode(self):
        new_hg_mode = 'something-different'

        self._create_hostgroup_mode(hostgroup="hg-1", mode="infra")
        plugin = DBPlugin()
        ctx = context.get_admin_context()
        plugin.set_hostgroup_mode(ctx, "hg-1", new_hg_mode)

        hg_mode = plugin.get_hostgroup_mode(ctx, "hg-1")
        self.assertEqual(new_hg_mode, hg_mode, f"Hostgroup Mode should match {new_hg_mode} but got {hg_mode}")
