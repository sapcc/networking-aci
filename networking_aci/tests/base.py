from neutron.common import config
from neutron.tests.unit.plugins.ml2 import test_plugin
from oslo_config import cfg
from oslotest import base

from networking_aci.plugins.ml2.drivers.mech_aci import constants


class NetworkingAciMechanismDriverTestBase(test_plugin.Ml2PluginV2TestCase, base.BaseTestCase):
    """Test case base class for all unit tests."""

    def get_additional_service_plugins(self):
        return dict(service_plugins='tag')

    def setUp(self):
        self._mechanism_drivers.append(constants.ACI_DRIVER_NAME)
        cfg.CONF.set_override('debug', True)
        config.setup_logging()
        super().setUp()
