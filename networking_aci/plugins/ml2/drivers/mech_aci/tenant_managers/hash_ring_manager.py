import uhashring
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class HashRingTenantManager(object):
    def __init__(self):
        self.ring_size = cfg.CONF.ml2_aci.tenant_ring_size
        self.tenant_prefix = cfg.CONF.ml2_aci.tenant_prefix

        items = cfg.CONF.ml2_aci.tenant_items_managed.split(":")
        if len(items) != 2:
            LOG.error("Managed items is incorrectly configured, should be in format n:m, "
                      "where n is the starting tenant key and m is the last tenant key managed")
            assert()

        start = int(items[0])
        stop = int(items[1])

        if start < 1 or stop > self.ring_size:
            LOG.error("Managed items is incorrectly configured, should be in format n:m, "
                      "where n is the starting tenant key and m is the last tenant key managed")
            assert()

        self._managed_range = list(range(start, stop + 1))
        self.ring = uhashring.HashRing(list(range(self.ring_size)), hash_fn='ketama', replicas=3)

    @property
    def managed_range(self):
        return self._managed_range

    def get_tenant_name(self, key):
        return self._tenant_name(self.ring.get_node(str(key)))

    def managed(self, key):
        return self.ring.get_node(str(key)) in self.managed_range

    def all_tenant_names(self):
        tenants = []

        for i in range(0, self.ring_size):
            tenants.append(self._tenant_name(i))

        return tenants

    def _tenant_name(self, suffix):
        return "{}-{}".format(self.tenant_prefix, suffix)
