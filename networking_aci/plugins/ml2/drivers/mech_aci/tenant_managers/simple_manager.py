from oslo_config import cfg

class SimpleTenantManager(object):

    def __init__(self):

        self.tenant_prefix =cfg.CONF.ml2_aci.tenant_prefix

    def get_tenant_name(self,key):
        return self.tenant_prefix

    def get_all_tenant_names(self):
        return [self.tenant_prefix]

    def managed(self, key):
        return True



