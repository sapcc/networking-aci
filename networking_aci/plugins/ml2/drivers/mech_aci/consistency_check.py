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
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron.db import address_scope_db as address_scope
from neutron.db import db_base_plugin_v2 as db
from neutron.db import external_net_db as extnet
from neutron.plugins.ml2 import db as ml2_db
from neutron.services.tag import tag_plugin
from oslo_log import log as logging
from stevedore import driver
from sqlalchemy.orm.exc import NoResultFound

from networking_aci.plugins.ml2.drivers.mech_aci import cobra_manager
from networking_aci.plugins.ml2.drivers.mech_aci import config as aci_config


LOG = logging.getLogger(__name__)
ACI_CONFIG = aci_config.ACI_CONFIG

MODE_CHECK = 'check'
MODE_SYNC = 'sync'


class DbPlugin(db.NeutronDbPluginV2,
               extnet.External_net_db_mixin,
               address_scope.AddressScopeDbMixin):
    pass


class ConsistencyCheck(object):
    def __init__(self, conf, network_id, mode):
        self.network_id = network_id
        self.mode = mode

        # Set up is similar to agent - need to review if compatible and how to refactor
        self.conf = conf
        self.aci_config = self.conf.ml2_aci
        self.conf.log_opt_values(LOG, logging.DEBUG)

        self.network_config = {
            'hostgroup_dict': ACI_CONFIG.hostgroups,
            'address_scope_dict': ACI_CONFIG.address_scopes,
        }

        self.host_group_config = self.network_config['hostgroup_dict']
        self.tenant_manager = driver.DriverManager(namespace='aci.tenant.managers',
                                                   name=self.aci_config.tenant_manager,
                                                   invoke_on_load=True).driver

        self.db = DbPlugin()  # db.NeutronDbPluginV2()
        self.tag_plugin = tag_plugin.TagPlugin()
        self.aci_manager = cobra_manager.CobraManager(self.tenant_manager)

        self.context = context.get_admin_context()

        self.network = None
        self.external = False
        self.orphan = False
        self.tenant_mismatch = False
        self.tagged_tenant = None
        self.tenant = None
        self.missing_tenant = True
        self.bd = None
        self.epg = None
        self.bd_config = {}
        self.epg_config = {}
        self.bindings = []

    def run(self):
        LOG.info("Starting ACI tool mode is %s , network id %s", self.mode, self.network_id)
        LOG.info("Network config is %s", self.network_config)

        try:
            self.network = self.db.get_network(self.context, self.network_id)
        except n_exc.NetworkNotFound:
            pass
        except NoResultFound:
            pass

        if self.network is None:
            LOG.info("Network %s does not exist in the neutron DB", self.network_id)
            self.orphan = True
        else:
            self.external = self.network['router:external']

        if self.network:
            self.check_tenant()
            self.check_epg()
            self.check_bd()
            self.check_subnet()
            self.check_bindings()

            self.required_state()

        if self.mode == MODE_SYNC:
            self.sync()

        self.report()

        # LOG.info(self.network)
        #
        # self.subnets = session.query(models.Subnet).filter_by(network_id=self.network_id)
        #
        # for subnet in self.subnets:
        #     LOG.info(subnet)
        #
        # self.ports = session.query(models.Port).filter_by(network_id=self.network_id)
        #
        # for port in self.ports:
        #     LOG.info(port)

    def check_tenant(self):
        tenant_name = self.aci_manager.get_tenant_name(self.network_id)
        LOG.info("Checking for ACI tenant %s", tenant_name)
        tags = self.tag_plugin.get_tags(self.context, 'networks', self.network_id)
        for tag in tags['tags']:

            if tag.startswith("monsoon3::aci::tenant::"):
                self.tagged_tenant = tag[len("monsoon3::aci::tenant::"):]

        if(self.tagged_tenant != tenant_name):
            self.tenant_mismatch = True

        self.tenant = self.aci_manager.get_tenant(self.network_id)
        if self.tenant is not None:
            self.missing_tenant = False

    def check_epg(self):
        self.epg = self.aci_manager.get_epg(self.network_id)
        if self.epg:
            for rsbd in self.epg.rsbd:
                self.epg_config['rsbd'] = {"tnFvBDName": rsbd.tnFvBDName}

            self.epg_config['rdDomAtt'] = []
            for rsdom in self.epg.rsdomAtt:
                self.epg_config['rdDomAtt'].append(rsdom.tDn[4:])

            subnets = self.db.get_subnets_by_network(self.context, self.network_id)
            if len(subnets) > 0:
                self.epg_config['rsProv'] = []
                for rsprov in self.epg.rsprov:
                    self.epg_config['rsProv'].append(rsprov.tnVzBrCPName)

                self.epg_config['rsCons'] = []
                for rscons in self.epg.rscons:
                    self.epg_config['rsCons'].append(rscons.tnVzBrCPName)

    def check_bd(self):
        tenant_name = self.aci_manager.get_tenant_name(self.network_id)
        self.bd = self.aci_manager.apic.get_bd(tenant_name, self.network_id,
                                               subtreeClassFilter=("fvSubnet", "fvRsCtx", "fvRsBDToOut",
                                                                   "fvRsBDSubnetToOut"))

        # Check required attributes
        if self.bd:
            self.bd_config['arpFlood'] = self.bd.arpFlood
            self.bd_config['unkMacUcastAct'] = self.bd.arpFlood

            subnets = self.db.get_subnets_by_network(self.context, self.network_id)
            if len(subnets) > 0:
                self.bd_config['rsCtx'] = []
                for ctx in self.bd.rsctx:
                    self.bd_config['rsCtx'].append(ctx.tnFvCtxName)

                self.bd_config['subnet'] = []
                for subnet in self.bd.subnet:
                    data = {"ip": subnet.ip, "scope": subnet.scope, "ctrl": subnet.ctrl, "l3_out": []}

                    for out in subnet.rsBDSubnetToOut:
                        data['l3_out'].append(out.tnL3extOutName)
                    self.bd_config['subnet'].append(data)

                if self.external:
                    self.bd_config['l3_out'] = []
                    for out in self.bd.rsBDToOut:
                        self.bd_config['l3_out'].append(out.tnL3extOutName)

    def check_subnet(self):
        pass

    def check_bindings(self):
        if self.epg:
            for path in self.epg.rspathAtt:
                self.bindings.append({"port": path.tDn, "encap": path.encap})

    def sync(self):
        self.aci_manager.ensure_domain_and_epg(self.network_id, external=self.external)

        subnets = self.db.get_subnets_by_network(self.context, self.network_id)

        for subnet in subnets:
            self.aci_manager.create_subnet(subnet, self.external, self._get_address_scope(subnet))

    def required_state(self):
        try:
            self.db.get_network(self.context, self.network_id)
        except NoResultFound:
            # Nothing in Neutron, so we expect nothing in ACI
            return None

        subnets = self.db.get_subnets_by_network(self.context, self.network_id)
        LOG.info(subnets)
        address_scopes = []

        for subnet in subnets:
            scope = self._get_address_scope(subnet)
            if scope:
                address_scopes.append(scope)

        binding_hosts = []
        ports = self.db.get_ports(self.context, {"network_id": [self.network_id]})
        for port in ports:
            # for some reason the port binding mixin is not populating the host.
            # its ineffecient but we use the ml2 db to get for each port.
            binding_host = ml2_db.get_port_binding_host(self.context, port['id'])

            if binding_host and (binding_host not in binding_hosts):
                binding_hosts.append(binding_host)

        LOG.info(binding_hosts)
        LOG.info(address_scopes)

    def report(self):
        LOG.info({
            "network": self.network,
            "external": self.external,
            "orphan": self.orphan,
            "tenant_mismatch": self.tenant_mismatch,
            "tagged_tenant": self.tagged_tenant,
            "tenant": self.tenant,
            "missing_tenant": self.missing_tenant,
            "bd": self.bd,
            "bd_config": self.bd_config,
            "epg": self.epg,
            "epg_config": self.epg_config,
            "epg_bindings": self.bindings,

        })

    def _get_address_scope(self, subnet):
        try:
            pool = self.db.get_subnetpool(self.context, subnet['subnetpool_id'])
            scope = self.db.get_address_scope(self.context, pool['address_scope_id'])
            if scope:
                return scope['name']
        except n_exc.SubnetPoolNotFound:
            pass
        except n_exc.address_scope.AddressScopeNotFound:
            pass
