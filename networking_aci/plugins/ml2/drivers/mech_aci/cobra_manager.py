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

import ast
import netaddr
from oslo_log import log

from networking_aci.plugins.ml2.drivers.mech_aci import cobra_client

from cobra.model import fv
from cobra.model import phys
from cobra import modelimpl

from neutron_lib import context


LOG = log.getLogger(__name__)

ENCAP_VLAN = 'vlan-%s'
PORT_DN_PATH = 'topology/%s/paths-%s/pathep-[eth%s/%s]'
VPCPORT_DN_PATH = 'topology/%s/protpaths-%s/pathep-[%s]'
DPCPORT_DN_PATH = 'topology/%s/paths-%s/pathep-[%s]'
NODE_DN_PATH = 'topology/%s/paths-%s/pathep-[Switch%s_%s-ports-%s_PolGrp]'


class CobraManager(object):
    def __init__(self, agent_plugin,network_config, aci_config, tenant_manager):
        # Connect to the APIC

        self.agent_plugin = agent_plugin
        self.aci_config = aci_config
        self.apic_application_profile = aci_config.apic_application_profile
        self.tenant_default_vrf = aci_config.tenant_default_vrf
        self.network_config = network_config

        self.host_dict = network_config.get('host_dict', {})
        self.address_scope_dict = network_config.get('address_scope_dict', {})

        self.apic = cobra_client.CobraClient(
                self.aci_config.apic_hosts,
                self.aci_config.apic_username,
                self.aci_config.apic_password,
                self.aci_config.apic_use_ssl,
        )



        self.context = context.get_admin_context()

        self.tenant_manager = tenant_manager

    @property
    def api(self):
        return self.apic

    def get_pdn(self,binding):
        binding_config = binding.split("/")
        pdn = None
        if binding_config[0] == 'port':
            pdn = PORT_DN_PATH % (binding_config[1], binding_config[2], binding_config[3],binding_config[4])
        elif binding_config[0] == 'node':
            pdn = NODE_DN_PATH % (binding_config[1], binding_config[2], binding_config[2], binding_config[3],binding_config[4])
        elif binding_config[0] == 'dpc':
            pdn = DPCPORT_DN_PATH % (binding_config[1], binding_config[2],binding_config[3])
        elif binding_config[0] == 'vpc':
            pdn = VPCPORT_DN_PATH % (binding_config[1], binding_config[2],binding_config[3])

        return pdn

    def get_static_binding_encap(self, segment_type, encap):
        if segment_type == 'vlan':
            encap = ENCAP_VLAN % str(encap)

        return encap

    def ensure_domain_and_epg(self, network_id, external = False):
        tenant = self.get_or_create_tenant(network_id)

        if external:
            unicast_route = 1
            move_detect =1
            limit_ip_learn_subnets = 1
        else:
            unicast_route = 0
            move_detect = 0
            limit_ip_learn_subnets = 0

        bd_opts = {'arpFlood':1, 'unkMacUcastAct':0,'unicastRoute':unicast_route,'epMoveDetectMode':move_detect,'limitIpLearnToSubnets':limit_ip_learn_subnets}

        if self.aci_config.support_remote_mac_clear:
            bd_opts['epClear'] = 1


        bd = fv.BD(tenant, network_id,  **bd_opts)

        app = fv.Ap(tenant, self.apic_application_profile)

        epg = fv.AEPg(app, network_id)

        # Add EPG to BD domain
        rsbd = fv.RsBd(epg, network_id, tnFvBDName=bd.name)

        # We have to make seperate config requests because cobra can't
        # handle MOs with different root contexts
        self.apic.commit(bd)

        self.apic.commit([app, epg, rsbd])

        self.agent_plugin.tag_network(network_id,"monsoon3::aci::tenant::{}".format(self.tenant_manager.get_tenant_name(network_id)))

    def delete_domain_and_epg(self, network_id, transaction=None):
        tenant = self.get_tenant(network_id)

        if tenant is None:
            LOG.warning("Cannot determine tenant {} for network {}. Aborting delete.".format(self.tenant_manager.get_tenant_name(network_id),network_id))
            return

        bd = fv.BD(tenant, network_id)
        bd.delete()

        app = fv.Ap(tenant, self.apic_application_profile)
        epg = fv.AEPg(app, network_id)
        epg.delete()

        self.apic.commit(epg)
        self.apic.commit(bd)

        if(len(self.get_tenant_bridge_domains(tenant))==0 and len(self.get_tenant_epgs(tenant))==0):
            tenant.delete()
            self.apic.commit(tenant)

    def ensure_static_bindings_configured(self, network_id, host_config, encap=None, delete=False, clear_phys_dom=False):
        tenant = self.get_tenant(network_id)

        if tenant:


            bindings = host_config['bindings']
            segment_type = host_config['segment_type']

            encap = self.get_static_binding_encap(segment_type, encap)

            app = fv.Ap(tenant, self.apic_application_profile)
            epg = fv.AEPg(app, network_id)
            ports = []

            for binding in bindings:
                pdn = self.get_pdn(binding)

                LOG.info("Preparing static binding %s encap %s for network %s", pdn , encap ,network_id )

                port = fv.RsPathAtt(epg, pdn, encap=encap)
                if delete:
                    port.delete()

                ports.append(port)

            self.apic.commit(ports)

            # Associate to Physical Domain


            self._ensure_physdom(epg,host_config['physical_domain'],(delete and clear_phys_dom))



        else:
           LOG.error("Network {} does not appear to be avilable in ACI, expected in tenant {}".format(network_id,self.tenant_manager.get_tenant_name(network_id)))

    def create_subnet(self,subnet, external, address_scope_name):
        self._configure_subnet(subnet, external=external, address_scope_name=address_scope_name,last_on_network=False, delete=False)

    def delete_subnet(self,subnet, external, address_scope_name,last_on_network):
        self._configure_subnet(subnet, external=external, address_scope_name=address_scope_name,last_on_network=last_on_network, delete=True)

    def ensure_subnet_created(self, network_id, address_scope_name, gateway):
        tenant = self.get_tenant(network_id)

        scope_config = self._get_address_scope_config(address_scope_name)

        l3_outs = scope_config['l3_outs']

        bd = fv.BD(tenant, network_id)

        subnet = fv.Subnet(bd, gateway, scope=scope_config.get('scope', 'public'), ctrl='querier')

        subnet_outs = []

        for l3_out in l3_outs.split(','):
            out = self._find_l3_out(network_id,l3_out)

            if out:

                subnet_outs.append(fv.RsBDSubnetToOut(subnet, out.name))
            else:
                LOG.error('Cannot configure L3 out for subnet, {} not found in ACI configuration'.format(l3_out))

                # We don't need the out profiles for now
                # subnet_out_profile = RsBDSubnetToProfile(subnet,l3_out,tnL3extOutName=l3_out)

                # self.apic.commit(subnet_out_profile)

        self.apic.commit([subnet] + subnet_outs)

    def ensure_subnet_deleted(self, network_id, gateway):
        tenant = self.get_tenant(network_id)
        bd = fv.BD(tenant, network_id)

        subnet = fv.Subnet(bd, gateway)
        subnet.delete()

        self.apic.commit(subnet)

    def ensure_internal_network_configured(self, network_id, delete=False):
        tenant = self.get_tenant(network_id)

        if tenant is None:
            LOG.warning("Cannot determine tenant {} for network {}. Aborting configuration.".format(
                self.tenant_manager.get_tenant_name(network_id), network_id))
            return

        bd = fv.BD(tenant, network_id)
        vrf = fv.RsCtx(bd, self.tenant_default_vrf, tnFvCtxName=self.tenant_default_vrf)

        self.apic.commit(vrf)

    def ensure_external_network_configured(self, network_id, address_scope_name, last_on_network, delete=False):
        tenant = self.get_tenant(network_id)

        scope_config = self._get_address_scope_config(address_scope_name)

        l3_outs = scope_config['l3_outs']
        vrf_name = scope_config['vrf']

        # prepare bridge domain

        bd = fv.BD(tenant, network_id)

        # We don't need the out profiles for now
        # out_profile  = RsBDToProfile(bd,tnL3extOutName=l3_out_name)
        vrf = fv.RsCtx(bd, vrf_name, tnFvCtxName=vrf_name)

        bd_outs = []

        for l3_out in l3_outs.split(','):
            out = self._find_l3_out(network_id, l3_out)
            if out:

                bd_out = fv.RsBDToOut(bd, out.name)
                if delete and last_on_network:
                    bd_out.delete()
                bd_outs.append(bd_out)
            else:
                LOG.error('Cannot configure L3 out for BD, {} not found in ACI configuration'.format(l3_out))

        #if delete:
            # vrf.delete() #TODO: the RsCtx object cannot be deleted, need to find out how to clear on the BD


        # Prepare EPG
        app = fv.Ap(tenant, self.apic_application_profile)
        epg = fv.AEPg(app, network_id)

        epg_contracts = []



        contract_def = ast.literal_eval(scope_config['contracts'])
        for type,contracts in contract_def.iteritems():
            if type =='consumed':
                for contract in contracts:
                    contract = fv.RsCons(epg, contract)
                    if delete and last_on_network:
                        contract.delete()
                    epg_contracts.append(contract)
            elif type =='provided':
                for contract in contracts:
                    contract = fv.RsProv(epg, contract)
                    if delete and last_on_network :
                        contract.delete()
                    epg_contracts.append(contract)

        self.apic.commit([vrf] + bd_outs + epg_contracts)


    def get_tenant_bridge_domains(self, tenant):
        if not tenant:
            return []
        return self.apic.mo_dir.lookupByClass('fv.BD', parentDn=tenant.dn)

    def get_all_bridge_domains(self):
        result = []

        for tenant_name in self.tenant_manager.all_tenant_names():
            bds = self.get_tenant_bridge_domains(self.apic.get_tenant(tenant_name))
            if len(bds) > 0 :
                result += bds

        return result

    def get_tenant_epgs(self, tenant):
        if not tenant:
            return []
        return self.apic.mo_dir.lookupByClass('fv.AEPg', parentDn=tenant.dn)



    def get_all_epgs(self):
        result = []

        for tenant_name in self.tenant_manager.all_tenant_names():
            epgs = self.get_tenant_epgs(self.apic.get_tenant(tenant_name))
            if len(epgs) > 0:
                result += epgs

        return result



    def get_bd(self,network_id):
        try:
            return self.apic.get_full_tenant(self.get_tenant_name(network_id)).BD[network_id]
        except:
            return None

    def get_epg(self,network_id):
        try:
            app = self.get_app(network_id)
            if app:
                return app.epg[network_id]
        except:
            return None

    def get_app(self,network_id):
        return self.apic.get_full_tenant(self.get_tenant_name(network_id)).ap[self.apic_application_profile]


    def get_or_create_tenant(self,network_id):
        return self.apic.get_or_create_tenant(self.tenant_manager.get_tenant_name(network_id))

    def get_tenant(self,network_id):
        return self.apic.get_tenant(self.get_tenant_name(network_id))

    def get_tenant_name(self,network_id):
        return self.tenant_manager.get_tenant_name(network_id)


    def clean_subnets(self, network):
        network_id = network['id']
        bd = self.get_bd(network_id)
        if bd:
            neutron_subnets = []

            for neutron_subnet in network.get('subnets',[]):
                neutron_subnets.append(self._get_gateway(neutron_subnet))

            for subnet in bd.subnet:
                if not subnet.ip in neutron_subnets:
                  LOG.warning("Cleaning subnet %s on BD %s",subnet.ip, network_id)
                  self.ensure_subnet_deleted(network_id ,subnet.ip)


    def clean_physdoms(self, network):

        network_id = network['id']
        epg = self.get_epg(network_id)
        if epg:
            physdoms = []

            fixed_bindings = network.get('fixed_bindings',[])
            for fixed_binding in fixed_bindings:
                physdoms.append(fixed_binding.get('physical_domain'))

            for binding in network.get('bindings',[]):
                host_config = binding.get('host_config',{})

                if host_config:
                    physdoms.append(host_config.get('physical_domain'))

            for rsdom in epg.rsdomAtt:
                physdom = rsdom.tDn[9:]
                if not physdom in physdoms:
                    LOG.warning("Cleaning physdom %s on EPG %s", physdom, network_id)
                    self._ensure_physdom(epg,physdom, True)



    def clean_bindings(self,network):
        network_id = network['id']
        epg = self.get_epg(network_id)

        neutron_bindings = []

        if epg:
            ports = []

            fixed_bindings = network.get('fixed_bindings')
            for fixed_binding in fixed_bindings:
                encap = self.get_static_binding_encap(fixed_binding['segment_type'], fixed_binding.get('segment_id'))
                for port_binding in fixed_binding.get('bindings',[]):
                    pdn = self.get_pdn(port_binding)
                    neutron_bindings.append({"port":pdn,"encap":encap})


            for binding in network.get('bindings',[]):
                encap = self.get_static_binding_encap(binding['network_type'], binding['encap'])
                host_config = binding['host_config']
                if host_config:
                    for port_binding in host_config.get('bindings',[]):
                        pdn = self.get_pdn(port_binding)

                        neutron_bindings.append({"port":pdn,"encap":encap})

            for path in epg.rspathAtt:
                if not {"port":path.tDn,"encap":path.encap} in neutron_bindings:
                    LOG.warning("Cleaning binding %s on EPG %s", {"port":path.tDn,"encap":path.encap}, network_id)

                    path.delete()
                    ports.append(path)

            if ports:
                self.apic.commit(ports)

    # Start Helper Methods

    def _configure_subnet(self, subnet, external=False, address_scope_name=None,last_on_network=False, delete=False):
        network_id = subnet['network_id']

        if external:

            gateway_ip = self._get_gateway(subnet)

            self.ensure_external_network_configured(network_id, address_scope_name,last_on_network, delete)

            if delete:
                # TODO handle multiple subnet case ?
                self.ensure_subnet_deleted(network_id, gateway_ip)

            else:
                self.ensure_subnet_created(network_id, address_scope_name, gateway_ip)



        else:
            self.ensure_internal_network_configured(network_id, delete)

    def _get_gateway(self,subnet):
        cidr = netaddr.IPNetwork(subnet['cidr'])
        gateway_ip = '%s/%s' % (subnet['gateway_ip'],
                                    str(cidr.prefixlen))
        return gateway_ip;

    def _get_address_scope_config(self, address_scope_name):

        if address_scope_name not in self.address_scope_dict:
            raise Exception(
                "No address scope configuration found for address scope pool {} no external configuration can be processed on ACI without configuration".format(
                    address_scope_name))

        scope_config = self.address_scope_dict[address_scope_name]

        return scope_config

    def _find_l3_out(self, network_id,out):
        names = out.split("/")

        if len(names) == 1:
            tenant = self.get_tenant(network_id)
            tenant_name = tenant.name
            out_name = names[0]

        elif len(names) == 2:
            tenant_name = names[0]
            out_name = names[1]
        else:
          return

        l3_out = self.apic.lookupByDn("uni/tn-{}/out-{}".format(tenant_name,out_name))

        if isinstance(l3_out, modelimpl.l3ext.out.Out):
            return l3_out

        return None

    def _ensure_physdom(self,epg,physdom,delete):
        phys_dom = phys.DomP('uni', physdom)

        rs_dom_att = fv.RsDomAtt(epg, phys_dom.dn)

        if delete:
            rs_dom_att.delete()

        self.apic.commit(rs_dom_att)

    # End Helper Methods