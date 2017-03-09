import ast
from oslo_log import log

from networking_aci.plugins.ml2.drivers.mech_aci import cobra_client

from cobra.model import fv
from cobra.model import phys
from cobra import modelimpl
from cobra.mit import request


# from cobra.model.fv import BD
# from cobra.model.fv import Subnet
# from cobra.model.fv import Ap
# from cobra.model.fv import AEPg
# from cobra.model.fv import RsBd
# from cobra.model.phys import DomP
# from cobra.model.fv import RsDomAtt
# from cobra.model.fv import RsBDSubnetToOut
# from cobra.model.fv import RsBDSubnetToProfile
# from cobra.model.fv import RsBDToProfile
# from cobra.model.fv import RsBDToOut
# from cobra.model.fv import RsCtx
# from cobra.model.fv import RsConsIf

LOG = log.getLogger(__name__)

ENCAP_VLAN = 'vlan-%s'
PORT_DN_PATH = 'topology/pod-1/paths-%s/pathep-[eth%s/%s]'
VPCPORT_DN_PATH = 'topology/pod-1/protpaths-%s/pathep-[%s]'
DPCPORT_DN_PATH = 'topology/pod-1/paths-%s/pathep-[%s]'
NODE_DN_PATH = 'topology/pod-1/paths-%s/pathep-[Switch%s_%s-ports-%s_PolGrp]'


class CobraManager(object):
    def __init__(self, network_config, aci_config, tenant_manager):
        # Connect to the APIC

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

        self.tenant_manager = tenant_manager



    def ensure_domain_and_epg(self, network_id):
        tenant = self.get_or_create_tenant(network_id)

        bd = fv.BD(tenant, network_id, arpFlood=1, unkMacUcastAct=0)

        app = fv.Ap(tenant, self.apic_application_profile)

        epg = fv.AEPg(app, network_id)

        # Add EPG to BD domain
        rsbd = fv.RsBd(epg, network_id, tnFvBDName=bd.name)

        # We have to make seperate config requests because cobra can't
        # handle MOs with different root contexts
        self.apic.commit(bd)

        self.apic.commit([app, epg, rsbd])

        return network_id

    def delete_domain_and_epg(self, network_id, transaction=None):
        tenant = self.get_tenant(network_id)

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


    def get_static_binding_encap(self, segment_type, encap):
        if segment_type == 'vlan':
            encap = ENCAP_VLAN % str(encap)

        return encap

    def ensure_static_bindings_configured(self, network_id, host_config, encap=None, delete=False, clear_phys_dom=False):
        tenant = self.get_tenant(network_id)

        if tenant:

            LOG.info("Using host config for bindings  {}".format(host_config))

            bindings = host_config['bindings']
            segment_type = host_config['segment_type']

            LOG.info("Preparing static bindings {} in tenant {}".format(bindings, tenant.name))

            encap = self.get_static_binding_encap(segment_type, encap)

            app = fv.Ap(tenant, self.apic_application_profile)
            epg = fv.AEPg(app, network_id)
            ports = []

            for binding in bindings:
                binding_config = binding.split("/")
                pdn = None
                if binding_config[0] == 'port':
                    pdn = PORT_DN_PATH % (binding_config[1], binding_config[2], binding_config[3])
                elif binding_config[0] == 'node':
                    pdn = NODE_DN_PATH % (binding_config[1], binding_config[1], binding_config[2], binding_config[3])
                elif binding_config[0] == 'dpc':
                    pdn = DPCPORT_DN_PATH % (binding_config[1], binding_config[2])
                elif binding_config[0] == 'vpc':
                    pdn = VPCPORT_DN_PATH % (binding_config[1], binding_config[2])

                LOG.info("Preparing static binding {}".format(pdn))

                port = fv.RsPathAtt(epg, pdn, encap=encap)
                if delete:
                    port.delete()

                ports.append(port)

            self.apic.commit(ports)

            # Associate to Physical Domain

            phys_dom = phys.DomP('uni', host_config['physical_domain'])

            rs_dom_att = fv.RsDomAtt(epg, phys_dom.dn)

            if delete and clear_phys_dom:
                rs_dom_att.delete()

            self.apic.commit(rs_dom_att)

        else:
           LOG.error("Network {} does not appear to be avilable in ACI, expected in tenant {}".format(network_id,self.tenant_manager.get_tenant_name(network_id)))

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
                LOG.info('Configure L3 out for subnet, {}'.format(out.name))
                subnet_outs.append(fv.RsBDSubnetToOut(subnet, out.name))
            else:
                LOG.error('Cannot configure L3 out for subnet, {} not found in ACI configuration'.format(l3_out))

                # We don't need the out profiles for now
                # subnet_out_profile = RsBDSubnetToProfile(subnet,l3_out,tnL3extOutName=l3_out)

                # self.apic.commit(subnet_out_profile)

        self.apic.commit([subnet] + subnet_outs)

    def ensure_internal_network_configured(self, network_id, delete=False):
        tenant = self.get_tenant(network_id)

        bd = fv.BD(tenant, network_id)
        vrf = fv.RsCtx(bd, self.tenant_default_vrf, tnFvCtxName=self.tenant_default_vrf)
        self.apic.commit(vrf)

    def ensure_external_network_configured(self, network_id, address_scope_name, delete=False):
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
                LOG.info('Configure L3 out for network, {}'.format(out.name))
                bd_out = fv.RsBDToOut(bd, out.name)
                if delete:
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
                    if delete:
                        contract.delete()
                    epg_contracts.append(contract)
            elif type =='provided':
                for contract in contracts:
                    contract = fv.RsProv(epg, contract)
                    if delete:
                        contract.delete()
                    epg_contracts.append(contract)

        self.apic.commit([vrf] + bd_outs + epg_contracts)

    def ensure_subnet_deleted(self, network_id, gateway):
        tenant = self.get_tenant(network_id)
        bd = fv.BD(tenant, network_id)

        subnet = fv.Subnet(bd, gateway)
        subnet.delete()

        self.apic.commit(subnet)




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
        return self.apic.mo_dir.lookupByClass('fv.AEPg',parentDn=tenant.dn)

    def get_all_epgs(self):
        result = []

        for tenant_name in self.tenant_manager.all_tenant_names():
            epgs = self.get_tenant_epgs(self.apic.get_tenant(tenant_name))
            if len(epgs) > 0:
                result += epgs

        return result

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

    def get_or_create_tenant(self,network_id):
        return self.apic.get_or_create_tenant(self.tenant_manager.get_tenant_name(network_id))

    def get_tenant(self,network_id):
        return self.apic.get_tenant(self.tenant_manager.get_tenant_name(network_id))




