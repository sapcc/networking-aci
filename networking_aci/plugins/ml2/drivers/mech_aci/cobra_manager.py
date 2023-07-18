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
from cobra.model import fv, fvns, infra, phys
import cobra.modelimpl.l3ext.out
import netaddr
from oslo_config import cfg
from oslo_log import log

from networking_aci.plugins.ml2.drivers.mech_aci import cobra_client
from networking_aci.plugins.ml2.drivers.mech_aci import common
from networking_aci.plugins.ml2.drivers.mech_aci.config import ACI_CONFIG
from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const


LOG = log.getLogger(__name__)
CONF = cfg.CONF

ENCAP_VLAN = 'vlan-%s'
PORT_DN_PATH = 'topology/%s/paths-%s/pathep-[eth%s/%s]'
VPCPORT_DN_PATH = 'topology/%s/protpaths-%s/pathep-[%s]'
DPCPORT_DN_PATH = 'topology/%s/paths-%s/pathep-[%s]'
NODE_DN_PATH = 'topology/%s/paths-%s/pathep-[Switch%s_%s-ports-%s_PolGrp]'
PORT_SELECTOR_DN = 'uni/infra/accportprof-{}/hports-{}-typ-range'


class CobraManager(object):
    def __init__(self, agent_plugin, tenant_manager):
        # Connect to the APIC

        self.agent_plugin = agent_plugin
        self.apic_application_profile = CONF.ml2_aci.apic_application_profile
        self.tenant_default_vrf = CONF.ml2_aci.tenant_default_vrf

        self.apic = cobra_client.CobraClient(CONF.ml2_aci.apic_hosts,
                                             CONF.ml2_aci.apic_username,
                                             CONF.ml2_aci.apic_password,
                                             CONF.ml2_aci.apic_use_ssl)

        self.tenant_manager = tenant_manager

    @property
    def api(self):
        return self.apic

    def get_pdn(self, binding):
        binding_config = binding.split("/")
        pdn = None
        if binding_config[0] == 'port':
            pdn = PORT_DN_PATH % (binding_config[1], binding_config[2], binding_config[3], binding_config[4])
        elif binding_config[0] == 'node':
            pdn = NODE_DN_PATH % (binding_config[1], binding_config[2], binding_config[2],
                                  binding_config[3], binding_config[4])
        elif binding_config[0] == 'dpc':
            pdn = DPCPORT_DN_PATH % (binding_config[1], binding_config[2], binding_config[3])
        elif binding_config[0] == 'vpc':
            pdn = VPCPORT_DN_PATH % (binding_config[1], binding_config[2], binding_config[3])

        return pdn

    @staticmethod
    def get_static_binding_encap(segment_type, encap):
        if segment_type == 'vlan':
            encap = ENCAP_VLAN % str(encap)

        return encap

    @classmethod
    def get_encap_mode(cls, hostgroup, segmentation_id):
        # normal VMs OR baremetal hosts with segment id outside baremetal vlan access range --> trunk
        # baremetal hosts with vlan id from baremetal vlan access range or infra hosts --> access
        if hostgroup.get('direct_mode', False) and (
                hostgroup['hostgroup_mode'] == aci_const.MODE_INFRA or
                segmentation_id in common.get_set_from_ranges(hostgroup['baremetal_access_vlan_ranges'])):
            return "untagged"  # access
        else:
            return "regular"  # trunk

    def ensure_domain_and_epg(self, context, network_id, external=False):
        tenant = self.get_or_create_tenant(network_id)
        ep_retention_policy = None

        if external:
            unicast_route = 1
            move_detect = 1
            limit_ip_learn_subnets = 1
            ep_retention_policy = CONF.ml2_aci.ep_retention_policy_net_external
            host_based_routing = 'yes' if CONF.ml2_aci.advertise_hostroutes else 'no'
        else:
            unicast_route = 0
            move_detect = 0
            limit_ip_learn_subnets = 0
            ep_retention_policy = CONF.ml2_aci.ep_retention_policy_net_internal
            host_based_routing = 'no'

        bd_opts = {
            'arpFlood': 1,
            'unkMacUcastAct': 0,
            'unicastRoute': unicast_route,
            'epMoveDetectMode': move_detect,
            'limitIpLearnToSubnets': limit_ip_learn_subnets,
            'hostBasedRouting': host_based_routing,
        }

        if CONF.ml2_aci.support_remote_mac_clear:
            bd_opts['epClear'] = 1

        bd = fv.BD(tenant, network_id, **bd_opts)
        app = fv.Ap(tenant, self.apic_application_profile)
        epg = fv.AEPg(app, network_id)

        # Add EPG to BD domain
        rsbd = fv.RsBd(epg, network_id, tnFvBDName=bd.name)

        bd_objs = [bd]
        if ep_retention_policy:
            epret = fv.RsBdToEpRet(bd, tnFvEpRetPolName=ep_retention_policy)
            bd_objs.append(epret)

        # We have to make seperate config requests because cobra can't
        # handle MOs with different root contexts
        self.apic.commit(bd_objs)
        self.apic.commit([app, epg, rsbd])
        tenant_tag = "monsoon3::aci::tenant::{}".format(self.tenant_manager.get_tenant_name(network_id))
        self.agent_plugin.tag_network(context, network_id, tenant_tag)

    def delete_domain_and_epg(self, network_id, transaction=None):
        tenant = self.get_tenant(network_id)

        if tenant is None:
            LOG.warning("Cannot determine tenant {} for network {}. Aborting delete."
                        .format(self.tenant_manager.get_tenant_name(network_id), network_id))
            return

        bd = fv.BD(tenant, network_id)
        bd.delete()

        app = fv.Ap(tenant, self.apic_application_profile)
        epg = fv.AEPg(app, network_id)
        epg.delete()

        self.apic.commit(epg)
        self.apic.commit(bd)

        if(len(self.get_tenant_bridge_domains(tenant)) == 0 and len(self.get_tenant_epgs(tenant)) == 0):
            tenant.delete()
            self.apic.commit(tenant)

    def _gen_port_selector_entities(self, host_config):
        pc_policy_group = host_config['pc_policy_group']
        if not pc_policy_group:
            return []

        pol_ref = infra.AccBndlGrp('uni/infra/funcprof', name=pc_policy_group)
        entities = []
        for port_sel in host_config['port_selectors']:
            if not port_sel.startswith("uni/"):
                port_sel = PORT_SELECTOR_DN.format(*port_sel.split("/"))
            acc_base_grp = infra.RsAccBaseGrp(port_sel, tDn=pol_ref.dn)
            entities.append(acc_base_grp)

        return entities

    def ensure_static_bindings_configured(self, network_id, host_config, encap=None,
                                          delete=False, physdoms_to_clear=[]):
        tenant = self.get_tenant(network_id)
        if not tenant:
            LOG.error("Network {} does not appear to be avilable in ACI, expected in tenant {}"
                      .format(network_id, self.tenant_manager.get_tenant_name(network_id)))
            return

        direct_mode = host_config.get('direct_mode', False)
        bindings = host_config['bindings']
        segment_type = host_config['segment_type']
        segmentation_id = encap
        encap = self.get_static_binding_encap(segment_type, segmentation_id)
        encap_mode = self.get_encap_mode(host_config, segmentation_id)
        app = fv.Ap(tenant, self.apic_application_profile)
        epg = fv.AEPg(app, network_id)
        entities = []

        if not delete and direct_mode:
            self.ensure_hostgroup_mode_config(host_config, source="network {}".format(network_id))

        for binding in bindings:
            pdn = self.get_pdn(binding)
            LOG.debug("Preparing static binding %s encap %s mode %s for network %s", pdn, encap, encap_mode, network_id)
            port = fv.RsPathAtt(epg, pdn, encap=encap, mode=encap_mode)
            if delete:
                port.delete()
            entities.append(port)

        if entities:
            self.apic.commit(entities)
        else:
            binding_hosts = ", ".join(host_config['hosts']) if host_config else "<no hosts>"
            LOG.debug("Sync of network %s for binding hosts '%s' did not have any bindings, skipping this hostgroup",
                      network_id, binding_hosts)

        # Associate to Physical Domain
        for physdom in host_config['physical_domain']:
            self._ensure_physdom(epg, physdom, (delete and physdom in physdoms_to_clear))

    def ensure_baremetal_entities(self, policy_group, project_domain, pc_policy_group_name):
        pc_policy_group_data = ACI_CONFIG.get_pc_policy_group_data(pc_policy_group_name)
        if not pc_policy_group_data:
            return False

        # aep, physdom, vlan pool
        aep = infra.AttEntityP('uni/infra', name=project_domain)
        physdom = phys.DomP('uni', project_domain)
        vlan_pool = fvns.VlanInstP('uni/infra', name=project_domain, allocMode="static")
        encap_blk = fvns.EncapBlk(vlan_pool,
                                  'vlan-{}'.format(CONF.ml2_aci.baremetal_encap_blk_start),
                                  'vlan-{}'.format(CONF.ml2_aci.baremetal_encap_blk_end))

        dom_vlan_pool_rel = infra.RsVlanNs(physdom, tDn=vlan_pool.dn)
        aep_dom_rel = infra.RsDomP(aep, physdom.dn)

        aep_entities = [aep, physdom, vlan_pool, encap_blk, dom_vlan_pool_rel, aep_dom_rel]

        # pc profile
        pc_profile = infra.AccBndlGrp('uni/infra/funcprof', name=policy_group, lagT=pc_policy_group_data['lag_mode'])
        pc_entities = [pc_profile]
        pc_attrs = [
            ('link_level_policy', infra.RsHIfPol, 'tnFabricHIfPolName'),
            ('cdp_policy', infra.RsCdpIfPol, 'tnCdpIfPolName'),
            ('lldp_policy', infra.RsLldpIfPol, 'tnLldpIfPolName'),
            ('lacp_policy', infra.RsLacpPol, 'tnLacpLagPolName'),
            ('mcp_policy', infra.RsMcpIfPol, 'tnMcpIfPolName'),
            ('monitoring_policy', infra.RsMonIfInfraPol, 'tnMonInfraPolName'),
            ('l2_policy', infra.RsL2IfPol, 'tnL2IfPolName'),
        ]
        for pc_conf_name, pc_rs, pc_attr in pc_attrs:
            pc_attr_val = pc_policy_group_data[pc_conf_name]
            if pc_attr_val:
                entity = pc_rs(pc_profile, **{pc_attr: pc_attr_val})
                pc_entities.append(entity)
        pc_entities.append(infra.RsAttEntP(pc_profile, tDn=aep.dn))
        self.apic.commit(aep_entities + pc_entities)

        return True

    def clean_baremetal_objects(self, resource_name):
        LOG.info("Clearing baremetal entities for %s", resource_name)
        aep = infra.AttEntityP('uni/infra', name=resource_name)
        aep.delete()
        physdom = phys.DomP('uni', resource_name)
        physdom.delete()
        vlan_pool = fvns.VlanInstP('uni/infra', name=resource_name, allocMode="static")
        vlan_pool.delete()
        pc_profile = infra.AccBndlGrp('uni/infra/funcprof', name=resource_name)
        pc_profile.delete()

        self.apic.commit([aep, physdom, vlan_pool, pc_profile])

    def ensure_hostgroup_mode_config(self, host_config, source=""):
        if host_config['hostgroup_mode'] == aci_const.MODE_BAREMETAL:
            if not self.ensure_baremetal_entities(host_config['pc_policy_group'],
                                                  host_config['baremetal_resource_name'],
                                                  host_config['baremetal_pc_policy_group']):
                LOG.error("Could not create baremetal entities for hostgroup %s %s",
                          host_config['name'], source)

        port_sel_entities = self._gen_port_selector_entities(host_config)
        if not port_sel_entities:
            LOG.error("No port selector entity configuration could be generated for hostgroup %s %s"
                      " - are there configuration entities missing?",
                      host_config['name'], source)
        self.apic.commit(port_sel_entities)

    def create_subnet(self, subnet, external, address_scope_name):
        self._configure_subnet(subnet, external=external, address_scope_name=address_scope_name,
                               last_on_network=False, delete=False)

    def delete_subnet(self, subnet, external, address_scope_name, last_on_network):
        self._configure_subnet(subnet, external=external, address_scope_name=address_scope_name,
                               last_on_network=last_on_network, delete=True)

    def ensure_subnet_created(self, network_id, address_scope_name, gateway):
        tenant = self.get_tenant(network_id)
        scope_config = self._get_address_scope_config(address_scope_name)
        l3_outs = scope_config['l3_outs']
        bd = fv.BD(tenant, network_id)
        subnet = fv.Subnet(bd, gateway, scope=scope_config.get('scope', 'public'), ctrl='querier')
        subnet_outs = []

        for l3_out in l3_outs:
            out = self._find_l3_out(network_id, l3_out)

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
        for l3_out in l3_outs:
            out = self._find_l3_out(network_id, l3_out)
            if out:
                bd_out = fv.RsBDToOut(bd, out.name)
                if delete and last_on_network:
                    bd_out.delete()
                bd_outs.append(bd_out)
            else:
                LOG.error('Cannot configure L3 out for BD, {} not found in ACI configuration'.format(l3_out))

        # if delete:
            # vrf.delete() #TODO: the RsCtx object cannot be deleted, need to find out how to clear on the BD

        # Prepare EPG
        app = fv.Ap(tenant, self.apic_application_profile)
        epg = fv.AEPg(app, network_id)

        epg_contracts = []
        for consumed in scope_config['consumed_contracts']:
            contract = fv.RsCons(epg, consumed)
            if delete and last_on_network:
                contract.delete()
            epg_contracts.append(contract)

        for provided in scope_config['provided_contracts']:
            contract = fv.RsProv(epg, provided)
            if delete and last_on_network:
                contract.delete()
            epg_contracts.append(contract)

        self.apic.commit([vrf] + bd_outs + epg_contracts)

    def get_tenant_bridge_domains(self, tenant):
        if not tenant:
            return []
        return self.apic.lookupByClass('fv.BD', parentDn=tenant.dn)

    def get_all_bridge_domains(self):
        result = []

        for tenant_name in self.tenant_manager.all_tenant_names():
            bds = self.get_tenant_bridge_domains(self.apic.get_tenant(tenant_name))
            if len(bds) > 0:
                result += bds

        return result

    def get_tenant_epgs(self, tenant):
        if not tenant:
            return []
        return self.apic.lookupByClass('fv.AEPg', parentDn=tenant.dn)

    def get_all_epgs(self):
        """Get all EPGs managed by OpenStack"""
        wcard = 'wcard(fvAEPg.dn, "/tn-{}")'.format(CONF.ml2_aci.tenant_prefix)
        return self.apic.lookupByClass('fvAEPg', propFilter=wcard)

    def get_bd(self, network_id):
        try:
            bd = self.apic.get_bd(self.get_tenant_name(network_id), network_id)
            if not bd:
                raise RuntimeError("BD {} not found on APIC".format(network_id))
            return bd
        except Exception as e:
            LOG.debug("Could not get BD for network %s: %s %s", network_id, e.__class__.__name__, e)
            return None

    def get_epg(self, network_id):
        try:
            epg = self.apic.get_epg(self.get_tenant_name(network_id), self.apic_application_profile, network_id)
            if not epg:
                raise RuntimeError("EPG {} not found on APIC".format(network_id))
            return epg
        except Exception as e:
            LOG.debug("Could not get EPG for network %s: %s %s", network_id, e.__class__.__name__, e)
            return None

    def get_app(self, network_id):
        return self.apic.get_full_tenant(self.get_tenant_name(network_id)).ap[self.apic_application_profile]

    def get_or_create_tenant(self, network_id):
        return self.apic.get_or_create_tenant(self.tenant_manager.get_tenant_name(network_id))

    def get_tenant(self, network_id):
        return self.apic.get_tenant(self.get_tenant_name(network_id))

    def get_tenant_name(self, network_id):
        return self.tenant_manager.get_tenant_name(network_id)

    def sync_network(self, context, network):
        self.clean_subnets(network)
        self.clean_physdoms(network)
        self.clean_bindings(network)
        self.ensure_domain_and_epg(context, network.get('id'), external=network.get('router:external'))

        if CONF.ml2_aci.handle_all_l3_gateways and aci_const.CC_FABRIC_L3_GATEWAY_TAG not in network['tags']:
            for subnet in network.get('subnets'):
                self.create_subnet(subnet, network.get('router:external'), subnet.get('address_scope_name'))

        for binding in network.get('bindings'):
            if binding.get('host_config'):
                self.ensure_static_bindings_configured(network.get('id'),
                                                       binding.get('host_config'),
                                                       encap=binding.get('encap'))
            else:
                LOG.warning("No host configuration found in binding %s", binding)

        for fixed_binding in network.get('fixed_bindings'):
            encap = fixed_binding.get('segment_id', None)
            self.ensure_static_bindings_configured(network.get('id'), fixed_binding, encap=encap)

    def clean_subnets(self, network):
        network_id = network['id']
        bd = self.get_bd(network_id)
        if bd:
            neutron_subnets = []
            if CONF.ml2_aci.handle_all_l3_gateways and aci_const.CC_FABRIC_L3_GATEWAY_TAG not in network['tags']:
                for neutron_subnet in network.get('subnets', []):
                    neutron_subnets.append(self._get_gateway(neutron_subnet))

            for subnet in bd.subnet:
                if subnet.ip not in neutron_subnets:
                    LOG.warning("Cleaning subnet %s on BD %s", subnet.ip, network_id)
                    self.ensure_subnet_deleted(network_id, subnet.ip)

    def clean_physdoms(self, network):
        network_id = network['id']
        epg = self.get_epg(network_id)
        if epg:
            physdoms = []
            fixed_bindings = network.get('fixed_bindings', [])
            for fixed_binding in fixed_bindings:
                physdoms.extend(fixed_binding.get('physical_domain'))

            for binding in network.get('bindings', []):
                host_config = binding.get('host_config', {})
                if host_config:
                    physdoms.extend(host_config.get('physical_domain'))

            for rsdom in epg.rsdomAtt:
                physdom = rsdom.tDn[9:]
                if physdom not in physdoms:
                    LOG.warning("Cleaning physdom %s on EPG %s", physdom, network_id)
                    self._ensure_physdom(epg, physdom, True)

    def clean_bindings(self, network):
        network_id = network['id']
        epg = self.get_epg(network_id)

        neutron_bindings = []

        if epg:
            ports = []

            fixed_bindings = network.get('fixed_bindings')
            for fixed_binding in fixed_bindings:
                encap = self.get_static_binding_encap(fixed_binding['segment_type'], fixed_binding.get('segment_id'))
                for port_binding in fixed_binding.get('bindings', []):
                    pdn = self.get_pdn(port_binding)
                    neutron_bindings.append({"port": pdn, "encap": encap})

            for binding in network.get('bindings', []):
                encap = self.get_static_binding_encap(binding['network_type'], binding['encap'])
                host_config = binding['host_config']
                if host_config:
                    for port_binding in host_config.get('bindings', []):
                        pdn = self.get_pdn(port_binding)

                        neutron_bindings.append({"port": pdn, "encap": encap})

            for path in epg.rspathAtt:
                if not {"port": path.tDn, "encap": path.encap} in neutron_bindings:
                    LOG.warning("Cleaning binding %s on EPG %s", {"port": path.tDn, "encap": path.encap}, network_id)
                    path.delete()
                    ports.append(path)

            if ports:
                self.apic.commit(ports)

    # Start Helper Methods

    def _configure_subnet(self, subnet, external=False, address_scope_name=None, last_on_network=False, delete=False):
        network_id = subnet['network_id']

        if external:
            gateway_ip = self._get_gateway(subnet)
            self.ensure_external_network_configured(network_id, address_scope_name, last_on_network, delete)

            if delete:
                # TODO handle multiple subnet case ?
                self.ensure_subnet_deleted(network_id, gateway_ip)
            else:
                self.ensure_subnet_created(network_id, address_scope_name, gateway_ip)
        else:
            self.ensure_internal_network_configured(network_id, delete)

    def _get_gateway(self, subnet):
        cidr = netaddr.IPNetwork(subnet['cidr'])
        gateway_ip = '{}/{}'.format(subnet['gateway_ip'], str(cidr.prefixlen))
        return gateway_ip

    def _get_address_scope_config(self, address_scope_name):
        scope_config = ACI_CONFIG.get_address_scope_by_name(address_scope_name)
        if scope_config is None:
            raise Exception("No address scope configuration found for address scope pool {} "
                            "no external configuration can be processed on ACI without configuration"
                            .format(address_scope_name))

        return scope_config

    def _find_l3_out(self, network_id, out):
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

        l3_out = self.apic.lookupByDn("uni/tn-{}/out-{}".format(tenant_name, out_name))

        if isinstance(l3_out, cobra.modelimpl.l3ext.out.Out):
            return l3_out

        return None

    def _ensure_physdom(self, epg, physdom, delete):
        phys_dom = phys.DomP('uni', physdom)

        rs_dom_att = fv.RsDomAtt(epg, phys_dom.dn)

        if delete:
            rs_dom_att.delete()

        self.apic.commit(rs_dom_att)
