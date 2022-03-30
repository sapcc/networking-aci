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
from copy import deepcopy

from neutron_lib import context
from neutron.conf import service as service_conf
from oslo_config import cfg
from oslo_log import log as logging

from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const
from networking_aci.plugins.ml2.drivers.mech_aci import exceptions as aci_exc
from networking_aci.plugins.ml2.drivers.mech_aci import common

LOG = logging.getLogger(__name__)
DEFAULT_ROOT_HELPER = ('sudo /usr/local/bin/neutron-rootwrap '
                       '/etc/neutron/rootwrap.conf')

aci_opts = [
    cfg.ListOpt('apic_hosts',
                default=[],
                help="An ordered list of host names or IP addresses of "
                     "the APIC controller(s)."),
    cfg.StrOpt('apic_username',
               help="Username for the APIC controller"),
    cfg.StrOpt('apic_password',
               help="Password for the APIC controller", secret=True),
    cfg.StrOpt('apic_name_mapping',
               default='use_name',
               help="Name mapping strategy to use: use_uuid | use_name"),
    cfg.BoolOpt('apic_use_ssl', default=True,
                help="Use SSL to connect to the APIC controller"),
    cfg.StrOpt('tenant_prefix',
               default='monsoon_lab',
               help="Name for the tenant on APIC"),
    cfg.IntOpt('tenant_ring_size',
               default=60,
               help="Size of tenant pool"),
    cfg.StrOpt('tenant_items_managed',
               default="1:60",
               help="The individual ring items managed by an agent"),
    cfg.BoolOpt('sync_active',
                default=True,
                help="Activate regular config sync"),
    cfg.StrOpt('tenant_manager',
               default='hash_ring',
               help="Name of tenant manager"),
    cfg.IntOpt('polling_interval',
               default=60,
               help="Polling interval for sync task"),
    cfg.IntOpt('sync_batch_size',
               default=10,
               help="Number of networks to process in on poll"),
    cfg.IntOpt('reauth_threshold',
               default=120,
               help="Minimum remaining auth token valid time in seconds before renewing it proactively. "
                    "By default the auth token is valid for 600s. This config defaults to 120s before timeout."),
    cfg.BoolOpt('prune_orphans',
                default=True,
                help="Clean orphaned EPG and BD on ACI"),
    cfg.StrOpt('apic_application_profile',
               default='monsoon_lab_infrastructure',
               help="Name for the application profile on APIC"),
    cfg.StrOpt('tenant_default_vrf',
               default='lab-l2',
               help="Name for the default vrf for tenant networks"),
    cfg.BoolOpt('support_remote_mac_clear',
                default=True,
                help="Region has API version supporting remote MAC clear"),
    cfg.BoolOpt('sync_allocations',
                default=True,
                help="Sync allocations on startup"),
    cfg.StrOpt('ep_retention_policy_net_internal',
               default=None,
               help="Name of the endpoint retention policy to use for internal networks. "
                    "If unset the attribute is left untouched."),
    cfg.StrOpt('ep_retention_policy_net_external',
               default=None,
               help="Name of the endpoint retention policy to use for external networks. "
                    "If unset the attribute is left untouched."),
    cfg.StrOpt('baremetal_resource_prefix',
               default='openstack-baremetal',
               help="Prefix baremetal resources created in ACI with this prefix"),
    cfg.StrOpt('default_baremetal_pc_policy_group',
               help="Default config group for baremetal port-channel policy group values, "
                    "written as pc-policy-group:$name (without prefix)"),
    cfg.ListOpt('baremetal_reserved_vlan_ids', default=[],
                help="List of reserved vlan id ranges in the format of A:B,C:D - e.g 100:107"),
    cfg.IntOpt('baremetal_encap_blk_start', default=1000),
    cfg.IntOpt('baremetal_encap_blk_end', default=1999),
    cfg.ListOpt('baremetal_default_access_vlan_ranges', default=['1800:1999'],
                help='Default access vlan ranges, must be included in the baremetal encap block. '
                     'These ranges will be used to allocate VLAN ids for access ports on a '
                     'per-physdom basis.'),
    cfg.StrOpt('handle_port_update_for_non_baremetal',
               default=False,
               help="Port updates (e.g. binding host removed/changed) are only handled for trunk ports. "
                    "This can be enabled for all ports, but this might have unforseen sideeffects (untested)."),
    cfg.BoolOpt('az_checks_enabled',
                default=True,
                help="Enable AZ checks for port creation (default on). If AZ checks are disabled and the check fails "
                     "port binding will not be blocked and a warning will be logged instead."),
]

hostgroup_opts = [
    cfg.ListOpt('hosts', required=True,
                help="List of hosts that this hostgroup is responsible for"),
    cfg.ListOpt('bindings', required=True,
                help="List of bindings that are bound to an EPG (VPCs/PCs)"),
    cfg.ListOpt('physical_domain',
                help="List of physical domains to add to an EPG"),
    cfg.StrOpt('physical_network',
               help="Name of the physical network / segment identifier. This basically defines the VLAN pool name"),
    cfg.StrOpt('segment_type',
               help="Segment type, currently only vlan is supported"),
    cfg.ListOpt('segment_range', default=[],
                help="Vlan/segment range to use, specified as from:to. Can have multiple entries separated by ','"),
    cfg.ListOpt('availability_zones', default=[],
                help='AZ this hostgroup is in. If a network has an AZ hint set then a port of this network can only '
                     'be bound if the AZ from the hint is present in this list'),
    cfg.DictOpt('host_azs', default={},
                help="Specify an AZ for a bindinghost in the format of 'host:AZ,host:AZ,...'. "
                     "This overrules the hostgroup's AZ"),
    cfg.BoolOpt('finalize_binding', default=False,
                help="Finalize portbinding. The port will be bound directly to ACI, but without being in direct mode. "
                     "This can be used for dummy portbindings or where no other driver should be involved. The driver "
                     "will still do a two level portbinding, where both levels are this driver."),
    cfg.BoolOpt('fabric_transit', default=False,
                help="Hostgroup is a transit to the cc-fabric and will automatically be bound when a segment is found. "
                     "Cannot be bound by a port."),

    # non-hierarchical portbinding / baremetal options
    cfg.BoolOpt('direct_mode', default=False,
                help="If enabled this hostgroup supports direct-on-aci non-hierarchical portbindings"),
    cfg.ListOpt('port_selectors', default=[],
                help="Port selectors whose policy needs to be changed / set when switching between "
                     "infra and baremetal mode"),
    cfg.StrOpt('parent_hostgroup',
               help="Hostgroup to be used for "),

    # infra mode
    cfg.StrOpt('infra_pc_policy_group',
               help='(infra mode) Policy group name to set on all specified port selectors when in infra mode'),

    # baremetal mode
    cfg.StrOpt('baremetal_pc_policy_group',
               help="(baremetal mode) Section which describes the portchannel policy group attributes. "
                    "If not specified wefall back to default_baremetal_pc_policy_group"),
    cfg.StrOpt('baremetal_access_vlan_ranges', default=None, help='See baremetal_default_access_vlan_ranges'),
]

fixed_binding_opts = [
    cfg.StrOpt('description'),
    cfg.ListOpt('bindings', required=True,
                help="List of bindings that are bound to an EPG (VPCs/PCs)"),
    cfg.ListOpt('physical_domain', default=[],
                help="List of physical domains to add to an EPG"),
    cfg.StrOpt('segment_type',
               help="Segment type, currently only vlan is supported"),
    cfg.IntOpt('segment_id',
               help="VLAN/segment id to use for this binding"),
]

address_scope_opts = [
    cfg.ListOpt('l3_outs', required=True,
                help="List of l3outs for this address scope"),
    cfg.StrOpt('contracts',
               help="Contract data structure, e.g. {'consumed':['foo'],'provided':['foo']}"),
    cfg.ListOpt('consumed_contracts', default=[],
                help="Consumed contracts for this scope. Contracts from the contracts option will be added as well."),
    cfg.ListOpt('provided_contracts', default=[],
                help="Provided contracts for this scope. Contracts from the contracts option will be added as well."),
    cfg.StrOpt('vrf', required=True,
               help="VRF name of this address scope"),
]

pc_policy_group_opts = [
    cfg.StrOpt("lag_mode", choices=("link", "node"),
               default="node",
               help="Port-Channel type (link == pc, node == vpc)"),
    cfg.StrOpt("link_level_policy",
               default="10Gig_Link_auto",
               help="Preprovisioned link level policy to use"),
    cfg.StrOpt("cdp_policy",
               default="CDP_on",
               help="Preprovisioned CDP policy to use"),
    cfg.StrOpt("lldp_policy",
               default="LLDP_enable",
               help="Preprovisioned LLDP policy to use"),
    cfg.StrOpt("lacp_policy",
               default="LACP_on_fast_suspend",
               help="Preprovisioned port channel policy to use"),
    cfg.StrOpt("mcp_policy",
               default="",
               help="Preprovisioned MCP policy to use"),
    cfg.StrOpt("monitoring_policy",
               default="SAP_SNMP",
               help="Preprovisioned monitoring policy to use"),
    cfg.StrOpt("l2_policy",
               default="SAP_SNMP",
               help="Preprovisioned l2 policy, should define VLAN local scope mode"),
]

cli_opts = [
    cfg.StrOpt('network-id',
               help="Network ID used in consistency check"),
    cfg.StrOpt('mode', default='check',
               help="Check mode - either read only check or sync to fix inconsistencies")
]

cfg.CONF.register_opts(aci_opts, "ml2_aci")
service_conf.register_service_opts(service_conf.RPC_EXTRA_OPTS)
CONF = cfg.CONF


class ACIConfig:
    def __init__(self):
        self._db = None
        self._context = None
        self.reset_config()

    def reset_config(self):
        self._hostgroups = {}
        self._fixed_bindings = {}
        self._address_scopes = {}
        self._pc_policy_groups = {}

    @property
    def db(self):
        """DB object, only used by neutron-server side, not by agent"""
        if not self._db:
            raise Exception("DB plugin not present")
        return self._db

    @property
    def context(self):
        if not self._context:
            self._context = context.get_admin_context()
        return self._context

    @db.setter
    def db(self, val):
        self._db = val

    @property
    def hostgroups(self):
        if not self._hostgroups:
            self._parse_hostgroups()
        return self._hostgroups

    @property
    def fixed_bindings(self):
        if not self._fixed_bindings:
            self._parse_fixed_bindings()
        return self._fixed_bindings

    @property
    def address_scopes(self):
        if not self._address_scopes:
            self._parse_address_scopes()
        return self._address_scopes

    @property
    def pc_policy_groups(self):
        if not self._pc_policy_groups:
            self._parse_pc_policy_groups()
        return self._pc_policy_groups

    def _parse_config(self, section_prefix, opts, to_dict=False):
        """Find all sections by prefix, parse sections with given oslo.config opts"""
        data = {}
        section_prefix = "{}:".format(section_prefix)
        for section in cfg.CONF.list_all_sections():
            if not section.startswith(section_prefix):
                continue
            cfg.CONF.register_opts(opts, section)
            sec_cfg = getattr(cfg.CONF, section)
            if to_dict:
                sec_cfg = dict(sec_cfg)
            key = section[len(section_prefix):]
            data[key] = sec_cfg

        return data

    @staticmethod
    def to_range_list(str_ranges):
        ranges = []
        for str_range in str_ranges:
            range_from, range_to = str_range.split(":")
            ranges.append((int(range_from), int(range_to)))
        return ranges

    def _parse_hostgroups(self):
        """Parse hostgroups, add missing information, do some sanity checks"""
        self._hostgroups = self._parse_config("aci-hostgroup", hostgroup_opts, to_dict=True)

        for hostgroup_name, hostgroup in self._hostgroups.items():
            hostgroup['name'] = hostgroup_name
            hostgroup['child_hostgroups'] = []

            # handle segment ranges
            segment_ranges = hostgroup['segment_range']
            if segment_ranges:
                hostgroup['segment_range'] = self.to_range_list(segment_ranges)

        for hostgroup_name, hostgroup in self._hostgroups.items():
            if not hostgroup['direct_mode']:
                continue

            if hostgroup.get('parent_hostgroup'):
                far_hg = hostgroup['parent_hostgroup']
                if far_hg not in self._hostgroups:
                    raise aci_exc.ACIOpenStackConfigurationError(reason="Could not find hostgroup {} referenced by {}"
                                                                        .format(far_hg, hostgroup_name))
                self._hostgroups[far_hg]['child_hostgroups'].append(hostgroup_name)

            if not hostgroup['baremetal_pc_policy_group']:
                hostgroup['baremetal_pc_policy_group'] = CONF.ml2_aci.default_baremetal_pc_policy_group

            if not hostgroup['baremetal_access_vlan_ranges']:
                hostgroup['baremetal_access_vlan_ranges'] = CONF.ml2_aci.baremetal_default_access_vlan_ranges
            hostgroup['baremetal_access_vlan_ranges'] = self.to_range_list(hostgroup['baremetal_access_vlan_ranges'])

    def _parse_fixed_bindings(self):
        self._fixed_bindings = self._parse_config("fixed-binding", fixed_binding_opts, to_dict=True)

    def _parse_address_scopes(self):
        self._address_scopes = self._parse_config("address-scope", address_scope_opts, to_dict=True)

        for scope in self._address_scopes.values():
            if scope.get('contracts'):
                contracts = ast.literal_eval(scope.get('contracts'))
                scope['consumed_contracts'].extend(contracts['consumed'])
                scope['provided_contracts'].extend(contracts['provided'])

    def _parse_pc_policy_groups(self):
        self._pc_policy_groups = self._parse_config("pc-policy-group", pc_policy_group_opts, to_dict=True)

    def _clean_bindings(self, hg, hostgroup_modes, segment_id=None, level=None):
        if segment_id:
            hosts_on_seg = self.db.get_hosts_on_segment(self.context, segment_id, level)

        for child_hg in hg['child_hostgroups']:
            hostgroup_mode = hostgroup_modes.get(child_hg)
            if hostgroup_mode == aci_const.MODE_BAREMETAL:
                # remove bindings for hostgroups in baremetal mode
                hg['bindings'] = list(set(hg['bindings']) - set(self.hostgroups[child_hg]['bindings']))
            elif hostgroup_mode == aci_const.MODE_INFRA:
                if segment_id and child_hg in hosts_on_seg:
                    # remove bindings for infra hostgroups that have a binding on this segment
                    hg['bindings'] = list(set(hg['bindings']) - set(self.hostgroups[child_hg]['bindings']))
            else:
                LOG.error("Unknwon or no host mode '%s' for group %s", hostgroup_mode, child_hg)

    def get_hostgroup(self, name, segment_id=None, level=None):
        """Returns an adjusted copy of a named hostgroup

        This method will create a copy of a named hostgtroup, find out its current mode (none, infra, baremetal)
        and adjust all values accordingly, so it can be used interchangeable in most places."""
        if name not in self.hostgroups:
            return

        hg = deepcopy(self.hostgroups[name])
        if not hg['direct_mode']:
            # remove all bindings used by child hostgroups in baremetal mode
            hostgroup_modes = self.db.get_hostgroup_modes(self.context, hg['child_hostgroups'])
            self._clean_bindings(hg, hostgroup_modes, segment_id, level)
        else:
            # add hostgroup_mode, copy parent physnet/segment values for infra mode
            hg_mode = self.db.get_hostgroup_mode(self.context, name)
            hg['hostgroup_mode'] = hg_mode
            if hg_mode == aci_const.MODE_INFRA:
                far_hg = hg['parent_hostgroup']
                for key in 'physical_network', 'segment_type', 'segment_range', 'physical_domain':
                    hg[key] = self.hostgroups[far_hg][key]
                hg['pc_policy_group'] = hg['infra_pc_policy_group']
            elif hg_mode == aci_const.MODE_BAREMETAL:
                node_resource_name = "{}-{}".format(CONF.ml2_aci.baremetal_resource_prefix, name)
                hg['pc_policy_group'] = node_resource_name

                # bindings do have a different policygroup in baremetal mode
                for n, binding in enumerate(hg['bindings']):
                    hg['bindings'][n] = "/".join(binding.split("/")[:-1] + [hg['pc_policy_group']])
            else:
                LOG.error("Unknown hostgroup mode %s for hostgroup %s", hg_mode, name)

        return hg

    def clean_bindings(self, hostgroup, segment_id, level):
        """Clean hostgroup from all bindings from currently-in-use direct bindings, inplace.

        This removes all bindings that are currently in use by a baremetal host or
        by an infra host in the specified segment.
        """
        if hostgroup['direct_mode']:
            return hostgroup

        hostgroup_modes = self.db.get_hostgroup_modes(self.context, hostgroup['child_hostgroups'])
        self._clean_bindings(hostgroup, hostgroup_modes, segment_id, level)

        return hostgroup

    def annotate_baremetal_info(self, hostgroup, network_id, override_project_id=None):
        if not (hostgroup['direct_mode'] and hostgroup['hostgroup_mode'] == aci_const.MODE_BAREMETAL):
            return

        # since baremetal resources are scoped to a project we need to find out if they are in a project
        ports = self.db.get_ports_on_network_by_physnet_prefix(self.context, network_id, self.baremetal_resource_prefix)
        project_id = override_project_id
        for port in ports:
            if project_id is None:
                project_id = port['project_id']
            elif port['project_id'] != project_id:
                LOG.error("Hostgroup %s has extra port %s in different project (%s vs %s)",
                          hostgroup['name'], port['port_id'], project_id, port['project_id'])

        if project_id:
            res_name = self.gen_bm_resource_name(project_id)
        else:
            res_name = None
        hostgroup['baremetal_resource_name'] = res_name
        hostgroup['physical_domain'] = [res_name]
        hostgroup['physical_network'] = res_name

    def get_hostgroup_name_by_host(self, host_id):
        for hostgroup_name, hostgroup_config in self.hostgroups.items():
            if host_id in hostgroup_config['hosts']:
                return hostgroup_name

    def get_hostgroup_by_host(self, host_id, segment_id=None, level=None):
        hostgroup_name = self.get_hostgroup_name_by_host(host_id)
        if not hostgroup_name:
            return None, None
        return hostgroup_name, self.get_hostgroup(hostgroup_name, segment_id, level)

    def get_physdoms_by_physnet(self, physnet, network_id, override_project_id=None):
        for hg_name, hg in self.hostgroups.items():
            if hg['direct_mode']:
                # we need mapped values for direct-mode hgs
                hg = self.get_hostgroup(hg_name)
            if hg['physical_network'] == physnet:
                self.annotate_baremetal_info(hg, network_id, override_project_id)
                return hg['physical_domain']
        return []

    def get_fixed_binding_by_tag(self, tag):
        return self.fixed_bindings.get(tag)

    def get_address_scope_by_name(self, name):
        return self.address_scopes.get(name)

    def get_pc_policy_group_data(self, name):
        return self.pc_policy_groups.get(name)

    @property
    def baremetal_reserved_vlans(self):
        ranges = self.to_range_list(CONF.ml2_aci.baremetal_reserved_vlan_ids)
        return common.get_set_from_ranges(ranges)

    @property
    def baremetal_resource_prefix(self):
        return "{}-".format(CONF.ml2_aci.baremetal_resource_prefix)

    def gen_bm_resource_name(self, project_id):
        return "{}{}".format(self.baremetal_resource_prefix, project_id)

    def get_transit_hostgroups(self):
        hgs = []
        for hg in self.hostgroups.values():
            if hg['fabric_transit']:
                hgs.append(hg)
        return hgs


ACI_CONFIG = ACIConfig()
