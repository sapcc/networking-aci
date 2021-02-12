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

from oslo_config import cfg

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
    cfg.ListOpt('segment_range',
                help="Vlan/segment range to use, specified as from:to. Can have multiple entries separated by ','"),
]

fixed_binding_opts = [
    cfg.StrOpt('description'),
    cfg.ListOpt('bindings', required=True,
                help="List of bindings that are bound to an EPG (VPCs/PCs)"),
    cfg.ListOpt('physical_domain',
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
    cfg.ListOpt('consumed_contracts',
                help="Consumed contracts for this scope. Contracts from the contracts option will be added as well."),
    cfg.ListOpt('provided_contracts',
                help="Provided contracts for this scope. Contracts from the contracts option will be added as well."),
    cfg.StrOpt('vrf', required=True,
               help="VRF name of this address scope"),
]

cli_opts = [
    cfg.StrOpt('network-id',
               help="Network ID used in consistency check"),
    cfg.StrOpt('mode', default='check',
               help="Check mode - either read only check or sync to fix inconsistencies")
]

cfg.CONF.register_opts(aci_opts, "ml2_aci")
# cfg.CONF.register_cli_opts(cli_opts)
CONF = cfg.CONF
# CONF()


class ACIConfig:
    def __init__(self):
        self.reset_config()

    def reset_config(self):
        self._hostgroups = {}
        self._fixed_bindings = {}
        self._address_scopes = {}

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

    def _parse_config(self, section_prefix, opts, to_dict=False):
        data = {}
        section_prefix = "{}:".format(section_prefix)
        for section in cfg.CONF.list_all_sections():
            if not section.startswith(section_prefix):
                continue
            cfg.CONF.register_opts(opts, section)
            # FIXME: maybe we could use the parsed version in the future, would be nice
            sec_cfg = getattr(cfg.CONF, section)
            if to_dict:
                sec_cfg = dict(sec_cfg)
            key = section[len(section_prefix):]
            data[key] = sec_cfg
            # FIXME: sanity checks

        return data

    def _parse_hostgroups(self):
        # FIXME: maybe we could use the parsed version in the future, would be nice
        # FIXME: sanity checks
        self._hostgroups = self._parse_config("aci-hostgroup", hostgroup_opts, to_dict=True)

        for hostgroup in self._hostgroups.values():
            segment_ranges = hostgroup['segment_range']
            full_range = set()
            for segment_range in segment_ranges:
                seg_from, seg_to = segment_range.split(":")
                full_range |= set(range(int(seg_from), int(seg_to) + 1))
            hostgroup['segment_range'] = full_range

    def _parse_fixed_bindings(self):
        self._fixed_bindings = self._parse_config("fixed-binding", fixed_binding_opts, to_dict=True)

    def _parse_address_scopes(self):
        self._address_scopes = self._parse_config("address-scope", address_scope_opts, to_dict=True)

        for scope in self._address_scopes:
            if scope.get('contracts'):
                contracts = ast.literal_eval(scope.get('contracts'))
                scope['consumed_contracts'].extend(contracts['consumed'])
                scope['provided_contracts'].extend(contracts['provided'])

    def get_hostgroup_by_host(self, host_id):
        for hostgroup, hostgroup_config in self.hostgroups.items():
            if host_id in hostgroup_config['hosts']:
                return hostgroup, hostgroup_config
        return host_id, None

    def get_fixed_binding_by_tag(self, tag):
        return self.fixed_bindings.get(tag)

    def get_address_scope_by_name(self, name):
        return self.address_scopes.get(name)


ACI_CONFIG = ACIConfig()
