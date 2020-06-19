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

    cfg.StrOpt('resource_prefix',
               default='openstack',
               help="Prefix baremetal resources (and others in the future) with this prefix"),
    cfg.StrOpt('default_aep',
               default=None,
               help="Default AEP, if none is defined in hostgroup"),
    cfg.StrOpt('default_lacp_policy',
               default=None,
               help="Default LACP policy to use. Set to empty string to clear it."),
    cfg.StrOpt('baremetal_lacp_policy',
               default=None,
               help="Baremetal LACP policy to use. Set to empty string to clear it."),
    cfg.StrOpt('default_mcp_policy',
               default=None,
               help="Default MCP policy to use. Set to empty string to clear it."),
    cfg.StrOpt('baremetal_mcp_policy',
               default=None,
               help="Baremetal MCP policy to use. Set to empty string to clear it."),
    cfg.StrOpt('default_l2iface_policy',
               default=None,
               help="Default L2 interface policy to use. Set to empty string to clear it."),
    cfg.StrOpt('baremetal_l2iface_policy',
               default=None,
               help="Baremetal L2 interface policy to use. Set to empty string to clear it."),
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


def _get_specific_config(prefix):
    """retrieve config in the format [<label>:<key>]."""
    conf_dict = {}
    multi_parser = cfg.MultiConfigParser()
    multi_parser.read(cfg.CONF.config_file)
    for parsed_file in multi_parser.parsed:
        for parsed_item in parsed_file.keys():
            if parsed_item.startswith(prefix):
                label, key = parsed_item.split(':')
                if label.lower() == prefix:
                    conf_dict[key] = parsed_file[parsed_item].items()
    return conf_dict


def create_fixed_bindings_dictionary():
    fixed_bindings_dict = {}
    conf = _get_specific_config('fixed-binding')
    for network_tag in conf:
        fixed_bindings_dict[network_tag] = {
            'bm_mode': False,
        }
        for key, value in conf[network_tag]:
            if key in ('bindings', 'physical_domain'):
                fixed_bindings_dict[network_tag][key] = value[0].split(",")
            else:
                fixed_bindings_dict[network_tag][key] = value[0]

    return fixed_bindings_dict


def create_addressscope_dictionary():
    scope_dict = {}
    conf = _get_specific_config('address-scope')
    for scope_id in conf:
        scope_dict[scope_id] = {}
        for key, value in conf[scope_id]:
            scope_dict[scope_id][key] = value[0]

    return scope_dict


def create_hostgroup_dictionary():
    host_dict = {}
    conf = _get_specific_config('aci-hostgroup')
    for host in conf:
        d = {
            'bm_mode': False,
        }
        for key, value in conf[host]:
            if key in ('bindings', 'hosts', 'physical_domain'):
                d[key] = value[0].split(",")
            elif key in ('bm_mode',):
                d[key] = value[0].lower() in ('yes', 'true')
            else:
                d[key] = value[0]

        if d['bm_mode']:
            resource_name = "{}-{}".format(CONF.ml2_aci.resource_prefix, host)
            # override physdom with generated name
            d['physical_domain'] = [resource_name]
            d['resource_name'] = resource_name

        host_dict[host] = d

    return host_dict
