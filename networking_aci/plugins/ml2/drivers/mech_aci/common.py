# Copyright 2016 SAP SE
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

from neutron_lib.exceptions import address_scope as ext_address_scope
from neutron.db import address_scope_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import models_v2
from neutron.db.models import segment as segment_models
from neutron.db import segments_db as ml2_db
from neutron.plugins.ml2 import models as ml2_models
from oslo_log import log as logging

from networking_aci.db.models import HostgroupModeModel


LOG = logging.getLogger(__name__)


class DBPlugin(db_base_plugin_v2.NeutronDbPluginV2,
               address_scope_db.AddressScopeDbMixin,
               external_net_db.External_net_db_mixin):

    def __init__(self):
        pass

    def get_ports_with_binding(self, context, network_id):
        with context.session.begin(subtransactions=True):
            query = context.session.query(models_v2.Port)
            query1 = query.join(ml2_models.PortBinding)
            bind_ports = query1.filter(models_v2.Port.network_id == network_id)

            return bind_ports

    def get_network_ids(self, context):
        result = []
        query = context.session.query(models_v2.Network.id).order_by(models_v2.Network.id)
        for network in query:
            result.append(network.id)

        return result

    def get_address_scope_name(self, context, subnet_pool_id):
        pool = self.get_subnetpool(context, subnet_pool_id)

        if not pool:
            LOG.warn("Subnet pool {} does not exist".format(subnet_pool_id))
            return

        try:
            scope = self.get_address_scope(context, pool['address_scope_id'])
        except ext_address_scope.AddressScopeNotFound:
            LOG.warn("Address scope {} does could not be found, check ACI config for correct configuration"
                     .format(['pool.address_scope_id']))
            return

        # This may not be needed no address scope not found is caught
        if not scope:
            LOG.warn("Address scope {} does not exist, check ACI config for correct configuration"
                     .format(['pool.address_scope_id']))
            return

        return scope.get('name')

    def get_hostgroup_modes(self, context, hostgroup_names=None):
        hg_modes = {}
        query = context.session.query(HostgroupModeModel)
        if hostgroup_names:
            query = query.filter(HostgroupModeModel.hostgroup.in_(hostgroup_names))
        for entry in query.all():
            hg_modes[entry.hostgroup] = entry.mode
        return hg_modes

    def get_hostgroup_mode(self, context, hostgroup_name):
        hg_modes = self.get_hostgroup_modes(context, [hostgroup_name])
        return hg_modes.get(hostgroup_name)

    def set_hostgroup_mode(self, context, hostgroup_name, hostgroup_mode):
        with context.session.begin(subtransactions=True):
            query = context.session.query(HostgroupModeModel).filter(HostgroupModeModel.hostgroup == hostgroup_name)
            hg = query.first()
            if not hg:
                return False
            hg.mode = hostgroup_mode
        return True

    def get_hosts_on_segment(self, context, segment_id, level=None):
        """Get all binding hosts (from host or binding_profile) present on a segment"""
        # get all ports bound to segment, extract their host
        query = context.session.query(ml2_models.PortBinding.host, ml2_models.PortBinding.profile)
        query = query.join(ml2_models.PortBindingLevel,
                           ml2_models.PortBinding.port_id == ml2_models.PortBindingLevel.port_id)
        query = query.filter(ml2_models.PortBindingLevel.segment_id == segment_id)
        if level is not None:
            query = query.filter(ml2_models.PortBindingLevel.level == level)

        hosts = set()
        for entry in query.all():
            host = get_host_from_profile(entry.profile, entry.host)
            hosts.add(host)
        return hosts

    def get_hosts_on_network(self, context, network_id, level=None, with_segment=False):
        """Get all binding hosts (from host or binding_profile) present on a network"""
        fields = [ml2_models.PortBinding.host, ml2_models.PortBinding.profile]
        if with_segment:
            fields.append(ml2_models.PortBindingLevel.segment_id)
        query = context.session.query(*fields)
        query = query.join(ml2_models.PortBindingLevel,
                           ml2_models.PortBinding.port_id == ml2_models.PortBindingLevel.port_id)
        query = query.join(segment_models.NetworkSegment,
                           ml2_models.PortBindingLevel.segment_id == segment_models.NetworkSegment.id)
        query = query.filter(segment_models.NetworkSegment.network_id == network_id)
        if level is not None:
            query = query.filter(ml2_models.PortBindingLevel.level == level)

        hosts = set()
        for entry in query.all():
            host = get_host_from_profile(entry.profile, entry.host)
            if with_segment:
                hosts.add((host, entry.segment_id))
            else:
                hosts.add(host)
        return hosts

    def get_segment_ids_by_physnet(self, context, physical_network):
        query = context.session.query(segment_models.NetworkSegment.id)
        query = query.filter(segment_models.NetworkSegment.physical_network == physical_network)
        return [seg.id for seg in query.all()]


def get_segments(context, network_id):
    return ml2_db.get_network_segments(context, network_id)


def get_switch_from_local_link(binding_profile):
    if binding_profile:
        try:
            if not isinstance(binding_profile, dict):
                binding_profile = ast.literal_eval(binding_profile)

            lli = binding_profile.get('local_link_information')
            # TODO validate assumption that we have 1 lli in list.
            if lli and lli[0] and isinstance(lli[0], dict):
                switch = lli[0].get('switch_info', None) or lli[0].get('switch_id', None)
                if switch:
                    LOG.info("Using link local information for binding host %s", switch)
                    return switch
                else:
                    LOG.error("Cannot determine switch for local link info %s in binding profile %s.",
                              lli[0], binding_profile)
            else:
                LOG.error("Local information %s is invalid in binding profile %s.",
                          lli, binding_profile)
        except ValueError:
            LOG.info("binding Profile %s cannot be parsed", binding_profile)


def get_host_from_profile(binding_profile, host):
    """Get switch from binding_profile, if present, else return host"""
    switch = get_switch_from_local_link(binding_profile)
    if switch:
        return switch
    return host


def get_set_from_ranges(ranges):
    """Convert [(a, b), (c, d), ...] to a set of all numbers in these ranges"""
    result = set()
    for range_from, range_to in ranges:
        result |= set(range(range_from, range_to + 1))

    return result
