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
import json

from neutron_lib.exceptions import address_scope as ext_address_scope
from neutron.db import address_scope_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import models_v2
from neutron.db.models import segment as segment_models
from neutron.db import segments_db as ml2_db
from neutron.plugins.ml2 import models as ml2_models
import neutron.services.trunk.models as trunk_models
from oslo_log import log as logging
import sqlalchemy as sa

from networking_aci.db.models import HostgroupModeModel
from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const


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

    def get_hosts_on_network(self, context, network_id, level=None, with_segment=False, transit_hostgroups=None):
        """Get all binding hosts (from host or binding_profile) present on a network"""
        fields = [ml2_models.PortBinding.host, ml2_models.PortBinding.profile]
        if with_segment:
            fields.append(ml2_models.PortBindingLevel.segment_id)
        query = context.session.query(*fields)
        query = query.join(ml2_models.PortBindingLevel,
                           sa.and_(ml2_models.PortBinding.port_id == ml2_models.PortBindingLevel.port_id,
                                   ml2_models.PortBinding.host == ml2_models.PortBindingLevel.host))
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

        # find all segments in this network that belong to a transit (unbound segments)
        if transit_hostgroups:
            transit_physnets = [hg['physical_network'] for hg in transit_hostgroups]
            query = context.session.query(segment_models.NetworkSegment.id,
                                          segment_models.NetworkSegment.physical_network)
            query = query.filter_by(network_type='vlan', network_id=network_id)
            query = query.filter(segment_models.NetworkSegment.physical_network.in_(transit_physnets))
            for entry in query.all():
                # find host(group) of physnet
                for hg in transit_hostgroups:
                    if entry.physical_network == hg['physical_network']:
                        break
                if with_segment:
                    hosts.add((hg['hosts'][0], entry.id))
                else:
                    hosts.add(hg['hosts'][0])

        return hosts

    def get_hosts_on_physnet(self, context, physical_network, level=None, with_segment=False, with_segmentation=False):
        """Get all binding hosts (from host or binding_profile) present on a network

        By default a set of all hosts is returned. If with_segment or with_segmentation is specified then a set of
        tuples is returned, containing the host, segment id (if requested) and segmentation id (if requested).
        """
        fields = [ml2_models.PortBinding.host, ml2_models.PortBinding.profile]
        if with_segment:
            fields.append(ml2_models.PortBindingLevel.segment_id)
        if with_segmentation:
            fields.append(segment_models.NetworkSegment.segmentation_id)
        query = context.session.query(*fields)
        query = query.join(ml2_models.PortBindingLevel,
                           ml2_models.PortBinding.port_id == ml2_models.PortBindingLevel.port_id)
        query = query.join(segment_models.NetworkSegment,
                           ml2_models.PortBindingLevel.segment_id == segment_models.NetworkSegment.id)
        query = query.filter(segment_models.NetworkSegment.physical_network == physical_network)
        if level is not None:
            query = query.filter(ml2_models.PortBindingLevel.level == level)

        hosts = set()
        for entry in query.all():
            host = get_host_from_profile(entry.profile, entry.host)
            if with_segment or with_segmentation:
                row = [host]
                if with_segment:
                    row.append(entry.segment_id)
                if with_segmentation:
                    row.append(entry.segmentation_id)
                hosts.add(tuple(row))
            else:
                hosts.add(host)
        return hosts

    def get_segment_ids_by_physnet(self, context, physical_network, fuzzy_match=False):
        query = context.session.query(segment_models.NetworkSegment.id)
        if fuzzy_match:
            query = query.filter(segment_models.NetworkSegment.physical_network.like(physical_network))
        else:
            query = query.filter(segment_models.NetworkSegment.physical_network == physical_network)
        return [seg.id for seg in query.all()]

    def get_ports_on_network_by_physnet_prefix(self, context, network_id, physical_network_prefix):
        # get all ports for a network that are on a segment with a physnet prefix
        fields = [
            models_v2.Port.id, models_v2.Port.project_id,
            segment_models.NetworkSegment.id, segment_models.NetworkSegment.physical_network
        ]
        query = context.session.query(*fields)
        query = query.filter(models_v2.Port.network_id == network_id)
        query = query.join(ml2_models.PortBindingLevel, ml2_models.PortBindingLevel.port_id == models_v2.Port.id)
        query = query.join(segment_models.NetworkSegment,
                           ml2_models.PortBindingLevel.segment_id == segment_models.NetworkSegment.id)
        query = query.filter(segment_models.NetworkSegment.physical_network.like('{}%'.format(physical_network_prefix)))

        result = []
        for entry in query.all():
            result.append({
                'port_id': entry[0],
                'project_id': entry[1],
                'segment_id': entry[2],
                'physical_network': entry[3],
            })

        return result

    def get_bound_projects_by_physnet_prefix(self, context, physical_network_prefix):
        # get all projects that have a port bound to a segment with this prefix
        query = context.session.query(models_v2.Port.project_id)
        query = query.join(ml2_models.PortBindingLevel, ml2_models.PortBindingLevel.port_id == models_v2.Port.id)
        query = query.join(segment_models.NetworkSegment,
                           ml2_models.PortBindingLevel.segment_id == segment_models.NetworkSegment.id)
        query = query.filter(segment_models.NetworkSegment.physical_network.like('{}%'.format(physical_network_prefix)))
        query = query.distinct()

        return [entry.project_id for entry in query.all()]

    def get_trunk_vlan_usage_on_project(self, context, project_id, segmentation_id=None):
        # return vlan --> networks mapping for aci trunk ports inside a project
        query = context.session.query(models_v2.Port.network_id, trunk_models.SubPort.segmentation_id)
        query = query.filter(models_v2.Port.project_id == project_id)
        query = query.join(trunk_models.SubPort, trunk_models.SubPort.port_id == models_v2.Port.id)
        query = query.join(ml2_models.PortBinding, ml2_models.PortBinding.port_id == models_v2.Port.id)
        query = query.filter(ml2_models.PortBinding.vif_type == aci_const.VIF_TYPE_ACI)
        if segmentation_id:
            query = query.filter(trunk_models.SubPort.segmentation_id == segmentation_id)
        query = query.distinct()

        # we only expect there to be one entry per segmentation id, but keep a list in case something goes wrong
        vlan_map = {}
        for entry in query.all():
            vlan_map.setdefault(entry[0], set()).add(entry[1])

        return vlan_map


def get_segments(context, network_id):
    return ml2_db.get_network_segments(context, network_id, filter_dynamic=None)


def get_switch_from_local_link(binding_profile):
    if binding_profile:
        if not isinstance(binding_profile, dict):
            try:
                binding_profile = json.loads(binding_profile)
            except ValueError:
                LOG.info("binding Profile %s cannot be parsed", binding_profile)
                return

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
            LOG.debug("Local information %s contains no binding host / switch info in profile %s, ignoring it",
                      lli, binding_profile)


def get_host_from_profile(binding_profile, host):
    """Get switch from binding_profile, if present, else return host"""
    switch = get_switch_from_local_link(binding_profile)
    if switch:
        return switch
    return host


def get_set_from_ranges(ranges):
    """Convert [(a, b), (c, d), ...] to a set of all numbers in these ranges (inclusive)"""
    result = set()
    for range_from, range_to in ranges:
        result |= set(range(range_from, range_to + 1))

    return result
