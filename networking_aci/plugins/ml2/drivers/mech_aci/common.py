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
import ipaddress
import json
import threading

from neutron_lib import constants as nl_const
from neutron_lib.exceptions import address_scope as ext_address_scope
from neutron.db import address_scope_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import models_v2
from neutron.db.models import address_scope as ascope_models
from neutron.db.models import agent as agent_models
from neutron.db.models import external_net as extnet_models
from neutron.db.models import l3 as l3_models
from neutron.db.models import l3agent as l3agent_models
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

    def get_az_aware_external_subnets(self, context):
        query = context.session.query(models_v2.Subnet.id, models_v2.Subnet.cidr,
                                      models_v2.Network.availability_zone_hints, ascope_models.AddressScope.name)
        query = query.join(models_v2.Network,
                           models_v2.Network.id == models_v2.Subnet.network_id)
        query = query.join(extnet_models.ExternalNetwork,
                           models_v2.Network.id == extnet_models.ExternalNetwork.network_id)
        query = query.join(models_v2.SubnetPool,
                           models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id)
        query = query.join(ascope_models.AddressScope,
                           models_v2.SubnetPool.address_scope_id == ascope_models.AddressScope.id)
        query = query.filter(models_v2.Network.availability_zone_hints != "[]")

        subnets = []
        for entry in query.all():
            try:
                azs = json.loads(entry.availability_zone_hints)
            except json.JSONDecodeError:
                continue
            if len(azs) != 1:
                continue
            subnets.append({"subnet_id": entry.id, "cidr": entry.cidr, "az": azs[0], "address_scope_name": entry.name})

        return subnets

    def get_external_subnet_nullroute_mapping(self, context, level=1):
        # 1. fetch all subnets where their CIDR doesn't completely overlap with a subnetpool prefix
        #   * every external subnet which doesn't have a matching prefix gets
        #   * we could filter here already for non-overlappings, but it shouldn't make much of a difference
        #     performance-wise and is a bit more complicated. The query could look like this:
        #     SELECT id, name, cidr, subnetpool_id FROM subnets s
        #     INNER JOIN externalnetworks extnet ON s.network_id = extnet.network_id
        #     WHERE s.subnetpool_id IS NOT NULL AND
        #     (SELECT COUNT(*) FROM subnetpoolprefixes snp
        #      WHERE subnetpool_id = s.subnetpool_id AND snp.cidr = s.cidr) = 0;
        query = context.session.query(models_v2.Subnet.id, models_v2.Subnet.cidr,
                                      models_v2.SubnetPool.id, ascope_models.AddressScope.name)
        query = query.join(extnet_models.ExternalNetwork,
                           models_v2.Subnet.network_id == extnet_models.ExternalNetwork.network_id)
        query = query.join(models_v2.SubnetPool,
                           models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id)
        query = query.join(ascope_models.AddressScope,
                           models_v2.SubnetPool.address_scope_id == ascope_models.AddressScope.id)
        all_subnets = list(query.all())

        # 2. fetch all subnetpools + their CIDRs and find out which is the longest matching prefix for each pool
        subnetpool_ids = {s[2] for s in all_subnets}
        query = context.session.query(models_v2.SubnetPool.id, models_v2.SubnetPoolPrefix.cidr)

        query = query.join(models_v2.SubnetPoolPrefix,
                           models_v2.SubnetPool.id == models_v2.SubnetPoolPrefix.subnetpool_id)

        query = query.filter(models_v2.SubnetPool.id.in_(subnetpool_ids))
        query = query.order_by(models_v2.SubnetPool.id, models_v2.SubnetPoolPrefix.cidr)
        subnetpools = {}
        for snp_id, cidr in query.all():
            subnetpools.setdefault(snp_id, set()).add(cidr)

        # 3. filter out all subnets where the subnet cidr is also a subnetpool prefix
        subnets = {}
        for subnet_id, cidr, subnetpool_id, ascope_name in all_subnets:
            if subnetpool_id not in subnetpools:
                continue
            if cidr in subnetpools[subnetpool_id]:
                continue

            s_cidr = ipaddress.ip_network(cidr)
            for snp_cidr in subnetpools[subnetpool_id]:
                if s_cidr.subnet_of(ipaddress.ip_network(snp_cidr)):
                    break
            else:
                LOG.warning("Subnet %s CIDR %s did not find any matching CIDR in subnetpool %s, options were %s",
                            subnet_id, cidr, subnetpool_id, subnetpools[subnetpool_id])
                continue
            subnets[subnet_id] = {
                'cidr': cidr,
                'parent_cidr': snp_cidr,
                'hosts': set(),
                'address_scope_name': ascope_name,
            }

        # 4. find all binding hosts that are currently in that subnet
        # SELECT pb.host, pb.profile FROM ml2_port_bindings pb
        #   JOIN ml2_port_binding_levels pbl ON pb.port_id = pbl.port_id AND pbl.level = 1
        #   JOIN ipallocations ia ON ia.port_id = pb.port_id WHERE ia.subnet_id IN (...);

        query = context.session.query(ml2_models.PortBinding.host, ml2_models.PortBinding.profile,
                                      models_v2.IPAllocation.subnet_id)
        # PortBindingLevels are joined in to make sure the port is bound somewhere
        query = query.join(ml2_models.PortBindingLevel,
                           sa.and_(ml2_models.PortBinding.port_id == ml2_models.PortBindingLevel.port_id,
                                   ml2_models.PortBinding.host == ml2_models.PortBindingLevel.host))
        query = query.join(models_v2.IPAllocation,
                           ml2_models.PortBinding.port_id == models_v2.IPAllocation.port_id)
        query = query.filter(models_v2.IPAllocation.subnet_id.in_(list(subnets)))
        if level is not None:
            query = query.filter(ml2_models.PortBindingLevel.level == level)
        # we only need to return subnets that are in use by a router as these are the
        # subnets that are "really in use" - the rest can be ignored (or so say the requirements)
        query = query.join(models_v2.Port,
                           models_v2.Port.id == ml2_models.PortBinding.port_id)
        query = query.filter(models_v2.Port.device_owner == nl_const.DEVICE_OWNER_ROUTER_GW)

        for entry in query.all():
            host = get_host_from_profile(entry.profile, entry.host)
            subnets[entry.subnet_id]['hosts'].add(host)

        # 5. find all floating ips that are in these subnets and bound to a floating port
        #  SELECT DISTINCT a.host, ipa.subnet_id
        #  FROM floatingips fips
        #  INNER JOIN ipallocations ipa ON ipa.port_id = fips.floating_port_id
        #  INNER JOIN routerl3agentbindings rabs ON rabs.router_id = fips.router_id
        #  INNER JOIN agents a ON a.id = rabs.l3_agent_id
        #  WHERE fips.status = "ACTIVE"
        #          AND ipa.subnet_id IN (...);

        query = context.session.query(agent_models.Agent.host, models_v2.IPAllocation.subnet_id)
        query = query.join(l3_models.FloatingIP,
                           l3_models.FloatingIP.floating_port_id == models_v2.IPAllocation.port_id)
        query = query.join(l3agent_models.RouterL3AgentBinding,
                           l3_models.FloatingIP.router_id == l3agent_models.RouterL3AgentBinding.router_id)
        query = query.filter(l3agent_models.RouterL3AgentBinding.l3_agent_id == agent_models.Agent.id)
        query = query.filter(l3_models.FloatingIP.status == nl_const.FLOATINGIP_STATUS_ACTIVE)
        query = query.filter(models_v2.IPAllocation.subnet_id.in_(list(subnets)))
        query = query.distinct()

        for entry in query.all():
            subnets[entry.subnet_id]['hosts'].add(entry.host)

        return subnets


class LockedDirtyCache:
    def __init__(self):
        self._cache = set()
        self._lock = threading.Lock()

    def clear(self):
        with self._lock:
            self._cache.clear()

    def mark_dirty(self, item):
        with self._lock:
            self._cache.add(item)

    def remove(self, network_id):
        with self._lock:
            try:
                self._cache.remove(network_id)
            except KeyError:
                pass

    def __contains__(self, item):
        with self._lock:
            return item in self._cache


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
