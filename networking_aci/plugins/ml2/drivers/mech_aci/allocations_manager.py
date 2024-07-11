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
from itertools import groupby
from operator import itemgetter
import os
import random
import time

from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron.db.models import segment as ml2_models
from neutron.plugins.ml2 import models
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import uuidutils
import sqlalchemy as sa

from networking_aci._i18n import _LI
from networking_aci.db.models import AllocationsModel, HostgroupModeModel
from networking_aci.plugins.ml2.drivers.mech_aci.config import ACI_CONFIG
from networking_aci.plugins.ml2.drivers.mech_aci import common
from networking_aci.plugins.ml2.drivers.mech_aci.exceptions import AccessSegmentationIdAllocationPoolExhausted
from networking_aci.plugins.ml2.drivers.mech_aci.exceptions import HostAlreadyHasAccessBinding
from networking_aci.plugins.ml2.drivers.mech_aci.exceptions import NetworkHasBoundTrunkPorts
from networking_aci.plugins.ml2.drivers.mech_aci.exceptions import NetworkUsesDifferentTrunkId
from networking_aci.plugins.ml2.drivers.mech_aci.exceptions import NoAllocationFoundInMaximumAllowedAttempts
from networking_aci.plugins.ml2.drivers.mech_aci.exceptions import TrunkSegmentIdAlreadyInUse

LOG = log.getLogger(__name__)
CONF = cfg.CONF


class AllocationsManager(object):
    def __init__(self, db):
        self.db = db
        self._sync_db_guarded()

    def initialize(self):
        self._sync_db_guarded()
        LOG.info(_LI("AllocationsManager initialization complete"))

    def _sync_db_guarded(self):
        if not CONF.ml2_aci.sync_allocations_done_file_path:
            # sync db unconditionally
            self._sync_db()
            return

        # first process/thread gathering the lock syncs the table
        with lockutils.external_lock("sync-allocations-guard", lock_file_prefix="networking-aci"):
            try:
                synced_by = open(CONF.ml2_aci.sync_allocations_done_file_path, "r").read()
                LOG.info("Not syncing in this thread, already synced by PID %s", synced_by)
            except FileNotFoundError:
                self._sync_db()
                with open(CONF.ml2_aci.sync_allocations_done_file_path, "w") as f:
                    f.write(str(os.getpid()))
                LOG.info("Successfully synced db")

    def _sync_db(self):
        if CONF.ml2_aci.sync_allocations:
            try:
                self._sync_allocations()
            except Exception:
                LOG.exception("__init__ sync alloc")
                raise
        self._sync_hostgroup_modes()

    def network_type_not_supported(self, network, host_id, level, segment_type, segment_physnet):
        LOG.error("Network type " + network["provider:network_type"] + " is not supported in the ACI driver")

    def allocate_segment(self, network, host_id, level, host_config):
        network_type = self._get_provider_attribute(network, "provider:network_type")
        allocate = getattr(self, "_allocate_" + network_type + "_segment", "network_type_not_supported")
        return allocate(network, host_id, level, host_config)

    def _get_provider_attribute(self, network, key):
        # Neutron kindly has two mechanism to get the provider attributes, depending on whether segments exist
        result = network.get(key, None)

        if not result:
            LOG.info(network)
            segments = network.get('segments', [])
            segment = segments[0]
            result = segment.get(key)

        return result

    def _allocate_vlan_segment(self, network, host_id, level, host_config):
        segment_type = host_config.get('segment_type', 'vlan')
        segment_physnet = host_config.get('physical_network', None)

        session = db_api.get_writer_session()
        segmentation_id = self._get_provider_attribute(network, "provider:segmentation_id")
        network_id = network["id"]
        segment = session.query(ml2_models.NetworkSegment).filter_by(segmentation_id=segmentation_id,
                                                                     physical_network=segment_physnet,
                                                                     network_type=segment_type,
                                                                     network_id=network_id,
                                                                     level=level).first()

        if not segment:
            with session.begin(subtransactions=True):
                segment = ml2_models.NetworkSegment(
                    id=uuidutils.generate_uuid(),
                    network_id=network_id,
                    network_type=segment_type,
                    physical_network=segment_physnet,
                    segmentation_id=segmentation_id,
                    segment_index=level,
                    is_dynamic=False
                )
                session.add(segment)

        return AllocationsModel(host=host_id, level=level, segment_type=segment_type, segmentation_id=segmentation_id,
                                segment_id=segment.id, network_id=network_id)

    @db_api.retry_db_errors
    def _allocate_vxlan_segment(self, network, host_id, level, host_config):
        LOG.info(_LI("Allocating segment for network type VXLAN"))
        segment_type = host_config.get('segment_type', 'vlan')
        segment_physnet = host_config.get('physical_network', None)
        network_id = network['id']

        session = db_api.get_writer_session()
        with db_api.exc_to_retry(sa.exc.IntegrityError), session.begin(subtransactions=True):
            LOG.debug("Searching for available allocation for host id %(host_id)s "
                      "segment_type %(segment_type)s network_id %(network_id)s segment_physnet %(segment_physnet)s",
                      {"host_id": host_id, "segment_type": segment_type, "segment_physnet": segment_physnet,
                       "network_id": network_id}
                      )

            alloc = session.query(AllocationsModel).filter_by(host=host_id, level=level, segment_type=segment_type,
                                                              network_id=network_id).first()
            if alloc and alloc.segment_id:
                return alloc

            # we regard a segment as unallocated if its segment_id is None
            select = (session.query(AllocationsModel).
                      filter_by(host=host_id, level=level, segment_type=segment_type, segment_id=None))

            # Selected segment can be allocated before update by someone else,
            allocs = select.limit(100).all()

            if not allocs:
                LOG.error("No Allocation available")
                # No resource available
                return

            alloc = random.choice(allocs)

            segment = ml2_models.NetworkSegment(
                id=uuidutils.generate_uuid(),
                network_id=network_id,
                network_type=alloc.segment_type,
                physical_network=segment_physnet,
                segmentation_id=alloc.segmentation_id,
                segment_index=level,
                is_dynamic=False
            )
            session.add(segment)

            raw_segment = {
                'host': alloc.host,
                'level': alloc.level,
                'segment_type': alloc.segment_type,
                'segmentation_id': alloc.segmentation_id,
            }
            LOG.debug("%(type)s segment allocated from pool with %(segment)s ",
                      {"type": alloc.segment_type, "segment": alloc.segmentation_id})

            count = (session.query(AllocationsModel).
                     filter_by(segment_id=None, **raw_segment).
                     update({"network_id": network_id, 'segment_id': segment.id}))

            if count:
                LOG.debug("%(type)s segment allocated from pool success with %(segment)s ",
                          {"type": alloc.segment_type, "segment": alloc.segment_id})
                return alloc

            # Segment allocated since select
            LOG.debug("Allocate %(type)s segment from pool failed with segment %(segment)s",
                      {"type": alloc.segment_type, "segment": alloc.segment_id, "level": alloc.level})

            raise db_exc.RetryRequest(NoAllocationFoundInMaximumAllowedAttempts())

    def release_segment(self, network, host_config, level, segment):
        LOG.info("Releasing segment %(segment)s", {"segment": segment})
        network_type = self._get_provider_attribute(network, "provider:network_type")
        release = getattr(self, "_release_" + network_type + "_segment", "network_type_not_supported")

        return release(network, host_config, level, segment)

    def _release_vlan_segment(self, network, host_config, level, segment):
        LOG.debug("Checking release for segment %(segment)s with top level VLAN segment", {"segment": segment})

        session = db_api.get_writer_session()
        with session.begin(subtransactions=True):
            # Delete the network segment
            query = (session.query(ml2_models.NetworkSegment).
                     filter_by(id=segment['id'], network_id=network['id'], network_type=segment['network_type'],
                               segmentation_id=segment['segmentation_id'], segment_index=level))
            query.delete()

    def _release_vxlan_segment(self, network, host_config, level, segment):
        LOG.debug("Checking release for segment %(segment)s with top level VXLAN segment", {"segment": segment})
        segment_type = segment['network_type']
        segment_id = segment['id']
        segmentation_id = segment['segmentation_id']
        network_id = network['id']

        session = db_api.get_writer_session()
        with session.begin(subtransactions=True):
            select = (session.query(models.PortBindingLevel).
                      filter_by(segment_id=segment_id, level=level))

            if select.count() > 0:
                LOG.debug("Segment %s still has ports on it", segment_id)
                return False
            LOG.info("Segment %s is empty and can be released", segment_id)

            segmentation_ids = self._segmentation_ids(host_config)
            inside = segmentation_id in segmentation_ids
            query = (session.query(AllocationsModel).
                     filter_by(network_id=network_id, level=level, segment_type=segment_type,
                               segment_id=segment_id))
            if inside:
                query.update({"network_id": None, "segment_id": None})
            else:
                query.delete()

            # Delete the network segment
            query = (session.query(ml2_models.NetworkSegment).
                     filter_by(id=segment_id, network_id=network_id, network_type=segment_type,
                               segmentation_id=segmentation_id, segment_index=level))

            query.delete()

            return True

    @db_api.retry_db_errors
    def allocate_baremetal_segment(self, context, network, hostgroup, level, segmentation_id):
        """Allocate a "baremetal segment" (with or without pre-specified id)

        Baremetal segments are dynamically allocated based on their physnet (physnet name will be
        $bm_prefix-$project_id). We have two cases:

        Access port: segmentation_id is None, we select it from a predefined pool tied to the hostgroup.
                     If the (network, physnet) combination already has a segment, return it.
                     For an existing segment check that the segmentation id is from the access segmentation
                     pool, if it is not raise an error.
                     If not, find all ids of existing segments on this physnet and remove the ids
                     from the pool, then select a free one

        Trunk port: segmentation_id is predefined by user.
                    Check if (network, physnet) already has a segment - if it has, raise if the
                    VLAN id is different, else return the segment.
                    Check if segmentation_id is already used (existing segment for physnet+id).
                    If no segment exists, create one.

        This means projects will need to provide strong VLAN consistency. ACI-Baremetal hosts have
        to be bound to the network in the same way: Either in access mode or in trunk mode with the
        same segmentation id. Having one host as access and a second one as trunk vlan 1000 is not
        supported, meaning there can only be one segmentation id per (physnet, network) combination.

        We don't use ACI allocation entries for such segments, as the physical_network attribute is
        dynamic. No extra release method is required, as it works the same way as with
        _release_vxlan_segment().
        """
        is_access = segmentation_id is None
        session = context.session
        segment_type = hostgroup.get('segment_type', 'vlan')
        segment_physnet = hostgroup.get('physical_network')
        network_id = network['id']
        access_id_pool = common.get_set_from_ranges(hostgroup['baremetal_access_vlan_ranges'])

        with db_api.exc_to_retry(sa.exc.IntegrityError), session.begin(subtransactions=True):
            # 1. check if segment exists
            existing_segments = (session.query(ml2_models.NetworkSegment)
                                 .filter_by(network_id=network_id, physical_network=segment_physnet,
                                            segment_index=level, network_type=segment_type)
                                 .all())

            if existing_segments:
                if len(existing_segments) > 1:
                    LOG.error("Multiple segments exists for network %s physical network %s - Segments %s with ids %s",
                              network_id, segment_physnet, ", ".join(n.id for n in existing_segments),
                              ", ".join(n.segmentation_id for n in existing_segments))
                segment = existing_segments[0]
                if is_access:
                    # make sure the segment id is from the right pool
                    if segment.segmentation_id not in access_id_pool:
                        raise NetworkHasBoundTrunkPorts(network_id=network_id, segment_id=segment.id,
                                                        segmentation_id=segment.segmentation_id)
                else:
                    # make sure the segment id matches, else it's an affinity error
                    if segment.segmentation_id != segmentation_id:
                        raise NetworkUsesDifferentTrunkId(network_id=network_id,
                                                          segmentation_id=segment.segmentation_id)
                return segment

            # 2. sanity checks
            if is_access:
                # for access mode: check that no other network has bound this in host mode
                host_segments = self.db.get_hosts_on_physnet(context, segment_physnet, level=1,
                                                             with_segment=True, with_segmentation=True)
                for far_host, far_segment_id, far_segmentation_id in host_segments:
                    if far_host in hostgroup['hosts'] and far_segmentation_id in access_id_pool:
                        raise HostAlreadyHasAccessBinding(host=far_host, segmentation_id=far_segmentation_id,
                                                          segment_id=far_segment_id)
            else:
                # for trunk mode: check segmentation_id is not already in use in physnet
                existing_segments = (session.query(ml2_models.NetworkSegment)
                                     .filter_by(segmentation_id=segmentation_id, physical_network=segment_physnet,
                                                segment_index=level, network_type=segment_type)
                                     .all())
                if existing_segments:
                    raise TrunkSegmentIdAlreadyInUse(segmentation_id=segmentation_id,
                                                     segment_id=existing_segments[0].id)

            # 3. no segment exists, allocate one
            if is_access:
                # find a free vlan id from the pool
                physnet_segments = (session.query(ml2_models.NetworkSegment)
                                    .filter_by(physical_network=segment_physnet)
                                    .all())
                used_ids = set(n.segmentation_id for n in physnet_segments)
                possible_ids = access_id_pool - used_ids
                if not possible_ids:
                    raise AccessSegmentationIdAllocationPoolExhausted(hostgroup_name=hostgroup['name'],
                                                                      physical_network=segment_physnet)
                segmentation_id = random.choice(list(possible_ids))

            segment = ml2_models.NetworkSegment(
                id=uuidutils.generate_uuid(),
                network_id=network_id,
                network_type=segment_type,
                physical_network=segment_physnet,
                segmentation_id=segmentation_id,
                segment_index=level,
                is_dynamic=False
            )
            session.add(segment)

            return segment

    def _allocation_key(self, host_id, level, segment_type):
        return "{}_{}_{}".format(host_id, level, segment_type)

    @staticmethod
    def _segmentation_ids(host_config):
        return common.get_set_from_ranges(host_config['segment_range'])

    @db_api.retry_db_errors
    def _sync_allocations(self):
        LOG.info("Preparing ACI Allocations table")
        start_time = time.time()
        level = 1  # Currently only supporting one level in hierarchy
        segment_type = 'vlan'

        config_physnets = {hg['physical_network'] for hg in ACI_CONFIG.hostgroups.values()}
        ctx = context.get_admin_context()
        with db_api.CONTEXT_WRITER.using(ctx) as session:
            # fetch allocations from db
            db_allocs = session.query(AllocationsModel.host, AllocationsModel.network_id,
                                      AllocationsModel.segmentation_id)
            db_allocs = db_allocs.filter_by(level=level, segment_type=segment_type).with_for_update()
            db_allocs = db_allocs.all()

            # sort allocations into data structures
            LOG.debug("Processing allocations")
            allocations = {}  # vlan ids grouped by hostgroup/physnet name
            no_net_allocations = {}  # vland ids grouped by hostgroup/physnet that don't have a network assigned
            hosts_to_delete = set()  # orphaned hosts with deletable allocs (no network_id assigned)
            for n, db_alloc in enumerate(db_allocs):
                if db_alloc.host not in allocations:
                    if db_alloc.host not in config_physnets:
                        if db_alloc.network_id is None:
                            # at least one allocation with this host can be deleted
                            hosts_to_delete.add(db_alloc.host)
                        continue
                    allocations[db_alloc.host] = set()
                    no_net_allocations[db_alloc.host] = set()
                allocations[db_alloc.host].add(db_alloc.segmentation_id)
                if db_alloc.network_id is None:
                    no_net_allocations[db_alloc.host].add(db_alloc.segmentation_id)

            # sync existing hostgroups (remove out-of-range allocs, add new allocs)
            LOG.debug("Processing hostgroups")
            hostgroups = [hg for hg in ACI_CONFIG.hostgroups.values() if not hg['direct_mode']]
            hostgroups.sort(key=itemgetter('physical_network'))
            for hg_physnet, hg_configs in groupby(hostgroups, key=itemgetter('physical_network')):
                hg_vlans = set()
                for hg_config in hg_configs:
                    hg_vlans |= self._segmentation_ids(hg_config)

                if hg_physnet in allocations:
                    # delete extra allocs
                    out_of_range_ids = no_net_allocations[hg_physnet] - hg_vlans
                    if out_of_range_ids:
                        LOG.debug("Deleting %s out-of-range allocations with no assigned network for "
                                  "physical network %s",
                                  len(out_of_range_ids), hg_physnet)
                        # delete all extra allocations that don't have a network_id referenced
                        del_q = session.query(AllocationsModel)
                        del_q = del_q.filter_by(level=level, segment_type=segment_type, host=hg_physnet,
                                                network_id=None)
                        del_q = del_q.filter(AllocationsModel.segmentation_id.in_(out_of_range_ids))
                        del_q.delete()

                missing_ids = hg_vlans - allocations.get(hg_physnet, set())
                if missing_ids:
                    LOG.debug("Adding %s allocations for physical network %s", len(missing_ids), hg_physnet)
                    for seg_id in missing_ids:
                        alloc = AllocationsModel(host=hg_physnet, level=level, segment_type=segment_type,
                                                 segmentation_id=seg_id, network_id=None)
                        session.add(alloc)

            # remove allocs on orphaned hostgroups that don't have a network_id assigned
            if hosts_to_delete:
                LOG.debug("Deleting old allocations without assigned networks for orphaned hosts: %s",
                          ", ".join(hosts_to_delete))
                del_q = session.query(AllocationsModel)
                del_q = del_q.filter_by(level=level, segment_type=segment_type, network_id=None)
                del_q = del_q.filter(AllocationsModel.host.in_(hosts_to_delete))
                del_q.delete()

            LOG.info("ACI allocations synced in %.2fs", time.time() - start_time)

    def _sync_hostgroup_modes(self):
        LOG.info("Preparing hostgroup modes sync")

        session = db_api.get_writer_session()
        with session.begin(subtransactions=True):
            # fetch all mode-hostgroups from db
            db_groups = []
            for db_entry in (session.query(HostgroupModeModel).with_for_update()):
                db_groups.append(db_entry.hostgroup)

            for hg_name, hg in ACI_CONFIG.hostgroups.items():
                if hg['direct_mode'] and hg_name not in db_groups:
                    LOG.info("Adding %s to hostgroup db", hg_name)
                    hgmm = HostgroupModeModel(hostgroup=hg_name)
                    session.add(hgmm)
        LOG.info("Hostgroup modes synced")
