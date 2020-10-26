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
import random

from neutron.db import api as db_api
from neutron_lib.db import model_base
from neutron.db.models import segment as ml2_models
from neutron.plugins.ml2 import models
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import uuidutils
from six import moves
import sqlalchemy as sa

from networking_aci._i18n import _LI
from networking_aci.plugins.ml2.drivers.mech_aci.exceptions import NoAllocationFoundInMaximumAllowedAttempts

LOG = log.getLogger(__name__)


class AllocationsModel(model_base.BASEV2):
    __tablename__ = 'aci_port_binding_allocations'

    host = sa.Column(sa.String(255), nullable=False, primary_key=True)
    level = sa.Column(sa.Integer(), nullable=False, primary_key=True)
    segment_type = sa.Column(sa.String(255), nullable=False, primary_key=True)
    segmentation_id = sa.Column(sa.Integer(), nullable=False, primary_key=True)
    segment_id = sa.Column(sa.String(36), sa.ForeignKey('networksegments.id', ondelete='SET NULL'), nullable=True)
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id', ondelete='SET NULL'), nullable=True)

    __table_args__ = (
        sa.UniqueConstraint(
            host, level, segment_type, network_id,
            name='restrict_one_segment_per_host_level_segtype_network'),
        model_base.BASEV2.__table_args__
    )


class AllocationsManager(object):
    def __init__(self, network_config):
        self.hostgroup_config = network_config['hostgroup_dict']
        if cfg.CONF.ml2_aci.sync_allocations:
            self._sync_allocations()

    def initialize(self):
        self._sync_allocations()
        LOG.info(_LI("AllocationsManager initialization complete"))

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
        LOG.info("Releasing segment %(segment)s with top level VLAN segment", {"segment": segment})

        session = db_api.get_writer_session()
        with session.begin(subtransactions=True):
            # Delete the network segment
            query = (session.query(ml2_models.NetworkSegment).
                     filter_by(id=segment['id'], network_id=network['id'], network_type=segment['network_type'],
                               segmentation_id=segment['segmentation_id'], segment_index=level))
            query.delete()

    def _release_vxlan_segment(self, network, host_config, level, segment):
        LOG.info("Releasing segment %(segment)s with top level VXLAN segment", {"segment": segment})
        segment_type = segment['network_type']
        segment_id = segment['id']
        segmentation_id = segment['segmentation_id']
        network_id = network['id']

        session = db_api.get_writer_session()
        with session.begin(subtransactions=True):
            select = (session.query(models.PortBindingLevel).
                      filter_by(segment_id=segment_id, level=level))

            if select.count() == 0:
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
        return False

    def _allocation_key(self, host_id, level, segment_type):
        return "{}_{}_{}".format(host_id, level, segment_type)

    @staticmethod
    def _segmentation_ids(host_config):
        segment_ranges = []
        for segment in host_config['segment_range'].split(','):
            segment_range_str = segment.strip().split(':')
            segment_range = moves.range(int(segment_range_str[0]), int(segment_range_str[1]) + 1)
            segment_ranges.extend(segment_range)

        return set(segment_ranges)

    def _sync_allocations(self):
        LOG.info("Preparing ACI Allocations table")
        level = 1  # Currently only supporting one level in hierarchy

        # TODO need to survive if the DB is not ready or migrations aren\t run
        # TODO add a retry loop
        session = db_api.get_writer_session()
        with session.begin(subtransactions=True):
            allocations = dict()
            allocs = (session.query(AllocationsModel).with_lockmode('update'))

            for alloc in allocs:
                alloc_key = self._allocation_key(alloc.host, alloc.level, alloc.segment_type)
                if alloc_key not in allocations:
                    allocations[alloc_key] = set()
                allocations[alloc_key].add(alloc)

            # process segment ranges for each configured hostgroup
            for hostgroup, hostgroup_config in self.hostgroup_config.iteritems():
                self._process_host_or_hostgroup(session, hostgroup, hostgroup_config, allocations, level)

        # remove from table unallocated vlans for any unconfigured
        # physical networks
        for allocs in allocations.values():
            for alloc in allocs:
                if not alloc.network_id:
                    LOG.debug("Removing segment %(seg_id)s on "
                              "host/hostgroup"
                              "%(host)s level %(level)s type %(segment_type)s from pool",
                              {'seg_id': alloc.segmentation_id,
                               'host': alloc.host,
                               'level': alloc.level,
                               'segment_type': alloc.segment_type})
                    session.delete(alloc)

    def _process_host_or_hostgroup(self, session, host, host_config, allocations, level):
        segment_type = host_config['segment_type']
        segmentation_ids = self._segmentation_ids(host_config)
        alloc_key = self._allocation_key(host, level, segment_type)
        if alloc_key in allocations:
            for alloc in allocations[alloc_key]:
                try:
                    # see if segment is allocatable
                    LOG.info("Check if allocatable")
                    LOG.info(alloc.segmentation_id)
                    segmentation_ids.remove(alloc.segmentation_id)
                except KeyError:
                    # it's not allocatable, so check if its allocated
                    if not alloc.network_id:
                        # it's not, so remove it from table
                        LOG.debug("Removing segment %(seg_id)s on "
                                  "host/hostgroup "
                                  "%(host)s level %(level)s type %(segment_type)s from pool",
                                  {'seg_id': alloc.segmentation_id,
                                   'host': host,
                                   'level': level,
                                   'segment_type': segment_type})
                        session.delete(alloc)
            del allocations[alloc_key]

        for segmentation_id in sorted(segmentation_ids):
            alloc = AllocationsModel(host=host, level=level, segment_type=segment_type, segmentation_id=segmentation_id,
                                     network_id=None)
            session.add(alloc)
