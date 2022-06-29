# Copyright 2021 SAP SE
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

from neutron_lib.db import model_base
from neutron_lib.db import standard_attr
import sqlalchemy as sa

from networking_aci.plugins.ml2.drivers.mech_aci import constants as aci_const


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


class HostgroupModeModel(standard_attr.HasStandardAttributes, model_base.BASEV2):
    __tablename__ = 'aci_hostgroup_modes'

    hostgroup = sa.Column(sa.String(255), nullable=False, primary_key=True)
    mode = sa.Column(sa.String(32), nullable=False, default=aci_const.MODE_INFRA)

    api_collections = []
