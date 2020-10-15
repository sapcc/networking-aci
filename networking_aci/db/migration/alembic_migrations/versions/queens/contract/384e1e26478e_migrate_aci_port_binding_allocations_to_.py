# Copyright 2020 OpenStack Foundation
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
#

from alembic import op
import sqlalchemy as sa


"""Migrate aci_port_binding_allocations to ml2

Revision ID: 384e1e26478e
Revises: 5c85685d616d
Create Date: 2020-10-15 12:52:14.263387

"""

# revision identifiers, used by Alembic.
revision = '384e1e26478e'
down_revision = '981f4d71956'


def upgrade():
    transfer_vlan_allocations()
    op.drop_table('aci_port_binding_allocations')


def transfer_vlan_allocations():
    """
    Migrates the allocations from aci_port_binding_allocations to the neutron-internal
    ml2_vlan_allocations, which is used and supported by the ml2 vlan type driver and
    network-segment-range plugin.
    :return:
    """
    aci_port_alloc = sa.Table('aci_port_binding_allocations',
                              sa.MetaData(),
                              sa.Column('host', sa.String(length=255)),
                              sa.Column('level', sa.Integer()),
                              sa.Column('segment_type', sa.String(length=255)),
                              sa.Column('segmentation_id', sa.Integer()),
                              sa.Column('segment_id', sa.String(length=36)),
                              sa.Column('network_id', sa.String(length=36)))

    ml2_vlan_alloc = sa.Table('ml2_vlan_allocations',
                              sa.MetaData(),
                              sa.Column('physical_network', sa.String(length=64)),
                              sa.Column('vlan_id', sa.Integer()),
                              sa.Column('allocated', sa.Boolean()))

    session = sa.orm.Session(bind=op.get_bind())
    with session.begin(subtransactions=True):
        query = session.query(aci_port_alloc)
        # Filter allocated values
        query = query.filter(aci_port_alloc.c.segment_id != None,
                             aci_port_alloc.c.network_id != None,
                             aci_port_alloc.c.segment_type == 'vlan')

        vlan_allocation_values = []
        for allocation in query:
            vlan_allocation_values.append(dict(
                physical_network=allocation.host,
                vlan_id=allocation.segmentation_id,
                allocated=True
            ))
        op.bulk_insert(ml2_vlan_alloc, vlan_allocation_values)

    # this commit is necessary to allow further operations
    session.commit()
