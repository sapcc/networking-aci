# Copyright 2021 SAP SE
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

"""add hostgroup mode table for direct-mode hostgroups

Revision ID: 3cda31f05a0b
Revises: 01bfdd894115
Create Date: 2021-03-16 15:03:17.126087

"""

# revision identifiers, used by Alembic.
revision = '3cda31f05a0b'
down_revision = '01bfdd894115'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'aci_hostgroup_modes',
        sa.Column('hostgroup', sa.String(length=255), nullable=False),
        sa.Column('mode', sa.String(length=32), nullable=False),
        sa.Column('standard_attr_id', sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(['standard_attr_id'], ['standardattributes.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('hostgroup'),
        sa.UniqueConstraint('standard_attr_id'),
        mysql_engine='InnoDB'
    )
