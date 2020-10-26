# Copyright 2020 SAP SE
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

"""add foreignkey relation ship to network and networksegment

Revision ID: 01bfdd894115
Revises: 877aad5faa0d
Create Date: 2020-10-26 17:24:24.798578

"""

# revision identifiers, used by Alembic.
revision = '01bfdd894115'
down_revision = '877aad5faa0d'

from alembic import op


def upgrade():
    op.create_foreign_key(
        None,
        'aci_port_binding_allocations',
        'networks', ['network_id'], ['id'],
        ondelete='SET NULL'
    )
    op.create_foreign_key(
        None,
        'aci_port_binding_allocations',
        'networksegments', ['segment_id'], ['id'],
        ondelete='SET NULL'
    )
