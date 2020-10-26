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

"""prevent duplicate network segments in allocation table

Revision ID: 877aad5faa0d
Revises: 981f4d71956
Create Date: 2020-10-26 16:35:51.882628

"""

# revision identifiers, used by Alembic.
revision = '877aad5faa0d'
down_revision = '981f4d71956'

from alembic import op


def upgrade():
    op.create_unique_constraint(
        'restrict_one_segment_per_host_level_segtype_network',
        'aci_port_binding_allocations',
        ['host', 'level', 'segment_type', 'network_id']
    )
