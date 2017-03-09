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

"""Hierarchical port binding allocations

Revision ID: 981f4d71956
Revises: 59cb5b6cf4d
Create Date: 2015-11-23 14:25:39.157776

"""

from alembic import op
import sqlalchemy as sa
from neutron.db.migration import cli


# revision identifiers, used by Alembic.
revision = '981f4d71956'
down_revision = 'a45cd5df3467'



def upgrade():
    op.create_table(
        'aci_port_binding_allocations',
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('level', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('segment_type', sa.String(length=255), nullable=False),
        sa.Column('segmentation_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('segment_id', sa.String(length=36), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=True),

        sa.PrimaryKeyConstraint("host", "level", "segment_type", "segmentation_id")
    )