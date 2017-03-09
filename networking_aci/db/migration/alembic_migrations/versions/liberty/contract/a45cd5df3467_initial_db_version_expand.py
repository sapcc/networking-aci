
"""Initial db version, expand branch

Revision ID: a45cd5df3467
Create Date: 2015-11-25 12:37:34.38453

"""

from neutron.db.migration import cli

# revision identifiers, used by Alembic.
revision = 'a45cd5df3467'
down_revision = '595c6d0435e2'
branch_labels = (cli.EXPAND_BRANCH,)


def upgrade():
    pass