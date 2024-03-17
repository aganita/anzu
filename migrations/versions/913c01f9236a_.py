"""empty message

Revision ID: 913c01f9236a
Revises: 3f90693b6fa4
Create Date: 2024-03-17 03:34:58.863635

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '913c01f9236a'
down_revision = '3f90693b6fa4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.add_column(sa.Column('type', sa.String(length=80), nullable=True))
        batch_op.add_column(sa.Column('open_ports', sa.String(length=80), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_column('open_ports')
        batch_op.drop_column('type')

    # ### end Alembic commands ###
