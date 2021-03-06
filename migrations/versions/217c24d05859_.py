"""empty message

Revision ID: 217c24d05859
Revises: 2b6428d4b74b
Create Date: 2018-03-15 17:00:16.500284

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '217c24d05859'
down_revision = '2b6428d4b74b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('avatar_hash', sa.String(length=32), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'avatar_hash')
    # ### end Alembic commands ###
