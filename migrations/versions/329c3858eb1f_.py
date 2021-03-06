"""empty message

Revision ID: 329c3858eb1f
Revises: 
Create Date: 2019-11-25 12:56:51.944161

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '329c3858eb1f'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('paises',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=50), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('paises')
    # ### end Alembic commands ###
