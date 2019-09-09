"""empty message

Revision ID: b92133dc12be
Revises: 1ad28b02e3de
Create Date: 2019-09-09 15:03:34.239895

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b92133dc12be'
down_revision = '1ad28b02e3de'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('post', sa.Column('views', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('post', 'views')
    # ### end Alembic commands ###