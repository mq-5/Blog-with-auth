"""empty message

Revision ID: 326e29e460b0
Revises: b92133dc12be
Create Date: 2019-09-10 11:30:15.031049

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '326e29e460b0'
down_revision = 'b92133dc12be'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('flag')
    op.add_column('user', sa.Column('is_admin', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'is_admin')
    op.create_table('flag',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('post_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.ForeignKeyConstraint(['post_id'], ['post.id'], name='flag_post_id_fkey'),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], name='flag_user_id_fkey'),
    sa.PrimaryKeyConstraint('id', name='flag_pkey')
    )
    # ### end Alembic commands ###
