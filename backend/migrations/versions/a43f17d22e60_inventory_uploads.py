"""Stage chunked Android inventory uploads.

Revision ID: a43f17d22e60
Revises: f1a2b3c4d5e6
"""

from alembic import op
import sqlalchemy as sa

revision = 'a43f17d22e60'
down_revision = 'f1a2b3c4d5e6'
branch_labels = None
depends_on = None


def upgrade():
    # Production can provision the staging table on first use.
    bind = op.get_bind()
    if bind.dialect.name == 'postgresql':
        op.execute(sa.text('SELECT pg_advisory_xact_lock(181991033, 426194)'))
    op.create_table(
        'inventory_uploads',
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('upload_id', sa.String(36), primary_key=True),
        sa.Column('filename', sa.String(200), nullable=False),
        sa.Column('vendor', sa.String(200), nullable=False),
        sa.Column('size', sa.Integer(), nullable=False),
        sa.Column('digest', sa.String(64), nullable=False),
        sa.Column('data', sa.LargeBinary(), nullable=False),
        sa.Column('result', sa.JSON()),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        if_not_exists=True,
    )
    op.create_index('ix_inventory_uploads_expires_at', 'inventory_uploads', ['expires_at'], if_not_exists=True)


def downgrade():
    op.drop_table('inventory_uploads')
