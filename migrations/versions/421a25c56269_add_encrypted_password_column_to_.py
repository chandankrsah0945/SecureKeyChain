"""Add encrypted_password column to credential table

Revision ID: 421a25c56269
Revises: 8f8c3accaffb
Create Date: 2025-03-15 15:49:08.327345

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '421a25c56269'
down_revision = '8f8c3accaffb'
branch_labels = None
depends_on = None


def upgrade():
    # Step 1: Add the column as nullable
    with op.batch_alter_table('credential', schema=None) as batch_op:
        batch_op.add_column(sa.Column('encrypted_password', sa.String(length=256), nullable=True))

    # Step 2: Populate the column with a default value for existing rows
    op.execute("UPDATE credential SET encrypted_password = '' WHERE encrypted_password IS NULL")

    # Step 3: Alter the column to be NOT NULL
    with op.batch_alter_table('credential', schema=None) as batch_op:
        batch_op.alter_column('encrypted_password', nullable=False)


def downgrade():
    # Remove the encrypted_password column
    with op.batch_alter_table('credential', schema=None) as batch_op:
        batch_op.drop_column('encrypted_password')