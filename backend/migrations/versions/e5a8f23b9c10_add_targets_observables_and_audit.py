"""add_targets_observables_and_audit

Revision ID: e5a8f23b9c10
Revises: ce4d521f64e2
Create Date: 2026-09-11 07:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5a8f23b9c10'
down_revision: Union[str, None] = 'ce4d521f64e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create security_targets table
    op.create_table(
        'security_targets',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('normalized_value', sa.String(length=500), nullable=False),
        sa.Column('original_value', sa.String(length=1000), nullable=False),
        sa.Column('status', sa.String(length=50), server_default='QUEUED', nullable=False),
        sa.Column('environment', sa.String(length=50), server_default='external_threat', nullable=False),
        sa.Column('priority', sa.String(length=50), server_default='high', nullable=False),
        sa.Column('threat_score', sa.Integer(), server_default='0', nullable=False),
        sa.Column('verdict', sa.String(length=50), server_default='unknown', nullable=False),
        sa.Column('risk_level', sa.String(length=50), server_default='UNKNOWN', nullable=False),
        sa.Column('confidence', sa.Integer(), server_default='0', nullable=False),
        sa.Column('asn', sa.String(length=255), nullable=True),
        sa.Column('country', sa.String(length=100), nullable=True),
        sa.Column('city', sa.String(length=100), nullable=True),
        sa.Column('open_ports', sa.JSON(), server_default='[]', nullable=False),
        sa.Column('tags', sa.JSON(), server_default='[]', nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_by', sa.UUID(), nullable=True),
        sa.Column('last_scanned_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_security_targets_created_by_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_security_targets_organization_id_organizations'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_security_targets')),
        sa.UniqueConstraint('organization_id', 'target_type', 'normalized_value', name='uq_security_targets_org_type_val')
    )
    op.create_index(op.f('ix_security_targets_organization_id'), 'security_targets', ['organization_id'], unique=False)
    op.create_index(op.f('ix_security_targets_target_type'), 'security_targets', ['target_type'], unique=False)
    op.create_index(op.f('ix_security_targets_normalized_value'), 'security_targets', ['normalized_value'], unique=False)
    op.create_index(op.f('ix_security_targets_status'), 'security_targets', ['status'], unique=False)
    op.create_index('ix_security_targets_org_status', 'security_targets', ['organization_id', 'status'], unique=False)
    op.create_index('ix_security_targets_org_type', 'security_targets', ['organization_id', 'target_type'], unique=False)
    op.create_index('ix_security_targets_org_norm', 'security_targets', ['organization_id', 'normalized_value'], unique=False)
    op.create_index('ix_security_targets_org_created', 'security_targets', ['organization_id', 'created_at'], unique=False)

    # 2. Create observables table
    op.create_table(
        'observables',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('target_id', sa.UUID(), nullable=True),
        sa.Column('observable_type', sa.String(length=50), nullable=False),
        sa.Column('normalized_value', sa.String(length=500), nullable=False),
        sa.Column('original_value', sa.String(length=1000), nullable=False),
        sa.Column('source', sa.String(length=100), server_default='manual', nullable=False),
        sa.Column('confidence', sa.Integer(), server_default='80', nullable=False),
        sa.Column('severity', sa.String(length=50), server_default='high', nullable=False),
        sa.Column('status', sa.String(length=50), server_default='active', nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_observables_organization_id_organizations'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['security_targets.id'], name=op.f('fk_observables_target_id_security_targets'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_observables')),
        sa.UniqueConstraint('organization_id', 'observable_type', 'normalized_value', name='uq_observables_org_type_val')
    )
    op.create_index(op.f('ix_observables_organization_id'), 'observables', ['organization_id'], unique=False)
    op.create_index(op.f('ix_observables_target_id'), 'observables', ['target_id'], unique=False)
    op.create_index(op.f('ix_observables_observable_type'), 'observables', ['observable_type'], unique=False)
    op.create_index(op.f('ix_observables_normalized_value'), 'observables', ['normalized_value'], unique=False)
    op.create_index('ix_observables_org_type', 'observables', ['organization_id', 'observable_type'], unique=False)
    op.create_index('ix_observables_org_norm', 'observables', ['organization_id', 'normalized_value'], unique=False)
    op.create_index('ix_observables_org_target', 'observables', ['organization_id', 'target_id'], unique=False)

    # 3. Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('actor_id', sa.UUID(), nullable=True),
        sa.Column('actor_email', sa.String(length=255), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource_type', sa.String(length=100), nullable=False),
        sa.Column('resource_id', sa.String(length=100), nullable=True),
        sa.Column('details', sa.JSON(), server_default='{}', nullable=False),
        sa.Column('request_id', sa.String(length=64), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], name=op.f('fk_audit_logs_actor_id_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_audit_logs_organization_id_organizations'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_logs'))
    )
    op.create_index(op.f('ix_audit_logs_organization_id'), 'audit_logs', ['organization_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_actor_id'), 'audit_logs', ['actor_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'], unique=False)
    op.create_index(op.f('ix_audit_logs_request_id'), 'audit_logs', ['request_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_created_at'), 'audit_logs', ['created_at'], unique=False)
    op.create_index('ix_audit_logs_org_action', 'audit_logs', ['organization_id', 'action'], unique=False)
    op.create_index('ix_audit_logs_org_created', 'audit_logs', ['organization_id', 'created_at'], unique=False)


def downgrade() -> None:
    # Drop in reverse dependency order
    op.drop_index('ix_audit_logs_org_created', table_name='audit_logs')
    op.drop_index('ix_audit_logs_org_action', table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_created_at'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_request_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_action'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_actor_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_organization_id'), table_name='audit_logs')
    op.drop_table('audit_logs')

    op.drop_index('ix_observables_org_target', table_name='observables')
    op.drop_index('ix_observables_org_norm', table_name='observables')
    op.drop_index('ix_observables_org_type', table_name='observables')
    op.drop_index(op.f('ix_observables_normalized_value'), table_name='observables')
    op.drop_index(op.f('ix_observables_observable_type'), table_name='observables')
    op.drop_index(op.f('ix_observables_target_id'), table_name='observables')
    op.drop_index(op.f('ix_observables_organization_id'), table_name='observables')
    op.drop_table('observables')

    op.drop_index('ix_security_targets_org_created', table_name='security_targets')
    op.drop_index('ix_security_targets_org_norm', table_name='security_targets')
    op.drop_index('ix_security_targets_org_type', table_name='security_targets')
    op.drop_index('ix_security_targets_org_status', table_name='security_targets')
    op.drop_index(op.f('ix_security_targets_status'), table_name='security_targets')
    op.drop_index(op.f('ix_security_targets_normalized_value'), table_name='security_targets')
    op.drop_index(op.f('ix_security_targets_target_type'), table_name='security_targets')
    op.drop_index(op.f('ix_security_targets_organization_id'), table_name='security_targets')
    op.drop_table('security_targets')
