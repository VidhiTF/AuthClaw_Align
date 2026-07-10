"""
Alembic migration - Create chat_sessions and chat_messages tables for Phase 13
This is version 005 - Compliance Agent Chat Persistence schema
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None

def upgrade():
    # Verify no existing chat schema before migration
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()
    if 'chat_sessions' in existing_tables or 'chat_messages' in existing_tables:
        print("WARNING: Existing chat tables (chat_sessions/chat_messages) detected. Skipping creation.")
        return

    # Create chat_sender enum type if not exists
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'chat_sender') THEN
                CREATE TYPE chat_sender AS ENUM ('user', 'agent');
            END IF;
        END
        $$;
    """)

    # Chat Sessions table
    op.create_table(
        'chat_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_chatsession_tenant', 'chat_sessions', ['tenant_id'])

    # Chat Messages table
    op.create_table(
        'chat_messages',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('sender', postgresql.ENUM('user', 'agent', name='chat_sender', create_type=False), nullable=False),
        sa.Column('text', sa.Text(), nullable=False),
        sa.Column('results', postgresql.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['session_id'], ['chat_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_chatmessage_session', 'chat_messages', ['session_id'])

    # Enable RLS on chat_sessions and chat_messages
    op.execute("ALTER TABLE chat_sessions ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE chat_sessions FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY chat_sessions_tenant_isolation
    ON chat_sessions
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)

    op.execute("ALTER TABLE chat_messages ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE chat_messages FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY chat_messages_tenant_isolation
    ON chat_messages
    USING (
        EXISTS (
            SELECT 1 FROM chat_sessions 
            WHERE chat_sessions.id = session_id 
            AND chat_sessions.tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        )
    );
    """)


def downgrade():
    op.execute("DROP POLICY IF EXISTS chat_messages_tenant_isolation ON chat_messages;")
    op.execute("ALTER TABLE chat_messages NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE chat_messages DISABLE ROW LEVEL SECURITY;")

    op.execute("DROP POLICY IF EXISTS chat_sessions_tenant_isolation ON chat_sessions;")
    op.execute("ALTER TABLE chat_sessions NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE chat_sessions DISABLE ROW LEVEL SECURITY;")

    op.drop_table('chat_messages')
    op.drop_table('chat_sessions')

    op.execute("DROP TYPE IF EXISTS chat_sender;")
