-- Migration: d2170a231906

BEGIN;

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

CREATE TABLE IF NOT EXISTS users (
    id UUID DEFAULT gen_random_uuid() NOT NULL, 

    is_active BOOLEAN DEFAULT true NOT NULL, 
    username VARCHAR(128) NOT NULL, 
    email VARCHAR(128) NOT NULL, 
    phone INTEGER, 
    password_hash VARCHAR(512) NOT NULL, 

    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,

    CONSTRAINT pk_users PRIMARY KEY (id), 
    CONSTRAINT uq_users_phone UNIQUE (phone),
    CONSTRAINT uq_users_email UNIQUE (email),
    CONSTRAINT uq_users_username UNIQUE (username)
);

DROP TRIGGER IF EXISTS trg_users_set_updated_at ON users;
CREATE TRIGGER trg_users_set_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS auth_sessions (
    id UUID DEFAULT gen_random_uuid() NOT NULL, 

    user_id UUID NOT NULL, 
    family_id UUID DEFAULT gen_random_uuid() NOT NULL, 
    refresh_token_hash VARCHAR(255) NOT NULL, 
    created_ip VARCHAR(45) NOT NULL, 
    created_user_agent VARCHAR(1024), 

    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    revoked_at TIMESTAMP WITH TIME ZONE, 

    revoke_reason VARCHAR(255), 
    replaced_by UUID,

    CONSTRAINT pk_auth_sessions PRIMARY KEY (id), 
    CONSTRAINT fk_auth_sessions_replaced_by_auth_sessions FOREIGN KEY(replaced_by) REFERENCES auth_sessions (id) ON DELETE SET NULL, 
    CONSTRAINT fk_auth_sessions_user_id_users FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
    CONSTRAINT ck_auth_sessions_replaced_by_not_self CHECK (replaced_by IS NULL OR replaced_by <> id),
    CONSTRAINT ck_auth_sessions_expires_after_created CHECK (expires_at > created_at),
    CONSTRAINT ck_auth_sessions_revoked_after_created CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

DROP TRIGGER IF EXISTS trg_auth_sessions_set_updated_at ON auth_sessions;
CREATE TRIGGER trg_auth_sessions_set_updated_at
BEFORE UPDATE ON auth_sessions
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX IF NOT EXISTS ix_auth_sessions_replaced_by ON auth_sessions (replaced_by);

CREATE INDEX IF NOT EXISTS ix_auth_sessions_user_created_at ON auth_sessions (user_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS ix_auth_sessions_family_id_revoked_at ON auth_sessions (family_id, revoked_at);

CREATE UNIQUE INDEX IF NOT EXISTS ix_auth_sessions_user_id_revoked_at ON auth_sessions (user_id, revoked_at);

CREATE UNIQUE INDEX IF NOT EXISTS ix_auth_sessions_refresh_token_hash ON auth_sessions (refresh_token_hash);

WITH updated AS (
    UPDATE version_auth
    SET version_num = 'd2170a231906'
    RETURNING version_auth.version_num
)
INSERT INTO version_auth (version_num)
SELECT 'd2170a231906'
WHERE NOT EXISTS (SELECT 1 FROM updated)
RETURNING version_auth.version_num;

COMMIT;
