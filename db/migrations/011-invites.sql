-- Migration: fd168c58bc02

BEGIN;

CREATE TABLE IF NOT EXISTS invites (
    id VARCHAR(255) NOT NULL, 
    user_id UUID, 
    
    description VARCHAR, 
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 

    CONSTRAINT pk_invites PRIMARY KEY (id), 
    CONSTRAINT fk_invites_user_id_users FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);

DROP TRIGGER IF EXISTS trg_invites_set_updated_at ON invites;
CREATE TRIGGER trg_invites_set_updated_at
BEFORE UPDATE ON invites
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

UPDATE version_auth SET version_num = 'fd168c58bc02' RETURNING version_auth.version_num;

COMMIT;
