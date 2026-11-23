CREATE TABLE IF NOT EXISTS users (
    id             BIGSERIAL PRIMARY KEY,   -- séquentiel exprès : la sécurité ne repose pas sur l'ID
    email          TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'USER' CHECK (role IN ('USER', 'ADMIN')),
    full_name      TEXT,
    phone          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS documents (
    id        BIGSERIAL PRIMARY KEY,
    owner_id  BIGINT NOT NULL REFERENCES users(id),
    title     TEXT NOT NULL,
    body      TEXT NOT NULL DEFAULT ''
);

-- Défense en profondeur : Row-Level Security PostgreSQL.
-- Même une requête applicative oubliant le filtre owner_id ne voit que ses lignes.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        CREATE ROLE app_rw NOLOGIN;
    END IF;
END $$;
GRANT USAGE ON SCHEMA public TO app_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON documents TO app_rw;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_rw;

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS documents_owner ON documents;
CREATE POLICY documents_owner ON documents
    USING (
        owner_id = NULLIF(current_setting('app.user_id', true), '')::BIGINT
        OR current_setting('app.user_role', true) = 'ADMIN'
    )
    WITH CHECK (owner_id = NULLIF(current_setting('app.user_id', true), '')::BIGINT);
