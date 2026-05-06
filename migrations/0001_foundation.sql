CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE organization_profile (
    id                INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    company_name      VARCHAR(255) NOT NULL DEFAULT 'Meine Organisation',
    scope_statement   TEXT NOT NULL DEFAULT '',
    target_frameworks JSONB NOT NULL DEFAULT '["ISO27001_2022"]'::jsonb,
    logo_storage_key  TEXT,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE organization_units (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(150) NOT NULL,
    parent_id    UUID REFERENCES organization_units(id) ON DELETE SET NULL,
    lead_user_id UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                VARCHAR(255) NOT NULL UNIQUE,
    full_name            VARCHAR(255) NOT NULL,
    password_hash        TEXT,
    oidc_subject         VARCHAR(255) UNIQUE,
    role                 VARCHAR(32) NOT NULL DEFAULT 'employee'
                             CHECK (role IN ('admin', 'iso', 'owner', 'auditor', 'employee')),
    organization_unit_id UUID REFERENCES organization_units(id) ON DELETE SET NULL,
    is_active            BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at           TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE organization_units
    ADD CONSTRAINT fk_org_units_lead_user
    FOREIGN KEY (lead_user_id) REFERENCES users(id) ON DELETE SET NULL;

CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_expires ON sessions (expires_at);

CREATE TABLE login_attempts (
    id               BIGSERIAL PRIMARY KEY,
    email_normalized VARCHAR(255) NOT NULL,
    client_ip        INET NOT NULL,
    attempted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_login_attempts_lookup
    ON login_attempts (email_normalized, client_ip, attempted_at DESC);

CREATE TABLE system_assets (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_code       VARCHAR(32) NOT NULL UNIQUE,
    name             VARCHAR(200) NOT NULL,
    asset_type       VARCHAR(32) NOT NULL
                         CHECK (asset_type IN ('server', 'application', 'cloud_service', 'network', 'vendor', 'endpoint')),
    description      TEXT,
    owner_unit_id    UUID REFERENCES organization_units(id) ON DELETE SET NULL,
    owner_user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    vendor_name      VARCHAR(200),
    hosting_location VARCHAR(100),
    criticality      VARCHAR(16) NOT NULL DEFAULT 'normal'
                         CHECK (criticality IN ('low', 'normal', 'high', 'critical')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_system_assets_unit ON system_assets (owner_unit_id);

CREATE TABLE audit_logs (
    id            BIGSERIAL PRIMARY KEY,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_ip      INET,
    action        VARCHAR(64) NOT NULL,
    entity_type   VARCHAR(64) NOT NULL,
    entity_id     VARCHAR(64) NOT NULL,
    summary       TEXT NOT NULL,
    old_values    JSONB,
    new_values    JSONB,
    prev_hash     CHAR(64) NOT NULL,
    row_hash      CHAR(64) NOT NULL
);

CREATE INDEX idx_audit_logs_entity ON audit_logs (entity_type, entity_id);
CREATE INDEX idx_audit_logs_occurred ON audit_logs (occurred_at DESC);
CREATE INDEX idx_audit_logs_actor ON audit_logs (actor_user_id);

CREATE OR REPLACE FUNCTION audit_log_chain_trigger()
RETURNS TRIGGER AS $$
DECLARE
    last_hash       TEXT;
    ts_utc_iso      TEXT;
    payload_to_hash TEXT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('ins_isms_audit_chain_lock'));

    SELECT row_hash INTO last_hash
    FROM audit_logs
    ORDER BY id DESC
    LIMIT 1;

    NEW.prev_hash := COALESCE(last_hash, repeat('0', 64));
    NEW.occurred_at := COALESCE(NEW.occurred_at, NOW());

    ts_utc_iso := to_char(NEW.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');

    payload_to_hash := concat_ws('|',
        NEW.prev_hash,
        COALESCE(NEW.actor_user_id::text, 'SYSTEM'),
        COALESCE(NEW.actor_ip::text, 'NO_IP'),
        NEW.action,
        NEW.entity_type,
        NEW.entity_id,
        NEW.summary,
        COALESCE(NEW.old_values::text, ''),
        COALESCE(NEW.new_values::text, ''),
        ts_utc_iso
    );

    NEW.row_hash := encode(digest(payload_to_hash, 'sha256'), 'hex');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_logs_insert
BEFORE INSERT ON audit_logs
FOR EACH ROW EXECUTE FUNCTION audit_log_chain_trigger();

CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Security Violation: audit_logs is immutable (append-only).';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_logs_immutable
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_modification();

CREATE OR REPLACE FUNCTION jsonb_diff_val(val1 JSONB, val2 JSONB)
RETURNS JSONB AS $$
DECLARE
    result JSONB := '{}'::jsonb;
    v      RECORD;
BEGIN
    FOR v IN SELECT * FROM jsonb_each(val2) LOOP
        IF v.key IN ('updated_at', 'created_at', 'password_hash') THEN
            CONTINUE;
        END IF;
        IF (val1 -> v.key) IS DISTINCT FROM v.value THEN
            result := result || jsonb_build_object(v.key, v.value);
        END IF;
    END LOOP;
    RETURN result;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION log_isms_entity_changes()
RETURNS TRIGGER AS $$
DECLARE
    v_actor_id  UUID;
    v_actor_ip  INET;
    v_old_json  JSONB;
    v_new_json  JSONB;
    v_diff_old  JSONB;
    v_diff_new  JSONB;
    v_entity_id VARCHAR(64);
    v_action    VARCHAR(64);
    v_summary   TEXT;
BEGIN
    BEGIN
        v_actor_id := NULLIF(current_setting('app.current_actor_id', true), '')::UUID;
    EXCEPTION WHEN OTHERS THEN
        v_actor_id := NULL;
    END;

    BEGIN
        v_actor_ip := NULLIF(current_setting('app.current_actor_ip', true), '')::INET;
    EXCEPTION WHEN OTHERS THEN
        v_actor_ip := NULL;
    END;

    IF (TG_OP = 'INSERT') THEN
        v_new_json := to_jsonb(NEW) - 'password_hash';
        v_entity_id := COALESCE(v_new_json ->> 'id', 'unknown');
        v_action := TG_TABLE_NAME || '.created';
        v_summary := 'Datensatz erstellt in ' || TG_TABLE_NAME;
        INSERT INTO audit_logs (actor_user_id, actor_ip, action, entity_type, entity_id, summary, old_values, new_values)
        VALUES (v_actor_id, v_actor_ip, v_action, TG_TABLE_NAME, v_entity_id, v_summary, NULL, v_new_json);
        RETURN NEW;

    ELSIF (TG_OP = 'UPDATE') THEN
        v_old_json := to_jsonb(OLD) - 'password_hash';
        v_new_json := to_jsonb(NEW) - 'password_hash';
        v_diff_old := jsonb_diff_val(v_new_json, v_old_json);
        v_diff_new := jsonb_diff_val(v_old_json, v_new_json);

        IF v_diff_new = '{}'::jsonb THEN
            RETURN NEW;
        END IF;

        v_entity_id := COALESCE(v_new_json ->> 'id', 'unknown');

        IF TG_TABLE_NAME = 'document_versions' AND (v_diff_new ->> 'status') = 'approved' THEN
            v_action := 'document_versions.approved';
            v_summary := 'Dokumentversion v' || COALESCE(v_new_json ->> 'version_number', '?') || ' freigegeben';
        ELSIF TG_TABLE_NAME = 'risk_scenarios' AND (v_diff_new ->> 'status') = 'accepted' THEN
            v_action := 'risk_scenarios.accepted';
            v_summary := 'Restrisiko akzeptiert: ' || COALESCE(v_new_json ->> 'reference_code', v_entity_id);
        ELSIF v_diff_new ? 'status' THEN
            v_action := TG_TABLE_NAME || '.status_changed';
            v_summary := 'Status in ' || TG_TABLE_NAME || ' geändert auf ' || (v_diff_new ->> 'status');
        ELSE
            v_action := TG_TABLE_NAME || '.updated';
            v_summary := 'Datensatz aktualisiert in ' || TG_TABLE_NAME;
        END IF;

        INSERT INTO audit_logs (actor_user_id, actor_ip, action, entity_type, entity_id, summary, old_values, new_values)
        VALUES (v_actor_id, v_actor_ip, v_action, TG_TABLE_NAME, v_entity_id, v_summary, v_diff_old, v_diff_new);
        RETURN NEW;

    ELSIF (TG_OP = 'DELETE') THEN
        v_old_json := to_jsonb(OLD) - 'password_hash';
        v_entity_id := COALESCE(v_old_json ->> 'id', 'unknown');
        v_action := TG_TABLE_NAME || '.deleted';
        v_summary := 'Datensatz gelöscht aus ' || TG_TABLE_NAME;
        INSERT INTO audit_logs (actor_user_id, actor_ip, action, entity_type, entity_id, summary, old_values, new_values)
        VALUES (v_actor_id, v_actor_ip, v_action, TG_TABLE_NAME, v_entity_id, v_summary, v_old_json, NULL);
        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_organization_profile
AFTER INSERT OR UPDATE OR DELETE ON organization_profile
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TRIGGER trg_audit_organization_units
AFTER INSERT OR UPDATE OR DELETE ON organization_units
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TRIGGER trg_audit_users
AFTER INSERT OR UPDATE OR DELETE ON users
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TRIGGER trg_audit_system_assets
AFTER INSERT OR UPDATE OR DELETE ON system_assets
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();
