CREATE TABLE classification_levels (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        VARCHAR(16) NOT NULL UNIQUE,
    rank        INTEGER NOT NULL UNIQUE CHECK (rank >= 1),
    name        VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    badge_color VARCHAR(32) NOT NULL CHECK (badge_color IN ('neutral', 'info', 'warning', 'danger')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE classification_handling_rules (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    level_id   UUID NOT NULL REFERENCES classification_levels(id) ON DELETE CASCADE,
    category   VARCHAR(32) NOT NULL CHECK (category IN ('storage', 'transmission', 'labeling', 'access', 'disposal')),
    rule_text  TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_classification_handling_rules_level
    ON classification_handling_rules (level_id, category, sort_order);

CREATE TABLE information_assets (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    VARCHAR(200) NOT NULL,
    description             TEXT,
    owner_unit_id           UUID REFERENCES organization_units(id) ON DELETE SET NULL,
    owner_user_id           UUID REFERENCES users(id) ON DELETE SET NULL,
    classification_level_id UUID NOT NULL REFERENCES classification_levels(id) ON DELETE RESTRICT,
    confidentiality         VARCHAR(16) NOT NULL DEFAULT 'normal' CHECK (confidentiality IN ('normal', 'high', 'very_high')),
    integrity               VARCHAR(16) NOT NULL DEFAULT 'normal' CHECK (integrity IN ('normal', 'high', 'very_high')),
    availability            VARCHAR(16) NOT NULL DEFAULT 'normal' CHECK (availability IN ('normal', 'high', 'very_high')),
    retention_period        VARCHAR(100),
    review_interval_months  INTEGER NOT NULL DEFAULT 12 CHECK (review_interval_months BETWEEN 1 AND 60),
    last_reviewed_at        TIMESTAMPTZ,
    next_review_due_at      TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_information_assets_level ON information_assets (classification_level_id);
CREATE INDEX idx_information_assets_unit ON information_assets (owner_unit_id);
CREATE INDEX idx_information_assets_review_due ON information_assets (next_review_due_at);

CREATE TABLE information_asset_systems (
    information_asset_id UUID NOT NULL REFERENCES information_assets(id) ON DELETE CASCADE,
    system_asset_id      UUID NOT NULL REFERENCES system_assets(id) ON DELETE CASCADE,
    PRIMARY KEY (information_asset_id, system_asset_id)
);

CREATE INDEX idx_information_asset_systems_system ON information_asset_systems (system_asset_id);

CREATE TRIGGER trg_audit_classification_levels
AFTER INSERT OR UPDATE OR DELETE ON classification_levels
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TRIGGER trg_audit_classification_handling_rules
AFTER INSERT OR UPDATE OR DELETE ON classification_handling_rules
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TRIGGER trg_audit_information_assets
AFTER INSERT OR UPDATE OR DELETE ON information_assets
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TABLE documents (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    doc_code                VARCHAR(32) NOT NULL UNIQUE,
    title                   VARCHAR(255) NOT NULL,
    doc_type                VARCHAR(32) NOT NULL CHECK (doc_type IN ('policy', 'guideline', 'sop', 'record', 'template', 'runbook')),
    source_type             VARCHAR(32) NOT NULL DEFAULT 'markdown_editor' CHECK (source_type IN ('markdown_editor', 'uploaded_file', 'external_link')),
    classification_level_id UUID NOT NULL REFERENCES classification_levels(id) ON DELETE RESTRICT,
    owner_unit_id           UUID REFERENCES organization_units(id) ON DELETE SET NULL,
    owner_user_id           UUID REFERENCES users(id) ON DELETE SET NULL,
    review_interval_months  INTEGER NOT NULL DEFAULT 12 CHECK (review_interval_months BETWEEN 1 AND 60),
    next_review_due_at      TIMESTAMPTZ,
    requires_acknowledgment BOOLEAN NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_documents_classification ON documents (classification_level_id);
CREATE INDEX idx_documents_unit ON documents (owner_unit_id);
CREATE INDEX idx_documents_type ON documents (doc_type);
CREATE INDEX idx_documents_review_due ON documents (next_review_due_at);

CREATE TABLE document_versions (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id       UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    version_number    VARCHAR(32) NOT NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'in_review', 'approved', 'archived')),
    content_markdown  TEXT,
    attached_file_key TEXT,
    original_filename VARCHAR(255),
    file_sha256       CHAR(64),
    external_url      TEXT,
    change_summary    TEXT NOT NULL DEFAULT '',
    author_id         UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    approved_by_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    approved_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (document_id, version_number)
);

CREATE UNIQUE INDEX idx_document_versions_single_approved
    ON document_versions (document_id)
    WHERE status = 'approved';

CREATE INDEX idx_document_versions_doc_created
    ON document_versions (document_id, created_at DESC);

CREATE TABLE document_acknowledgments (
    document_version_id UUID NOT NULL REFERENCES document_versions(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    acknowledged_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (document_version_id, user_id)
);

CREATE TRIGGER trg_audit_documents
AFTER INSERT OR UPDATE OR DELETE ON documents
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TRIGGER trg_audit_document_versions
AFTER INSERT OR UPDATE OR DELETE ON document_versions
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TABLE compliance_frameworks (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code       VARCHAR(32) NOT NULL UNIQUE,
    name       VARCHAR(150) NOT NULL,
    version    VARCHAR(32) NOT NULL,
    is_active  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE framework_controls (
    id                            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id                  UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    code                          VARCHAR(32) NOT NULL,
    domain                        VARCHAR(100) NOT NULL,
    title                         VARCHAR(255) NOT NULL,
    description                   TEXT NOT NULL,
    audit_question                TEXT,
    default_not_applicable_reason TEXT,
    sort_order                    INTEGER NOT NULL DEFAULT 0,
    UNIQUE (framework_id, code)
);

CREATE INDEX idx_framework_controls_fw_sort
    ON framework_controls (framework_id, sort_order, code);

CREATE TABLE control_mappings (
    source_control_id UUID NOT NULL REFERENCES framework_controls(id) ON DELETE CASCADE,
    target_control_id UUID NOT NULL REFERENCES framework_controls(id) ON DELETE CASCADE,
    mapping_type      VARCHAR(32) NOT NULL DEFAULT 'equivalent' CHECK (mapping_type IN ('equivalent', 'partial', 'superset')),
    PRIMARY KEY (source_control_id, target_control_id),
    CHECK (source_control_id <> target_control_id)
);

CREATE INDEX idx_control_mappings_target ON control_mappings (target_control_id);

CREATE TABLE soa_entries (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id            UUID NOT NULL UNIQUE REFERENCES framework_controls(id) ON DELETE CASCADE,
    is_applicable         BOOLEAN NOT NULL DEFAULT TRUE,
    justification         TEXT NOT NULL DEFAULT '',
    implementation_status VARCHAR(32) NOT NULL DEFAULT 'not_started' CHECK (implementation_status IN ('not_started', 'in_progress', 'implemented', 'verified')),
    implementation_notes  TEXT,
    owner_unit_id         UUID REFERENCES organization_units(id) ON DELETE SET NULL,
    owner_user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    target_date           DATE,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_soa_entries_unit ON soa_entries (owner_unit_id);
CREATE INDEX idx_soa_entries_status ON soa_entries (implementation_status);
CREATE INDEX idx_soa_entries_target_date ON soa_entries (target_date);

CREATE TABLE control_evidences (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    soa_entry_id        UUID NOT NULL REFERENCES soa_entries(id) ON DELETE CASCADE,
    title               VARCHAR(200) NOT NULL,
    evidence_type       VARCHAR(32) NOT NULL CHECK (evidence_type IN ('file', 'policy_link', 'external_url', 'note')),
    file_storage_key    TEXT,
    original_filename   VARCHAR(255),
    file_sha256         CHAR(64),
    linked_document_id  UUID REFERENCES documents(id) ON DELETE SET NULL,
    section_anchor      VARCHAR(255),
    section_label       VARCHAR(255),
    evidence_url        TEXT,
    evidence_note       TEXT,
    uploaded_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    verified_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    verified_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (evidence_type = 'file'         AND file_storage_key IS NOT NULL AND original_filename IS NOT NULL AND file_sha256 IS NOT NULL) OR
        (evidence_type = 'policy_link'  AND linked_document_id IS NOT NULL) OR
        (evidence_type = 'external_url' AND evidence_url IS NOT NULL AND length(trim(evidence_url)) > 0) OR
        (evidence_type = 'note'         AND evidence_note IS NOT NULL AND length(trim(evidence_note)) > 0)
    )
);

CREATE INDEX idx_control_evidences_soa ON control_evidences (soa_entry_id, created_at DESC);
CREATE INDEX idx_control_evidences_doc ON control_evidences (linked_document_id);

CREATE TRIGGER trg_audit_soa_entries
AFTER INSERT OR UPDATE OR DELETE ON soa_entries
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TRIGGER trg_audit_control_evidences
AFTER INSERT OR UPDATE OR DELETE ON control_evidences
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TABLE risk_scenarios (
    id                              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reference_code                  VARCHAR(32) NOT NULL UNIQUE,
    title                           VARCHAR(200) NOT NULL,
    threat_description              TEXT NOT NULL,
    vulnerability_description       TEXT,
    affected_information_asset_id   UUID REFERENCES information_assets(id) ON DELETE SET NULL,
    affected_system_asset_id        UUID REFERENCES system_assets(id) ON DELETE SET NULL,
    owner_unit_id                   UUID REFERENCES organization_units(id) ON DELETE SET NULL,
    owner_user_id                   UUID REFERENCES users(id) ON DELETE SET NULL,
    inherent_likelihood             SMALLINT NOT NULL CHECK (inherent_likelihood BETWEEN 1 AND 5),
    inherent_impact                 SMALLINT NOT NULL CHECK (inherent_impact BETWEEN 1 AND 5),
    treatment_strategy              VARCHAR(32) NOT NULL DEFAULT 'mitigate' CHECK (treatment_strategy IN ('mitigate', 'accept', 'avoid', 'transfer')),
    treatment_plan                  TEXT,
    acceptance_justification        TEXT,
    accepted_by_user_id             UUID REFERENCES users(id) ON DELETE SET NULL,
    accepted_at                     TIMESTAMPTZ,
    residual_likelihood             SMALLINT NOT NULL CHECK (residual_likelihood BETWEEN 1 AND 5),
    residual_impact                 SMALLINT NOT NULL CHECK (residual_impact BETWEEN 1 AND 5),
    status                          VARCHAR(32) NOT NULL DEFAULT 'identified' CHECK (status IN ('identified', 'assessed', 'treating', 'accepted', 'closed')),
    next_review_due_at              TIMESTAMPTZ,
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_risk_scenarios_status ON risk_scenarios (status);
CREATE INDEX idx_risk_scenarios_unit ON risk_scenarios (owner_unit_id);
CREATE INDEX idx_risk_scenarios_review ON risk_scenarios (next_review_due_at);
CREATE INDEX idx_risk_scenarios_info_asset ON risk_scenarios (affected_information_asset_id);
CREATE INDEX idx_risk_scenarios_sys_asset ON risk_scenarios (affected_system_asset_id);

CREATE TABLE risk_control_links (
    risk_id      UUID NOT NULL REFERENCES risk_scenarios(id) ON DELETE CASCADE,
    soa_entry_id UUID NOT NULL REFERENCES soa_entries(id) ON DELETE CASCADE,
    PRIMARY KEY (risk_id, soa_entry_id)
);

CREATE INDEX idx_risk_control_links_soa ON risk_control_links (soa_entry_id);

CREATE TRIGGER trg_audit_risk_scenarios
AFTER INSERT OR UPDATE OR DELETE ON risk_scenarios
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();
