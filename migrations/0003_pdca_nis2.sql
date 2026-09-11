CREATE TABLE security_incidents (
    id                           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reference_code               VARCHAR(32) NOT NULL UNIQUE,
    title                        VARCHAR(255) NOT NULL,
    description                  TEXT NOT NULL,
    severity                     VARCHAR(16) NOT NULL DEFAULT 'medium'
                                     CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status                       VARCHAR(32) NOT NULL DEFAULT 'detected'
                                     CHECK (status IN ('detected', 'analyzing', 'contained', 'eradicated', 'closed')),
    affected_system_asset_id     UUID REFERENCES system_assets(id) ON DELETE SET NULL,
    owner_unit_id                UUID REFERENCES organization_units(id) ON DELETE SET NULL,
    reported_by_user_id          UUID REFERENCES users(id) ON DELETE SET NULL,
    lead_handler_id              UUID REFERENCES users(id) ON DELETE SET NULL,
    detected_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    contained_at                 TIMESTAMPTZ,
    resolved_at                  TIMESTAMPTZ,
    is_nis2_significant          BOOLEAN NOT NULL DEFAULT FALSE,
    early_warning_due_at         TIMESTAMPTZ,
    early_warning_submitted_at   TIMESTAMPTZ,
    incident_report_due_at       TIMESTAMPTZ,
    incident_report_submitted_at TIMESTAMPTZ,
    final_report_due_at          TIMESTAMPTZ,
    final_report_submitted_at    TIMESTAMPTZ,
    bsi_ticket_reference         VARCHAR(100),
    nis2_alert_24h_sent_at       TIMESTAMPTZ,
    nis2_alert_72h_sent_at       TIMESTAMPTZ,
    root_cause_analysis          TEXT,
    lessons_learned              TEXT,
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_incidents_status ON security_incidents (status);
CREATE INDEX idx_security_incidents_nis2 ON security_incidents (is_nis2_significant, status);
CREATE INDEX idx_security_incidents_unit ON security_incidents (owner_unit_id);
CREATE INDEX idx_security_incidents_reporter ON security_incidents (reported_by_user_id);
CREATE INDEX idx_security_incidents_detected ON security_incidents (detected_at DESC);

CREATE TABLE incident_timeline_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES security_incidents(id) ON DELETE CASCADE,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    author_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    note        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incident_timeline_incident
    ON incident_timeline_events (incident_id, occurred_at ASC, created_at ASC);

CREATE TRIGGER trg_audit_security_incidents
AFTER INSERT OR UPDATE OR DELETE ON security_incidents
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TRIGGER trg_audit_incident_timeline_events
AFTER INSERT OR UPDATE OR DELETE ON incident_timeline_events
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TABLE internal_audits (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_code               VARCHAR(32) NOT NULL UNIQUE,
    title                    VARCHAR(200) NOT NULL,
    scope                    TEXT NOT NULL,
    auditor_name             VARCHAR(200) NOT NULL,
    audit_date               DATE NOT NULL,
    status                   VARCHAR(32) NOT NULL DEFAULT 'planned'
                                 CHECK (status IN ('planned', 'in_progress', 'completed')),
    summary_report           TEXT,
    attached_report_key      TEXT,
    attached_report_filename VARCHAR(255),
    attached_report_sha256   CHAR(64),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_internal_audits_status ON internal_audits (status);
CREATE INDEX idx_internal_audits_date ON internal_audits (audit_date DESC);

CREATE TABLE audit_findings (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id           UUID NOT NULL REFERENCES internal_audits(id) ON DELETE CASCADE,
    finding_code       VARCHAR(32) NOT NULL,
    finding_type       VARCHAR(32) NOT NULL
                           CHECK (finding_type IN ('major_nc', 'minor_nc', 'observation', 'opportunity')),
    related_control_id UUID REFERENCES framework_controls(id) ON DELETE SET NULL,
    owner_unit_id      UUID REFERENCES organization_units(id) ON DELETE SET NULL,
    description        TEXT NOT NULL,
    status             VARCHAR(32) NOT NULL DEFAULT 'open'
                           CHECK (status IN ('open', 'action_planned', 'verified_closed')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (audit_id, finding_code)
);

CREATE INDEX idx_audit_findings_audit ON audit_findings (audit_id, finding_code);
CREATE INDEX idx_audit_findings_status ON audit_findings (status, finding_type);
CREATE INDEX idx_audit_findings_unit ON audit_findings (owner_unit_id);

CREATE TABLE management_reviews (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_date          DATE NOT NULL,
    period_label         VARCHAR(64) NOT NULL,
    participants         TEXT NOT NULL,
    status               VARCHAR(32) NOT NULL DEFAULT 'draft'
                             CHECK (status IN ('draft', 'approved')),
    kpi_snapshot_json    JSONB NOT NULL,
    management_decisions TEXT NOT NULL DEFAULT '',
    approved_by_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    approved_at          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_management_reviews_date ON management_reviews (review_date DESC);
CREATE INDEX idx_management_reviews_status ON management_reviews (status);

CREATE TRIGGER trg_audit_internal_audits
AFTER INSERT OR UPDATE OR DELETE ON internal_audits
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TRIGGER trg_audit_audit_findings
AFTER INSERT OR UPDATE OR DELETE ON audit_findings
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TRIGGER trg_audit_management_reviews
AFTER INSERT OR UPDATE OR DELETE ON management_reviews
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();

CREATE TABLE action_items (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reference_code            VARCHAR(32) NOT NULL UNIQUE,
    title                     VARCHAR(255) NOT NULL,
    description               TEXT,
    source_type               VARCHAR(32) NOT NULL DEFAULT 'general'
                                  CHECK (source_type IN (
                                      'risk_treatment',
                                      'soa_gap',
                                      'audit_finding',
                                      'incident_capa',
                                      'recurring_compliance',
                                      'general'
                                  )),
    linked_risk_id            UUID REFERENCES risk_scenarios(id) ON DELETE SET NULL,
    linked_soa_entry_id       UUID REFERENCES soa_entries(id) ON DELETE SET NULL,
    linked_audit_finding_id   UUID REFERENCES audit_findings(id) ON DELETE SET NULL,
    linked_incident_id        UUID REFERENCES security_incidents(id) ON DELETE SET NULL,
    assignee_user_id          UUID REFERENCES users(id) ON DELETE SET NULL,
    owner_unit_id             UUID REFERENCES organization_units(id) ON DELETE SET NULL,
    priority                  VARCHAR(16) NOT NULL DEFAULT 'medium'
                                  CHECK (priority IN ('low', 'medium', 'high', 'critical')),
    status                    VARCHAR(32) NOT NULL DEFAULT 'open'
                                  CHECK (status IN ('open', 'in_progress', 'review', 'done', 'cancelled')),
    due_date                  DATE,
    completed_at              TIMESTAMPTZ,
    verification_note         TEXT,
    verified_by_user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    recurrence_interval       VARCHAR(32)
                                  CHECK (recurrence_interval IS NULL OR recurrence_interval IN (
                                      'monthly',
                                      'quarterly',
                                      'semi_annually',
                                      'annually'
                                  )),
    recurrence_parent_id      UUID REFERENCES action_items(id) ON DELETE SET NULL,
    recurrence_next_generated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_action_items_due_status ON action_items (due_date, status);
CREATE INDEX idx_action_items_assignee ON action_items (assignee_user_id, status);
CREATE INDEX idx_action_items_unit ON action_items (owner_unit_id);
CREATE INDEX idx_action_items_risk ON action_items (linked_risk_id) WHERE linked_risk_id IS NOT NULL;
CREATE INDEX idx_action_items_soa ON action_items (linked_soa_entry_id) WHERE linked_soa_entry_id IS NOT NULL;
CREATE INDEX idx_action_items_finding ON action_items (linked_audit_finding_id) WHERE linked_audit_finding_id IS NOT NULL;
CREATE INDEX idx_action_items_incident ON action_items (linked_incident_id) WHERE linked_incident_id IS NOT NULL;

CREATE TRIGGER trg_audit_action_items
AFTER INSERT OR UPDATE OR DELETE ON action_items
FOR EACH ROW EXECUTE FUNCTION log_isms_entity_changes();
