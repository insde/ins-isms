CREATE INDEX idx_document_versions_status_doc
    ON document_versions (status, document_id);

CREATE INDEX idx_control_evidences_soa_type
    ON control_evidences (soa_entry_id, evidence_type);

CREATE INDEX idx_audit_logs_action_occurred
    ON audit_logs (action, occurred_at DESC);

CREATE VIEW v_system_asset_effective_protection AS
WITH ranked_links AS (
    SELECT
        ias.system_asset_id,
        cl.id AS level_id,
        cl.code AS level_code,
        cl.name AS level_name,
        cl.rank AS level_rank,
        cl.badge_color,
        CASE ia.confidentiality
            WHEN 'very_high' THEN 3
            WHEN 'high' THEN 2
            ELSE 1
        END AS c_rank,
        CASE ia.integrity
            WHEN 'very_high' THEN 3
            WHEN 'high' THEN 2
            ELSE 1
        END AS i_rank,
        CASE ia.availability
            WHEN 'very_high' THEN 3
            WHEN 'high' THEN 2
            ELSE 1
        END AS a_rank
    FROM information_asset_systems ias
    JOIN information_assets ia ON ia.id = ias.information_asset_id
    JOIN classification_levels cl ON cl.id = ia.classification_level_id
),
max_level AS (
    SELECT DISTINCT ON (system_asset_id)
        system_asset_id,
        level_id,
        level_code,
        level_name,
        level_rank,
        badge_color
    FROM ranked_links
    ORDER BY system_asset_id, level_rank DESC, level_code ASC
),
max_cia AS (
    SELECT
        system_asset_id,
        COUNT(*)::BIGINT AS linked_information_assets_count,
        MAX(c_rank) AS max_c_rank,
        MAX(i_rank) AS max_i_rank,
        MAX(a_rank) AS max_a_rank
    FROM ranked_links
    GROUP BY system_asset_id
)
SELECT
    sa.id AS system_asset_id,
    sa.asset_code,
    sa.name,
    sa.asset_type,
    sa.criticality,
    ml.level_id AS effective_level_id,
    ml.level_code AS effective_level_code,
    ml.level_name AS effective_level_name,
    ml.level_rank AS effective_level_rank,
    ml.badge_color AS effective_badge_color,
    CASE mc.max_c_rank
        WHEN 3 THEN 'very_high'
        WHEN 2 THEN 'high'
        WHEN 1 THEN 'normal'
        ELSE NULL
    END AS effective_confidentiality,
    CASE mc.max_i_rank
        WHEN 3 THEN 'very_high'
        WHEN 2 THEN 'high'
        WHEN 1 THEN 'normal'
        ELSE NULL
    END AS effective_integrity,
    CASE mc.max_a_rank
        WHEN 3 THEN 'very_high'
        WHEN 2 THEN 'high'
        WHEN 1 THEN 'normal'
        ELSE NULL
    END AS effective_availability,
    COALESCE(mc.linked_information_assets_count, 0) AS linked_information_assets_count
FROM system_assets sa
LEFT JOIN max_level ml ON ml.system_asset_id = sa.id
LEFT JOIN max_cia mc ON mc.system_asset_id = sa.id;

CREATE VIEW v_soa_export_summary AS
SELECT
    se.id AS soa_entry_id,
    cf.id AS framework_id,
    cf.code AS framework_code,
    cf.name AS framework_name,
    fc.id AS control_id,
    fc.code AS control_code,
    fc.domain,
    fc.title,
    fc.description,
    fc.sort_order,
    se.is_applicable,
    se.justification,
    se.implementation_status,
    se.implementation_notes,
    se.target_date,
    se.updated_at,
    se.owner_unit_id,
    ou.name AS owner_unit_name,
    se.owner_user_id,
    u.full_name AS owner_user_name,
    COUNT(ce.id)::BIGINT AS evidence_count,
    COUNT(ce.id) FILTER (WHERE ce.verified_at IS NOT NULL)::BIGINT AS verified_evidence_count
FROM soa_entries se
JOIN framework_controls fc ON fc.id = se.control_id
JOIN compliance_frameworks cf ON cf.id = fc.framework_id
LEFT JOIN organization_units ou ON ou.id = se.owner_unit_id
LEFT JOIN users u ON u.id = se.owner_user_id
LEFT JOIN control_evidences ce ON ce.soa_entry_id = se.id
GROUP BY
    se.id,
    cf.id,
    cf.code,
    cf.name,
    fc.id,
    fc.code,
    fc.domain,
    fc.title,
    fc.description,
    fc.sort_order,
    se.is_applicable,
    se.justification,
    se.implementation_status,
    se.implementation_notes,
    se.target_date,
    se.updated_at,
    se.owner_unit_id,
    ou.name,
    se.owner_user_id,
    u.full_name;
