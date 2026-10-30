ALTER TABLE system_assets
    DROP CONSTRAINT IF EXISTS system_assets_asset_type_check;

ALTER TABLE system_assets
    ADD CONSTRAINT system_assets_asset_type_check
    CHECK (asset_type IN (
        'server',
        'application',
        'cloud_service',
        'network',
        'endpoint',
        'facility',
        'ot_equipment',
        'vendor',
        'other'
    ));
