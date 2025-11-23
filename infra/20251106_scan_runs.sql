-- Scan history support: create table to record every analysis run per version
CREATE TABLE IF NOT EXISTS scan_runs (
    id BIGSERIAL PRIMARY KEY,
    version_id BIGINT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    source TEXT,
    queued_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    analyzer_version TEXT,
    config_hash TEXT,
    score INTEGER,
    label TEXT,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    findings JSONB,
    findings_s3_key TEXT,
    rerun_reason TEXT,
    requested_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_version_completed
    ON scan_runs(version_id, completed_at DESC);


