CREATE TABLE IF NOT EXISTS packages(
  id BIGSERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  ecosystem TEXT NOT NULL DEFAULT 'npm',
  author TEXT,
  description TEXT,
  dependents INT,
  last_seen TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS versions(
  id BIGSERIAL PRIMARY KEY,
  package_id BIGINT REFERENCES packages(id) ON DELETE CASCADE,
  version TEXT NOT NULL,
  tarball_url TEXT,
  integrity TEXT,
  shasum TEXT,
  published_at TIMESTAMPTZ,
  analyzed_at TIMESTAMPTZ,
  status TEXT DEFAULT 'queued',
  UNIQUE(package_id, version)
);

CREATE TABLE IF NOT EXISTS findings(
  id BIGSERIAL PRIMARY KEY,
  version_id BIGINT REFERENCES versions(id) ON DELETE CASCADE,
  rule TEXT NOT NULL,
  severity TEXT,
  details JSONB,
  file_path TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scores(
  version_id BIGINT PRIMARY KEY REFERENCES versions(id) ON DELETE CASCADE,
  score INT NOT NULL DEFAULT 0,
  label TEXT
);

CREATE TABLE IF NOT EXISTS run_state(
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMPTZ DEFAULT now()
);


-- Performance indexes for API queries
CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
CREATE INDEX IF NOT EXISTS idx_versions_pkg_analyzed ON versions(package_id, analyzed_at);
CREATE INDEX IF NOT EXISTS idx_findings_version ON findings(version_id);
CREATE INDEX IF NOT EXISTS idx_findings_rule_sev ON findings(rule, severity);
CREATE INDEX IF NOT EXISTS idx_scores_version ON scores(version_id);


