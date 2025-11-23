# PackageInferno Scanning Guide

## How I Tested and Validated the Setup

### Initial Testing: Specific Package Seeds

**What I did first:**
```bash
export SEEDS="is-odd,is-even"
./scripts/run_pipeline.sh
```

**Why these packages?**
- Small and fast to download (~3KB each)
- Simple structure for debugging
- Actually triggered findings (typosquatting, URLs, suspicious patterns)
- Perfect for validating the full pipeline works end-to-end

**Results from initial test:**
- `is-odd`: Score 39 (malicious) - 8 findings including typosquatting
- `is-even`: Score 14 (malicious) - 4 findings

**This proved:** ✅ Database works, ✅ Analyzer detects threats, ✅ Dashboard displays results

---

### Scaling Up: Registry Scan

**After validation, I ran a broader scan:**
```bash
# Clean previous state
rm -rf downloads/* out/*

# Configure pagination (2 pages of 10 = 20 packages)
export MAX_CHUNKS=2
export CHUNK_LIMIT=10
unset SEEDS                # Critical: disables seeds mode

# Run the scan
docker compose run --rm enumerator
docker compose run --rm fetcher
docker compose run --rm analyzer
```

**What happened:**
1. Enumerator checked recent changes feed → found 2 updates
2. Enumerator paginated through _all_docs → fetched 20 packages
3. **Total: 22 packages queued**
4. Fetcher downloaded all 22 tarballs
5. Analyzer scanned everything and detected threats

**Top findings:**
```
Package                   | Score | Label      | Findings
--------------------------|-------|------------|----------
rendition                 | 606   | malicious  | 153
vs-deploy                 | 454   | malicious  | 119
--123hoodmane-pyodide     | 213   | malicious  | 46
```

**What made `rendition` (score 606!) so suspicious?**
- 57× `url_outside_allowlist` - Non-allowed domains
- 46× `suspicious_pattern` - Shell/eval patterns  
- 12× `advanced_obfuscation` - Hex encoding, XOR
- 6× `big_base64_blob` - Large encoded payloads

---

## How the Enumerator Works

### Three Discovery Modes (Can Run Together)

#### 1. Seeds Mode (Highest Priority)
If `SEEDS` or `SEEDS_FILE` is set:
- Processes only specified packages
- Skips pagination entirely
- Fetches metadata for each seed
- Queues latest version
- **Use for:** Targeted investigations, testing

```bash
export SEEDS="lodash,express,axios"
docker compose run --rm enumerator
```

#### 2. Changes Feed (Automatic)
Always checks `_changes` endpoint first:
- Enabled by default (`CHECK_CHANGES_FIRST=true`)
- Fetches last 200 updates from npm
- Deduplicates against DB (skips analyzed versions)
- **Use for:** Catching new releases immediately

#### 3. All Docs Scan (Bulk Mode)
Paginates through npm's complete package list:
- Uses cursor-based pagination
- Saves state to `enumerator_state.json`
- Can be paused and resumed
- Controlled by `MAX_CHUNKS` and `CHUNK_LIMIT`
- **Use for:** Comprehensive audits

---

## Scanning Strategies

### Strategy 1: Audit Specific Packages
**Use case:** Investigate known packages or your dependencies

```bash
# From command line
export SEEDS="axios,lodash,express"
./scripts/run_pipeline.sh

# Or from file
cat package.json | jq -r '.dependencies | keys[]' > deps.txt
export SEEDS_FILE=deps.txt
./scripts/run_pipeline.sh
```

**Runtime:** Seconds to minutes  
**Storage:** Minimal (~KB per package)  
**Ideal for:** CI/CD, dependency audits, quick checks

---

### Strategy 2: Sample Scan
**Use case:** Understand threat landscape, tune detection rules

```bash
export MAX_CHUNKS=10      # 10 pages
export CHUNK_LIMIT=50     # 50 packages/page
unset SEEDS
./scripts/run_pipeline.sh
```

**Runtime:** 1-2 hours  
**Coverage:** 500 packages  
**Storage:** ~50MB tarballs, ~5MB findings  
**Ideal for:** Testing, rule tuning, demos

---

### Strategy 3: Full Registry Scan
**Use case:** Comprehensive supply chain security audit

```bash
export MAX_CHUNKS=0       # 0 = unbounded
export CHUNK_LIMIT=100
unset SEEDS
./scripts/run_pipeline.sh
```

**Runtime:** Days  
**Coverage:** 2M+ packages  
**Storage:** 100GB+ tarballs, 10GB+ database  
**Ideal for:** Threat intelligence, research, finding all typosquatters

---

### Strategy 4: Continuous Monitoring
**Use case:** Watch for new malicious packages daily

```bash
# Add to crontab (runs daily at 2am)
0 2 * * * cd /path/to/project && MAX_CHUNKS=5 CHUNK_LIMIT=100 ./scripts/run_pipeline.sh

# Or run manually for today's updates
MAX_CHUNKS=1 CHUNK_LIMIT=200 ./scripts/run_pipeline.sh
```

The changes feed automatically catches new releases, perfect for monitoring.

---

## State Management & Resume

The enumerator saves progress to `./out/enumerator_state.json`:

```json
{
  "last_seq": "0",
  "last_startkey": "--hepl",
  "last_run": "2025-11-23T19:24:49.123Z",
  "last_processed": 22,
  "last_new": 22
}
```

**Resume automatically:**
```bash
./scripts/run_pipeline.sh  # Picks up where it left off
```

**Force fresh scan:**
```bash
rm -f out/enumerator_state.json
./scripts/run_pipeline.sh
```

---

## Real-World Examples

### Example 1: Audit Your Project's Dependencies

```bash
# Extract dependencies from package.json
cat package.json | jq -r '.dependencies, .devDependencies | keys[]' | sort -u > my-deps.txt

# Scan them
export SEEDS_FILE=my-deps.txt
./scripts/run_pipeline.sh

# View in dashboard
docker compose up -d dashboard
open http://localhost:8501
```

---

### Example 2: Monitor High-Value Targets

```bash
# Create watchlist of popular packages
cat > watchlist.txt <<EOF
@anthropic-ai/sdk
openai
express
react
vue
angular
typescript
webpack
lodash
axios
EOF

export SEEDS_FILE=watchlist.txt
./scripts/run_pipeline.sh
```

---

### Example 3: Find All Typosquatters

```bash
# Full registry scan
export MAX_CHUNKS=0
./scripts/run_pipeline.sh

# Query for typosquatting attempts
docker exec -it pi-postgres psql -U piuser -d packageinferno -c "
  SELECT 
    p.name,
    f.details->>'target_package' as impersonating,
    f.details->>'similarity' as similarity,
    f.details->>'typosquat_type' as attack_type
  FROM packages p
  JOIN versions v ON p.id = v.package_id
  JOIN findings f ON v.id = f.version_id
  WHERE f.rule = 'typosquat_detected'
  ORDER BY (f.details->>'similarity')::float DESC
  LIMIT 50;
"
```

---

## Performance Tips

### Speed Up Scans

**1. Disable YARA if not needed:**
```yaml
# scan.yml
analysis:
  yara:
    enabled: false
```

**2. Increase chunk size:**
```bash
export CHUNK_LIMIT=200  # More packages per page
```

**3. Skip database writes (local-only):**
```bash
export DB_URL=""  # Findings still written to JSON files
./scripts/run_pipeline.sh
```

---

### Reduce Storage

**1. Delete tarballs after analysis:**
```bash
# After pipeline completes
rm -rf downloads/*
```

**2. Keep only latest scan results:**
```sql
DELETE FROM scan_runs WHERE id NOT IN (
  SELECT MAX(id) FROM scan_runs GROUP BY version_id
);
```

---

## Troubleshooting

### Enumerator seems stuck

Check progress:
```bash
docker compose logs -f enumerator
cat out/enumerator_state.json
```

### Fetcher getting rate-limited (HTTP 429)

Increase backoff:
```bash
export MAX_RETRIES=10
export BACKOFF_MS=2000
docker compose run --rm fetcher
```

### Analyzer out of memory

Reduce YARA limits:
```yaml
# scan.yml
analysis:
  yara:
    max_file_size_mb: 5
    timeout_seconds: 10
```

### Database connection errors

```bash
docker compose restart db
sleep 5
./scripts/init_db.sh
```

---

## Summary: Testing vs Production

| Aspect | Initial Testing (Seeds) | Production (Registry) |
|--------|------------------------|----------------------|
| **Command** | `SEEDS="pkg1,pkg2"` | `MAX_CHUNKS=10 CHUNK_LIMIT=50` |
| **Speed** | Seconds | Minutes to Days |
| **Packages** | 2-10 | 500 - 2M+ |
| **Purpose** | Validate setup | Find threats at scale |
| **Storage** | < 1MB | GB to TB |
| **Database** | Optional | Recommended |

**My recommendation:**
1. ✅ Start with seeds mode (2-5 packages) to validate
2. ✅ Run a small batch scan (50-100 packages) to tune rules
3. ✅ Scale to full registry if needed for research/intel

Happy hunting! 🔥

