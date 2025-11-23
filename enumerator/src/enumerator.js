// Node 18+
import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import pg from 'pg';

const OUT_FILE = process.env.OUT_FILE || './out/fetch_queue.ndjson';
const LAST_N_DAYS = parseInt(process.env.DAYS || '30', 10);
const CHUNK_LIMIT = parseInt(process.env.CHUNK_LIMIT || '200', 10);

const MAX_CHUNKS_ENV = process.env.MAX_ENUMERATOR_CHUNKS ?? process.env.MAX_CHUNKS;
let MAX_CHUNKS = 500;
if (MAX_CHUNKS_ENV !== undefined) {
  const parsed = parseInt(String(MAX_CHUNKS_ENV).trim(), 10);
  if (!Number.isNaN(parsed)) {
    MAX_CHUNKS = parsed;
  }
}
const UNBOUNDED_SCAN = MAX_CHUNKS <= 0;
const START_SINCE = process.env.START_SINCE || '0';
const LOCAL_ONLY = process.env.LOCAL_ONLY === 'true';
const SQS_URL = process.env.SQS_FETCH_URL;
const REGION = process.env.AWS_REGION || 'us-west-2';
const USER_AGENT = process.env.USER_AGENT || 'package-inferno-enumerator/1.0';
const MAX_RETRIES = parseInt(process.env.MAX_RETRIES || '5', 10);
const BACKOFF_MS = parseInt(process.env.BACKOFF_MS || '500', 10);
const DB_URL = process.env.DB_URL || null; // preferred in locked-down envs
const DB_SECRET_NAME = process.env.DB_SECRET_NAME || null;
const DB_ENDPOINT = process.env.DB_ENDPOINT || null;
const DB_NAME = process.env.DB_NAME || 'packageinferno';
const ENUMERATOR_DISABLE_DB = process.env.ENUMERATOR_DISABLE_DB === 'true';
const QUEUE_MODE = process.env.QUEUE_MODE || (SQS_URL && !LOCAL_ONLY ? 'sqs' : 'file');
const SEEDS = (process.env.SEEDS || '').trim();
const SEEDS_FILE = process.env.SEEDS_FILE || null;
const SINCE_RAW = process.env.SINCE;
const SINCE_OVERRIDE = SINCE_RAW && !['0', 'null', 'undefined', ''].includes(SINCE_RAW.trim().toLowerCase()) ? SINCE_RAW : null;
const SEED_FROM_FEED = process.env.SEED_FROM_FEED === 'true';
const ALL_DOCS_URL = 'https://replicate.npmjs.com/registry/_all_docs';
const CHANGES_URL = 'https://replicate.npmjs.com/registry/_changes';
const CHECK_CHANGES_FIRST = process.env.CHECK_CHANGES_FIRST !== 'false'; // default true

const sqsClient = new SQSClient({ region: REGION });
const secretsClient = new SecretsManagerClient({ region: REGION });
let pgPool = null;

function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

async function fetchWithRetry(url, options, maxRetries = MAX_RETRIES) {
  let attempt = 0;
  for (;;) {
    const res = await fetch(url, options).catch(err => ({ ok: false, status: 0, _err: err }));
    if (res && res.ok) return res;
    const status = res && res.status ? res.status : 0;
    const retryable = status === 429 || (status >= 500 && status < 600) || status === 0;
    if (!retryable || attempt >= maxRetries) {
      if (res && res._err) throw res._err;
      throw new Error(`HTTP ${status} for ${url}`);
    }
    const jitter = Math.floor(Math.random() * 100);
    const delay = Math.min(30_000, BACKOFF_MS * Math.pow(2, attempt)) + jitter;
    await sleep(delay);
    attempt++;
  }
}

function daysAgoISO(days){
  const d = new Date(Date.now() - days*24*60*60*1000);
  return d.toISOString();
}

function latestTimeFromMeta(meta){
  if (!meta || !meta.time) return null;
  let latest = null;
  for (const k of Object.keys(meta.time)){
    const v = meta.time[k];
    const t = new Date(v).getTime();
    if (!isNaN(t)){
      if (latest === null || t > latest) latest = t;
    }
  }
  return latest ? new Date(latest) : null;
}

async function fetchAllDocsPage(startKey = null, limit = CHUNK_LIMIT){
  let url = `${ALL_DOCS_URL}?limit=${limit}`;
  if (startKey) {
    url += `&startkey=${encodeURIComponent(JSON.stringify(startKey))}`;
  }
  console.log('fetching all_docs', startKey ? `startkey=${startKey} limit=${limit}` : `limit=${limit}`);
  const res = await fetchWithRetry(url, { headers: { 'User-Agent': USER_AGENT }});
  const json = await res.json();
  return json;
}

async function fetchRecentChanges(limit = 200){
  const url = `${CHANGES_URL}?limit=${limit}`;
  console.log('fetching recent changes', url);
  try {
    const res = await fetchWithRetry(url, { headers: { 'User-Agent': USER_AGENT, 'npm-replication-opt-in': 'true' }});
    const json = await res.json();
    return json.results || [];
  } catch (e) {
    console.warn('changes fetch failed, skipping:', e.message);
    return [];
  }
}

async function fetchMetadata(pkgName){
  const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}`;
  const res = await fetchWithRetry(url, { headers: { 'User-Agent': USER_AGENT }});
  return await res.json();
}

function touchedInLastNDays(meta, days){
  const lt = latestTimeFromMeta(meta);
  if (!lt) return true; // if unknown, keep
  return lt >= new Date(Date.now() - days*24*60*60*1000);
}

async function enqueue(record){
  if (QUEUE_MODE === 'file') {
    fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
    fs.appendFileSync(OUT_FILE, JSON.stringify(record) + "\n");
    return;
  }
  if (QUEUE_MODE === 'sqs' && SQS_URL) {
    const cmd = new SendMessageCommand({ QueueUrl: SQS_URL, MessageBody: JSON.stringify(record) });
    await sqsClient.send(cmd);
  }
  // db mode: we already upserted versions with status 'queued'
}

function loadSeeds(){
  let seeds = [];
  if (SEEDS) {
    seeds = SEEDS.split(',').map(s => s.trim()).filter(Boolean);
  }
  if (SEEDS_FILE && fs.existsSync(SEEDS_FILE)) {
    const lines = fs.readFileSync(SEEDS_FILE, 'utf-8').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    seeds = seeds.concat(lines);
  }
  return Array.from(new Set(seeds));
}

function loadState(){
  const statePath = path.join(path.dirname(OUT_FILE), 'enumerator_state.json');
  try {
    const raw = fs.readFileSync(statePath, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return { last_seq: '0', last_startkey: null, last_run: null };
  }
}

function saveState(state){
  const statePath = path.join(path.dirname(OUT_FILE), 'enumerator_state.json');
  fs.mkdirSync(path.dirname(statePath), { recursive: true });
  fs.writeFileSync(statePath, JSON.stringify(state, null, 2));
}

async function main(){
  // SEED_FROM_FEED mode removed; use _all_docs by default
  const seeds = loadSeeds();
  if (seeds.length > 0) {
    console.log('enumerating from seeds', seeds.length);
    if (!ENUMERATOR_DISABLE_DB && (DB_URL || (DB_SECRET_NAME && DB_ENDPOINT))) {
      pgPool = await connectPostgres();
    }
    for (const name of seeds) {
      try {
        const meta = await fetchMetadata(name);
        if (!meta) continue;
        const latest = meta['dist-tags']?.latest;
        if (!latest) continue;
        const v = meta.versions?.[latest];
        if (!v?.dist?.tarball) continue;
        const rec = {
          name,
          version: latest,
          tarball: v.dist.tarball,
          integrity: v.dist.integrity || null,
          shasum: v.dist.shasum || null,
          published_at: meta.time?.[latest] || null,
          meta_head: meta.time?.modified || null
        };
        rec.queued_at = new Date().toISOString();
        rec.source = 'enumerator';
        if (pgPool) await upsertPackageVersion(pgPool, rec);
        await enqueue(rec);
        console.log('enqueued', name+'@'+latest);
      } catch(e) {
        console.error('seed err', name, e.message);
      }
    }
    console.log('done (seeds)');
    return;
  }

  // Hybrid mode: check recent changes first, then continue _all_docs scan
  console.log(`config: chunkLimit=${CHUNK_LIMIT}, maxChunks=${UNBOUNDED_SCAN ? 'unbounded' : MAX_CHUNKS}`);
  const state = loadState();
  
  if (!ENUMERATOR_DISABLE_DB && (DB_URL || (DB_SECRET_NAME && DB_ENDPOINT))) {
    pgPool = await connectPostgres();
  }
  
  let processed = 0;
  let newVersions = 0;
  
  // Step 1: Check _changes feed for recent updates (catches new releases immediately)
  if (CHECK_CHANGES_FIRST) {
    console.log('checking recent changes feed...');
    const changes = await fetchRecentChanges(200);
    for (const c of changes) {
      if (c.deleted) continue;
      const name = c.id;
      try {
        const meta = await fetchMetadata(name);
        if (!meta) continue;
        const latest = meta['dist-tags']?.latest;
        if (!latest) continue;
        
        // Check if already analyzed
        if (pgPool) {
          const existing = await pgPool.query(
            'SELECT v.id, v.status FROM packages p JOIN versions v ON p.id = v.package_id WHERE p.name = $1 AND v.version = $2',
            [name, latest]
          );
          if (existing.rows.length > 0 && existing.rows[0].status === 'analyzed') {
            continue;
          }
        }
        
        const v = meta.versions?.[latest];
        if (!v?.dist?.tarball) continue;
        
        const rec = {
          name,
          version: latest,
          tarball: v.dist.tarball,
          integrity: v.dist.integrity || null,
          shasum: v.dist.shasum || null,
          published_at: meta.time?.[latest] || null,
          meta_head: meta.time?.modified || null
        };
        rec.queued_at = new Date().toISOString();
        rec.source = 'enumerator';
        
        if (pgPool) await upsertPackageVersion(pgPool, rec);
        await enqueue(rec);
        processed++;
        newVersions++;
        
        if (processed % 10 === 0) console.log(`changes: enqueued ${processed} new`);
      } catch (e) {
        // skip individual errors
      }
    }
    console.log(`changes feed: enqueued ${processed} new versions`);
  }
  
  // Step 2: Continue _all_docs scan from cursor
  const resumeFrom = SINCE_OVERRIDE ? null : state.last_startkey;
  console.log('enumerating via _all_docs', resumeFrom ? `(resume from ${resumeFrom})` : '(fresh scan)');
  
  let startKey = resumeFrom;
  
  for (let chunkIndex = 0; UNBOUNDED_SCAN || chunkIndex < MAX_CHUNKS; chunkIndex++) {
    const result = await fetchAllDocsPage(startKey, CHUNK_LIMIT);
    const rows = result.rows || [];
    const pageLabel = UNBOUNDED_SCAN ? 'unbounded' : MAX_CHUNKS;
    console.log(`page ${chunkIndex + 1}/${pageLabel} count: ${rows.length}`);
    
    for (const row of rows) {
      const name = row.id || row.key;
      if (!name || name.startsWith('_design/')) continue;
      
      try {
        const meta = await fetchMetadata(name);
        if (!meta) continue;
        
        const latest = meta['dist-tags']?.latest;
        if (!latest) continue;
        
        // Check if we've already analyzed this version
        if (pgPool) {
          const existing = await pgPool.query(
            'SELECT v.id, v.status FROM packages p JOIN versions v ON p.id = v.package_id WHERE p.name = $1 AND v.version = $2',
            [name, latest]
          );
          if (existing.rows.length > 0 && existing.rows[0].status === 'analyzed') {
            continue; // skip already-analyzed versions
          }
        }
        
        const v = meta.versions?.[latest];
        if (!v?.dist?.tarball) continue;
        
        const rec = {
          name,
          version: latest,
          tarball: v.dist.tarball,
          integrity: v.dist.integrity || null,
          shasum: v.dist.shasum || null,
          published_at: meta.time?.[latest] || null,
          meta_head: meta.time?.modified || null
        };
        rec.queued_at = new Date().toISOString();
        rec.source = 'enumerator';
        
        if (pgPool) await upsertPackageVersion(pgPool, rec);
        await enqueue(rec);
        processed++;
        newVersions++;
        
        if (processed % 25 === 0) console.log(`enqueued so far: ${processed} (${newVersions} new)`);
      } catch (e) {
        // skip individual errors
      }
    }
    
    if (rows.length < CHUNK_LIMIT) {
      // Reached end, reset cursor for next full scan
      startKey = null;
      break;
    }
    startKey = rows[rows.length - 1].id || rows[rows.length - 1].key;
  }
  
  // Save state for next run
  saveState({
    last_seq: state.last_seq,
    last_startkey: startKey,
    last_run: new Date().toISOString(),
    last_processed: processed,
    last_new: newVersions
  });
  
  console.log(`done, enqueued ${processed} (${newVersions} new versions)`);
}

async function connectPostgres(){
  try {
    if (DB_URL) {
      const pool = new pg.Pool({ connectionString: DB_URL, max: 4 });
      await pool.query('SELECT 1');
      return pool;
    }
    const secret = await secretsClient.send(new GetSecretValueCommand({ SecretId: DB_SECRET_NAME }));
    const creds = JSON.parse(secret.SecretString || '{}');
    const pool = new pg.Pool({ host: DB_ENDPOINT, user: creds.username, password: creds.password, database: DB_NAME, port: 5432, max: 4 });
    await pool.query('SELECT 1');
    return pool;
  } catch (e) {
    console.error('db connect failed', e.message);
    return null;
  }
}

async function upsertPackageVersion(pool, rec){
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const pkg = await client.query(
      `INSERT INTO packages(name, ecosystem, last_seen) VALUES($1,'npm',now())
       ON CONFLICT(name) DO UPDATE SET last_seen=EXCLUDED.last_seen RETURNING id`, [rec.name]
    );
    const packageId = pkg.rows[0].id;
    await client.query(
      `INSERT INTO versions(package_id, version, tarball_url, integrity, shasum, published_at, status)
       VALUES($1,$2,$3,$4,$5,$6,'queued')
       ON CONFLICT(package_id, version) DO UPDATE SET tarball_url=EXCLUDED.tarball_url, integrity=EXCLUDED.integrity, shasum=EXCLUDED.shasum, published_at=EXCLUDED.published_at`,
      [packageId, rec.version, rec.tarball, rec.integrity, rec.shasum, rec.published_at]
    );
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('db upsert failed', rec.name, rec.version, e.message);
  } finally {
    client.release();
  }
}

main().catch(err => { console.error(err); process.exit(1); });


