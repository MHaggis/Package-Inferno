import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch';
import { S3Client, PutObjectCommand, GetBucketLocationCommand } from "@aws-sdk/client-s3";
import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand, SendMessageCommand } from "@aws-sdk/client-sqs";
import crypto from 'crypto';

const LOCAL_ONLY = process.env.LOCAL_ONLY === 'true';
const IN_FILE = process.env.IN_FILE || './out/fetch_queue.ndjson';
const DOWNLOAD_DIR = process.env.DOWNLOAD_DIR || './downloads';
const S3_BUCKET = process.env.S3_BUCKET || process.env.S3_TARBALLS || null;
const REGION = process.env.AWS_REGION || 'us-west-2';
const S3_REGION = process.env.S3_REGION || REGION;
const USER_AGENT = process.env.USER_AGENT || 'package-inferno-fetcher/1.0';
const MAX_RETRIES = parseInt(process.env.MAX_RETRIES || '5', 10);
const BACKOFF_MS = parseInt(process.env.BACKOFF_MS || '500', 10);
const SQS_FETCH_URL = process.env.SQS_FETCH_URL || null;
const SQS_ANALYZE_URL = process.env.SQS_ANALYZE_URL || null;
const DB_SECRET_NAME = process.env.DB_SECRET_NAME || null;
const DB_ENDPOINT = process.env.DB_ENDPOINT || null;
const DB_NAME = process.env.DB_NAME || 'packageinferno';
const QUEUE_MODE = process.env.QUEUE_MODE || (SQS_FETCH_URL && !LOCAL_ONLY ? 'sqs' : 'file');

let s3 = new S3Client({ region: S3_REGION });
async function ensureS3Region() {
  if (!S3_BUCKET) return;
  try {
    const resp = await s3.send(new GetBucketLocationCommand({ Bucket: S3_BUCKET }));
    // AWS returns null or 'EU' for some legacy buckets; normalize to us-east-1 when falsy
    const loc = resp.LocationConstraint || 'us-east-1';
    if (loc && s3.config.region !== loc) {
      s3 = new S3Client({ region: loc });
    }
  } catch (_) {
    // best-effort; keep current client
  }
}
const sqs = new SQSClient({ region: REGION });

function ensureDir(p){ fs.mkdirSync(p, { recursive: true }); }

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

async function verifyShasum(buffer, expectedShasum){
  if (!expectedShasum) return true;
  const shasum = crypto.createHash('sha1').update(buffer).digest('hex');
  return shasum === expectedShasum;
}

async function uploadToS3(key, body){
  if (!S3_BUCKET) throw new Error('S3_BUCKET not set');
  await ensureS3Region();
  const cmd = new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, Body: body });
  await s3.send(cmd);
}

async function processRecord(rec){
  const { name, version, tarball, shasum } = rec;
  console.log('fetching', name+'@'+version, tarball);
  const res = await fetchWithRetry(tarball, { headers: { 'User-Agent': USER_AGENT }});
  const buf = await res.arrayBuffer();
  const buffer = Buffer.from(buf);
  if (!await verifyShasum(buffer, shasum)) {
    console.warn('shasum mismatch for', name+'@'+version);
  }
  const p = path.join(DOWNLOAD_DIR, `${name.replace(/\//g,'__')}@${version}.tgz`);
  ensureDir(path.dirname(p));
  fs.writeFileSync(p, buffer);
  if (!LOCAL_ONLY && S3_BUCKET) {
    const key = `npm-raw-tarballs/${name}/${version}.tgz`;
    await uploadToS3(key, buffer);
    console.log('uploaded', key);
  } else {
    console.log('saved local', p);
  }
  if (QUEUE_MODE === 'sqs' && SQS_ANALYZE_URL) {
    const msg = {
      ...rec,
      name,
      version,
      fetched_at: new Date().toISOString(),
    };
    if (!msg.queued_at) {
      msg.queued_at = new Date().toISOString();
    }
    await sqs.send(new SendMessageCommand({ QueueUrl: SQS_ANALYZE_URL, MessageBody: JSON.stringify(msg) }));
  }
}

async function main(){
  ensureDir(DOWNLOAD_DIR);
  if (QUEUE_MODE === 'sqs' && SQS_FETCH_URL) {
    console.log('consuming SQS fetch queue...');
    for (;;) {
      const resp = await sqs.send(new ReceiveMessageCommand({ QueueUrl: SQS_FETCH_URL, MaxNumberOfMessages: 10, WaitTimeSeconds: 10 }));
      const messages = resp.Messages || [];
      if (!messages.length) continue;
      for (const m of messages) {
        try {
          const rec = JSON.parse(m.Body || '{}');
          await processRecord(rec);
          await sqs.send(new DeleteMessageCommand({ QueueUrl: SQS_FETCH_URL, ReceiptHandle: m.ReceiptHandle }));
        } catch (e) {
          console.error('fetch error', e.message);
        }
      }
    }
  } else { // file/db modes
    if (!fs.existsSync(IN_FILE)) {
      console.error('input file not found', IN_FILE);
      process.exit(1);
    }
    const rl = (await import('readline')).createInterface({ input: fs.createReadStream(IN_FILE), crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line.trim()) continue;
      const rec = JSON.parse(line);
      try {
        await processRecord(rec);
      } catch (e) {
        console.error('fetch error', e.message);
      }
    }
    console.log('fetcher done');
  }
}

main().catch(e => { console.error(e); process.exit(1); });


