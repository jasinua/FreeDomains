#!/usr/bin/env node
'use strict';

/**
 * sync-dns.js — Cloudflare DNS sync script for free-domains
 *
 * Runs on push to main (i.e., after a PR is merged).
 * Reads which domain files were added, modified, or deleted in the last
 * commit and upserts / removes the corresponding Cloudflare DNS records.
 *
 * Required environment variables (stored in GitHub Secrets):
 *   CF_API_TOKEN  — Cloudflare API token (Zone:DNS:Edit on this zone only)
 *   CF_ZONE_ID    — Cloudflare Zone ID
 *   BASE_DOMAIN   — Root domain (e.g. "yourdomain.com")
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

// ---------------------------------------------------------------------------
// Configuration & constants
// ---------------------------------------------------------------------------

const REPO_ROOT = path.resolve(__dirname, '..');
const DOMAINS_DIR = path.join(REPO_ROOT, 'domains');

const CF_API_TOKEN = process.env.CF_API_TOKEN;
const CF_ZONE_ID = process.env.CF_ZONE_ID;
const BASE_DOMAIN = (process.env.BASE_DOMAIN || '').replace(/\.$/, ''); // strip trailing dot

function assertEnv() {
  const missing = [];
  if (!CF_API_TOKEN) missing.push('CF_API_TOKEN');
  if (!CF_ZONE_ID) missing.push('CF_ZONE_ID');
  if (!BASE_DOMAIN) missing.push('BASE_DOMAIN');

  if (missing.length > 0) {
    console.error(`Missing required environment variables: ${missing.join(', ')}`);
    process.exit(1);
  }

  // Basic sanity checks on env var shapes to catch configuration mistakes
  if (!/^[A-Za-z0-9_-]{20,}$/.test(CF_API_TOKEN)) {
    console.error('CF_API_TOKEN does not look like a valid Cloudflare API token.');
    process.exit(1);
  }
  if (!/^[a-f0-9]{32}$/.test(CF_ZONE_ID)) {
    console.error('CF_ZONE_ID does not look like a valid Cloudflare Zone ID (32 hex chars).');
    process.exit(1);
  }
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(BASE_DOMAIN)) {
    console.error(`BASE_DOMAIN "${BASE_DOMAIN}" does not look like a valid domain.`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Cloudflare API helpers (uses Node built-in https — no external deps)
// ---------------------------------------------------------------------------

/**
 * Makes an authenticated request to the Cloudflare v4 API.
 * Returns the parsed JSON body.
 * Throws on network error or non-2xx status.
 */
function cfRequest(method, endpoint, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;

    const options = {
      hostname: 'api.cloudflare.com',
      path: `/client/v4/zones/${CF_ZONE_ID}/${endpoint}`,
      method,
      headers: {
        Authorization: `Bearer ${CF_API_TOKEN}`,
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let parsed;
        try {
          parsed = JSON.parse(data);
        } catch (err) {
          return reject(new Error(`Failed to parse Cloudflare response: ${data}`));
        }
        if (!parsed.success) {
          const msgs = (parsed.errors || []).map((e) => `[${e.code}] ${e.message}`).join('; ');
          return reject(new Error(`Cloudflare API error: ${msgs || JSON.stringify(parsed)}`));
        }
        resolve(parsed);
      });
    });

    req.on('error', reject);

    if (payload) req.write(payload);
    req.end();
  });
}

/**
 * Returns all existing Cloudflare DNS records for `fullName` (e.g., "sub.example.com").
 */
async function listRecords(fullName) {
  const encoded = encodeURIComponent(fullName);
  const res = await cfRequest('GET', `dns_records?name=${encoded}&per_page=100`);
  return res.result || [];
}

/**
 * Creates a new DNS record.
 */
async function createRecord(fullName, type, value) {
  console.log(`  → Creating ${type} record for ${fullName} → ${value}`);
  await cfRequest('POST', 'dns_records', {
    type,
    name: fullName,
    content: value,
    ttl: 1,     // 1 = automatic TTL
    proxied: false,
  });
}

/**
 * Updates an existing DNS record by ID.
 */
async function updateRecord(recordId, fullName, type, value) {
  console.log(`  → Updating ${type} record for ${fullName} → ${value}`);
  await cfRequest('PUT', `dns_records/${recordId}`, {
    type,
    name: fullName,
    content: value,
    ttl: 1,
    proxied: false,
  });
}

/**
 * Deletes a DNS record by ID.
 */
async function deleteRecord(recordId, fullName) {
  console.log(`  → Deleting record ${recordId} for ${fullName}`);
  await cfRequest('DELETE', `dns_records/${recordId}`);
}

// ---------------------------------------------------------------------------
// Git helpers
// ---------------------------------------------------------------------------

/**
 * Returns changed files in the last commit, split into added/modified and deleted.
 */
function getChangedFiles() {
  const output = execSync('git diff --name-status --diff-filter=ACMRD HEAD~1 HEAD', {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  });

  const upsert = [];
  const deleted = [];

  for (const line of output.trim().split('\n').filter(Boolean)) {
    const [rawStatus, ...parts] = line.split('\t');
    const file = parts[parts.length - 1];
    const status = rawStatus.charAt(0);

    if (!file.startsWith('domains/')) continue;
    if (!file.endsWith('.json')) continue;
    if (path.basename(file) === '.gitkeep') continue;

    // Reject any path that isn't a direct child of domains/ (double-check)
    const rel = file.slice('domains/'.length);
    if (rel.includes('/')) continue;

    if (status === 'D') {
      deleted.push(file);
    } else {
      upsert.push(file);
    }
  }

  return { upsert, deleted };
}

// ---------------------------------------------------------------------------
// Main sync logic
// ---------------------------------------------------------------------------

async function processUpsert(file) {
  const filename = path.basename(file);
  const subdomain = filename.slice(0, -5); // strip .json
  const fullName = `${subdomain}.${BASE_DOMAIN}`;

  console.log(`\nProcessing UPSERT: ${fullName}`);

  // Resolve the full path and verify it is inside DOMAINS_DIR
  const resolvedPath = path.resolve(DOMAINS_DIR, filename);
  if (!resolvedPath.startsWith(DOMAINS_DIR + path.sep)) {
    throw new Error(`Path traversal detected for file: ${file}`);
  }

  let data;
  try {
    data = JSON.parse(fs.readFileSync(resolvedPath, 'utf8'));
  } catch (err) {
    throw new Error(`Failed to read/parse "${file}": ${err.message}`);
  }

  const type = data?.record?.type?.toUpperCase();
  const value = data?.record?.value?.trim();

  if (!type || !value) {
    throw new Error(`"${file}" is missing record.type or record.value.`);
  }

  // Fetch existing records for this name
  const existing = await listRecords(fullName);

  if (existing.length === 0) {
    await createRecord(fullName, type, value);
  } else {
    // Update the first matching record, delete the rest (clean up duplicates)
    await updateRecord(existing[0].id, fullName, type, value);
    for (const extra of existing.slice(1)) {
      console.log(`  → Removing duplicate record ${extra.id}`);
      await deleteRecord(extra.id, fullName);
    }
  }
}

async function processDelete(file) {
  const filename = path.basename(file);
  const subdomain = filename.slice(0, -5);
  const fullName = `${subdomain}.${BASE_DOMAIN}`;

  console.log(`\nProcessing DELETE: ${fullName}`);

  const existing = await listRecords(fullName);
  if (existing.length === 0) {
    console.log(`  → No records found for ${fullName}, nothing to delete.`);
    return;
  }

  for (const rec of existing) {
    await deleteRecord(rec.id, fullName);
  }
}

async function main() {
  assertEnv();

  let changedFiles;
  try {
    changedFiles = getChangedFiles();
  } catch (err) {
    console.error(`Failed to get changed files: ${err.message}`);
    process.exit(1);
  }

  const { upsert, deleted } = changedFiles;

  if (upsert.length === 0 && deleted.length === 0) {
    console.log('No domain files changed in this commit. Nothing to sync.');
    return;
  }

  console.log(`Syncing ${upsert.length} upsert(s) and ${deleted.length} deletion(s) to Cloudflare...`);

  let exitCode = 0;

  for (const file of upsert) {
    try {
      await processUpsert(file);
      console.log(`  ✅ Done: ${path.basename(file, '.json')}.${BASE_DOMAIN}`);
    } catch (err) {
      console.error(`  ❌ Failed to upsert "${file}": ${err.message}`);
      exitCode = 1;
    }
  }

  for (const file of deleted) {
    try {
      await processDelete(file);
      console.log(`  ✅ Deleted: ${path.basename(file, '.json')}.${BASE_DOMAIN}`);
    } catch (err) {
      console.error(`  ❌ Failed to delete "${file}": ${err.message}`);
      exitCode = 1;
    }
  }

  if (exitCode !== 0) {
    console.error('\nOne or more sync operations failed. Check the output above.');
    process.exit(1);
  }

  console.log('\n✅ All DNS records synced successfully.');
}

main().catch((err) => {
  console.error(`Unhandled error: ${err.message}`);
  process.exit(1);
});
