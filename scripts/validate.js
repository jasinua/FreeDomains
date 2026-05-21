#!/usr/bin/env node
'use strict';

/**
 * validate.js — PR validation script for free-domains
 *
 * Security considerations implemented:
 * - Rejects any PR that touches files outside domains/
 * - Prevents path traversal in filenames
 * - Enforces owner.username === PR author (stops impersonation)
 * - Validates A/AAAA values against private/reserved IP ranges (SSRF prevention)
 * - Blocks NS, MX, TXT records (prevents DNS delegation & domain takeover)
 * - Enforces one subdomain per GitHub user
 * - Blocklist of reserved and brand-name subdomains
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REPO_ROOT = path.resolve(__dirname, '..');
const DOMAINS_DIR = path.join(REPO_ROOT, 'domains');

/** Only these record types are permitted. */
const ALLOWED_TYPES = new Set(['A', 'AAAA', 'CNAME']);

/**
 * Subdomain label rules (RFC 1123):
 *   - Lowercase alphanumeric + hyphens
 *   - Cannot start or end with a hyphen
 *   - 1–63 characters
 */
const SUBDOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$|^[a-z0-9]$/;

/**
 * Permanently reserved / blocked subdomain prefixes.
 * Extend this list freely — it is checked case-insensitively.
 */
const BLOCKLIST = new Set([
  // Infrastructure
  'www', 'mail', 'email', 'smtp', 'pop', 'pop3', 'imap', 'imap4',
  'ftp', 'sftp', 'ssh', 'telnet',
  'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
  'mx', 'mx1', 'mx2', 'relay',
  'api', 'apis', 'rest', 'graphql', 'grpc', 'rpc', 'soap',
  'dev', 'development', 'test', 'testing', 'staging', 'stage', 'uat',
  'prod', 'production', 'live',
  'admin', 'administrator', 'root', 'system', 'sysadmin',
  'cpanel', 'whm', 'plesk', 'webmail', 'roundcube',
  'cdn', 'static', 'assets', 'media', 'img', 'images', 'files', 'upload',
  'download', 'downloads', 'storage',
  'status', 'monitor', 'metrics', 'health', 'uptime', 'ping', 'dashboard',
  'panel', 'control', 'console', 'manage', 'management',
  'auth', 'login', 'signin', 'signup', 'register', 'registration',
  'account', 'accounts', 'password', 'reset', 'verify', 'verification',
  'secure', 'security', 'ssl', 'tls', 'vpn', 'proxy', 'gateway',
  'portal', 'help', 'support', 'docs', 'documentation', 'wiki',
  'blog', 'news', 'forum', 'community',
  'shop', 'store', 'checkout', 'cart', 'payment', 'billing', 'invoice',
  // Brand names — prevent phishing / impersonation
  'google', 'gmail', 'youtube', 'googlemail',
  'facebook', 'instagram', 'whatsapp', 'messenger', 'meta',
  'twitter', 'x', 'tweet',
  'apple', 'icloud', 'itunes', 'appstore',
  'microsoft', 'outlook', 'hotmail', 'live', 'bing', 'msn', 'office',
  'amazon', 'aws', 'azure', 'gcp', 'firebase',
  'netflix', 'spotify', 'twitch', 'tiktok', 'snapchat', 'reddit', 'linkedin',
  'paypal', 'stripe', 'visa', 'mastercard', 'amex',
  'github', 'gitlab', 'bitbucket', 'npmjs', 'npm',
  'cloudflare', 'vercel', 'netlify', 'heroku', 'digitalocean', 'linode',
  'discord', 'slack', 'zoom', 'teams', 'meet',
  'coinbase', 'binance', 'kraken', 'bitcoin', 'ethereum', 'crypto', 'nft', 'wallet',
  // Abusive / content
  'nsfw', 'adult', 'xxx', 'porn', 'sex', 'nude', 'cam',
  'hack', 'crack', 'warez', 'pirate', 'torrent',
  'phish', 'phishing', 'scam', 'spam', 'malware', 'virus', 'ransomware',
  'ban', 'takedown', 'abuse', 'report',
]);

/**
 * Private, loopback, link-local and reserved IPv4/IPv6 ranges.
 * A/AAAA records pointing to these are rejected to prevent DNS rebinding
 * and SSRF-like attacks.
 */
const PRIVATE_IP_RE = [
  // IPv4
  /^0\./,                                          // 0.0.0.0/8
  /^10\./,                                         // 10.0.0.0/8 (RFC 1918)
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,    // 100.64.0.0/10 (shared)
  /^127\./,                                        // 127.0.0.0/8 (loopback)
  /^169\.254\./,                                   // 169.254.0.0/16 (link-local)
  /^172\.(1[6-9]|2\d|3[01])\./,                  // 172.16.0.0/12 (RFC 1918)
  /^192\.0\.0\./,                                  // 192.0.0.0/24 (IETF protocol)
  /^192\.0\.2\./,                                  // 192.0.2.0/24 (TEST-NET-1)
  /^192\.168\./,                                   // 192.168.0.0/16 (RFC 1918)
  /^198\.18\./,                                    // 198.18.0.0/15 (benchmarking)
  /^198\.51\.100\./,                               // 198.51.100.0/24 (TEST-NET-2)
  /^203\.0\.113\./,                                // 203.0.113.0/24 (TEST-NET-3)
  /^22[4-9]\.|^2[3-4]\d\.|^25[0-5]\./,           // 224.0.0.0/4+ (multicast & reserved)
  /^255\.255\.255\.255$/,                          // broadcast

  // IPv6
  /^::1$/,             // loopback
  /^::/,               // unspecified / :: prefix
  /^fe80:/i,           // link-local
  /^fc[0-9a-f]{2}:/i, // ULA fc00::/7
  /^fd[0-9a-f]{2}:/i, // ULA fd00::/7
  /^ff[0-9a-f]{2}:/i, // multicast
  /^64:ff9b:/i,        // IPv4-mapped / NAT64
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isPrivateIP(ip) {
  return PRIVATE_IP_RE.some((re) => re.test(ip));
}

function isValidIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d+$/.test(p)) return false;
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

function isValidIPv6(ip) {
  // RFC 4291 — allow full and compressed forms
  if (ip === '::') return true;
  // Must contain only hex digits, colons, and an optional trailing /prefix
  if (!/^[0-9a-fA-F:]{2,39}$/.test(ip)) return false;
  const groups = ip.split(':');
  if (groups.length < 3 || groups.length > 8) return false;
  const doubleColonCount = (ip.match(/::/g) || []).length;
  if (doubleColonCount > 1) return false;
  return groups.every((g) => g === '' || /^[0-9a-fA-F]{1,4}$/.test(g));
}

function isValidHostname(hostname) {
  if (!hostname || hostname.length > 253) return false;
  // Remove trailing dot (fully-qualified)
  const h = hostname.endsWith('.') ? hostname.slice(0, -1) : hostname;
  return h.split('.').every((label) =>
    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$|^[a-zA-Z0-9]$/.test(label)
  );
}

/**
 * Returns {status: 'A'|'D'|'M', file: string}[] for files in this PR.
 * Only safe git arguments are passed — no user data enters the shell command.
 */
function getChangedFiles() {
  const baseRef = process.env.GITHUB_BASE_REF;
  let diffOutput;

  if (baseRef) {
    // Sanitise the branch name — only allow safe characters
    if (!/^[a-zA-Z0-9/_.-]+$/.test(baseRef)) {
      fail(`Invalid GITHUB_BASE_REF value: "${baseRef}"`);
    }
    // Fetch the base ref so the diff target exists locally
    try {
      execSync(`git fetch --depth=1 origin ${baseRef}`, {
        cwd: REPO_ROOT,
        stdio: 'pipe',
      });
    } catch {
      // Might already be fetched; continue
    }
    diffOutput = execSync(`git diff --name-status --diff-filter=ACMRD origin/${baseRef}...HEAD`, {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    });
  } else {
    // Local / non-Actions run — diff against previous commit
    diffOutput = execSync('git diff --name-status --diff-filter=ACMRD HEAD~1 HEAD', {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    });
  }

  return diffOutput
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const [rawStatus, ...parts] = line.split('\t');
      return { status: rawStatus.charAt(0), file: parts[parts.length - 1] };
    });
}

const errors = [];
const warnings = [];

function fail(msg) {
  errors.push(`❌ ${msg}`);
}

function warn(msg) {
  warnings.push(`⚠️  ${msg}`);
}

// ---------------------------------------------------------------------------
// Main validation
// ---------------------------------------------------------------------------

function main() {
  const prAuthor = (process.env.PR_AUTHOR || '').trim().toLowerCase();
  if (!prAuthor) {
    fail('PR_AUTHOR environment variable is not set.');
    report();
    return;
  }

  let changedFiles;
  try {
    changedFiles = getChangedFiles();
  } catch (err) {
    fail(`Could not determine changed files: ${err.message}`);
    report();
    return;
  }

  if (changedFiles.length === 0) {
    fail('No files were changed in this PR.');
    report();
    return;
  }

  // ------------------------------------------------------------------
  // SECURITY CHECK 1: All changed files must be inside domains/
  // This prevents PRs that modify workflow files or other critical files
  // ------------------------------------------------------------------
  const outsideDomains = changedFiles.filter(({ file }) => !file.startsWith('domains/'));
  if (outsideDomains.length > 0) {
    fail(
      `PR must only change files inside the \`domains/\` directory.\n` +
        `  The following files are outside \`domains/\`:\n` +
        outsideDomains.map(({ file }) => `    - ${file}`).join('\n')
    );
    report();
    return;
  }

  // ------------------------------------------------------------------
  // SECURITY CHECK 2: Files must be direct children of domains/ (no subdir)
  // ------------------------------------------------------------------
  const inSubDir = changedFiles.filter(({ file }) => {
    const rel = file.slice('domains/'.length);
    return rel.includes('/') || rel.includes('\\');
  });
  if (inSubDir.length > 0) {
    fail(
      `Files must be placed directly inside \`domains/\`, not in sub-directories:\n` +
        inSubDir.map(({ file }) => `    - ${file}`).join('\n')
    );
  }

  // Only one file may be added per PR (prevents bulk registrations)
  const addedFiles = changedFiles.filter(({ status }) => status === 'A');
  if (addedFiles.length > 1) {
    fail(`Only one new domain file may be added per PR. This PR adds ${addedFiles.length}.`);
  }

  // ------------------------------------------------------------------
  // Per-file validation
  // ------------------------------------------------------------------
  for (const { status, file } of changedFiles) {
    validateFile(file, status, prAuthor);
  }

  // ------------------------------------------------------------------
  // One-domain-per-user check (only for newly added files)
  // ------------------------------------------------------------------
  if (addedFiles.length === 1 && errors.length === 0) {
    const newFile = addedFiles[0].file;
    checkOneDomainPerUser(prAuthor, newFile);
  }

  report();
}

function validateFile(file, status, prAuthor) {
  const filename = path.basename(file); // e.g., "my-app.json"

  // Must end in .json
  if (!filename.endsWith('.json')) {
    fail(`File "${file}" must have a .json extension.`);
    return;
  }

  const subdomain = filename.slice(0, -5); // strip .json

  // ------------------------------------------------------------------
  // SECURITY CHECK 3: Path traversal prevention
  // Resolve the full path and ensure it is inside DOMAINS_DIR
  // ------------------------------------------------------------------
  const resolvedPath = path.resolve(DOMAINS_DIR, filename);
  if (!resolvedPath.startsWith(DOMAINS_DIR + path.sep)) {
    fail(`Path traversal detected in filename: "${file}"`);
    return;
  }

  // ------------------------------------------------------------------
  // Subdomain format validation
  // ------------------------------------------------------------------
  if (!SUBDOMAIN_RE.test(subdomain)) {
    fail(
      `"${subdomain}" is not a valid subdomain. ` +
        `Use only lowercase letters (a-z), digits (0-9), and hyphens (-). ` +
        `Cannot start or end with a hyphen. Max 63 characters.`
    );
    return;
  }

  // Blocklist check
  if (BLOCKLIST.has(subdomain.toLowerCase())) {
    fail(`"${subdomain}" is a reserved subdomain and cannot be registered.`);
    return;
  }

  // Skip JSON validation for deleted files
  if (status === 'D') {
    return;
  }

  // ------------------------------------------------------------------
  // JSON parsing
  // ------------------------------------------------------------------
  let raw;
  try {
    raw = fs.readFileSync(resolvedPath, 'utf8');
  } catch (err) {
    fail(`Could not read "${file}": ${err.message}`);
    return;
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    fail(`"${file}" contains invalid JSON: ${err.message}`);
    return;
  }

  // ------------------------------------------------------------------
  // Schema validation (manual — no external deps for supply chain safety)
  // ------------------------------------------------------------------
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    fail(`"${file}": Root must be a JSON object.`);
    return;
  }

  const { owner, record } = data;

  // owner block
  if (!owner || typeof owner !== 'object' || Array.isArray(owner)) {
    fail(`"${file}": Missing or invalid "owner" object.`);
    return;
  }
  if (typeof owner.username !== 'string' || !owner.username.trim()) {
    fail(`"${file}": "owner.username" must be a non-empty string.`);
    return;
  }
  if (typeof owner.email !== 'string' || !owner.email.trim()) {
    fail(`"${file}": "owner.email" must be a non-empty string.`);
    return;
  }
  if (!/.+@.+\..+/.test(owner.email)) {
    fail(`"${file}": "owner.email" does not look like a valid email address.`);
    return;
  }

  // ------------------------------------------------------------------
  // SECURITY CHECK 4: owner.username must equal the authenticated PR author
  // This prevents impersonation — someone filing a domain on behalf of another.
  // ------------------------------------------------------------------
  if (owner.username.trim().toLowerCase() !== prAuthor) {
    fail(
      `"${file}": "owner.username" is "${owner.username}" but this PR was opened by ` +
        `"${prAuthor}". They must match.`
    );
  }

  // record block
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    fail(`"${file}": Missing or invalid "record" object.`);
    return;
  }
  if (typeof record.type !== 'string') {
    fail(`"${file}": "record.type" must be a string.`);
    return;
  }
  if (typeof record.value !== 'string' || !record.value.trim()) {
    fail(`"${file}": "record.value" must be a non-empty string.`);
    return;
  }

  const type = record.type.toUpperCase();
  const value = record.value.trim();

  // ------------------------------------------------------------------
  // SECURITY CHECK 5: Allowlist record types only
  // ------------------------------------------------------------------
  if (!ALLOWED_TYPES.has(type)) {
    fail(
      `"${file}": Record type "${record.type}" is not allowed. ` +
        `Only ${[...ALLOWED_TYPES].join(', ')} are permitted.`
    );
    return;
  }

  // ------------------------------------------------------------------
  // SECURITY CHECK 6: Validate record value based on type
  // ------------------------------------------------------------------
  if (type === 'A') {
    if (!isValidIPv4(value)) {
      fail(`"${file}": "record.value" is not a valid IPv4 address: "${value}"`);
      return;
    }
    if (isPrivateIP(value)) {
      fail(
        `"${file}": "record.value" "${value}" is a private/reserved IP address ` +
          `and cannot be used for public DNS records.`
      );
    }
  } else if (type === 'AAAA') {
    if (!isValidIPv6(value)) {
      fail(`"${file}": "record.value" is not a valid IPv6 address: "${value}"`);
      return;
    }
    if (isPrivateIP(value)) {
      fail(
        `"${file}": "record.value" "${value}" is a private/reserved IPv6 address ` +
          `and cannot be used for public DNS records.`
      );
    }
  } else if (type === 'CNAME') {
    if (!isValidHostname(value)) {
      fail(`"${file}": "record.value" is not a valid hostname for a CNAME record: "${value}"`);
      return;
    }
    // Warn about potential subdomain takeover risk
    if (
      value.endsWith('.herokuapp.com') ||
      value.endsWith('.azurewebsites.net') ||
      value.endsWith('.cloudapp.azure.com')
    ) {
      warn(
        `"${file}": CNAME target "${value}" points to a platform that can be subject ` +
          `to subdomain takeover if the upstream app is deleted. Ensure the app is active.`
      );
    }
  }

  // ------------------------------------------------------------------
  // Reject unexpected extra keys (loose schema enforcement)
  // ------------------------------------------------------------------
  const allowedTopKeys = new Set(['owner', 'record']);
  const extraTopKeys = Object.keys(data).filter((k) => !allowedTopKeys.has(k));
  if (extraTopKeys.length > 0) {
    fail(`"${file}": Unexpected top-level keys: ${extraTopKeys.join(', ')}. Only "owner" and "record" are allowed.`);
  }

  const allowedOwnerKeys = new Set(['username', 'email']);
  const extraOwnerKeys = Object.keys(owner).filter((k) => !allowedOwnerKeys.has(k));
  if (extraOwnerKeys.length > 0) {
    fail(`"${file}": Unexpected keys in "owner": ${extraOwnerKeys.join(', ')}.`);
  }

  const allowedRecordKeys = new Set(['type', 'value']);
  const extraRecordKeys = Object.keys(record).filter((k) => !allowedRecordKeys.has(k));
  if (extraRecordKeys.length > 0) {
    fail(`"${file}": Unexpected keys in "record": ${extraRecordKeys.join(', ')}.`);
  }
}

/**
 * SECURITY CHECK 7: One subdomain per GitHub user.
 * Scans all existing domain files to see if the PR author already has one.
 */
function checkOneDomainPerUser(prAuthor, newFile) {
  const newFilename = path.basename(newFile);
  let existingFiles;
  try {
    existingFiles = fs.readdirSync(DOMAINS_DIR).filter(
      (f) => f.endsWith('.json') && f !== newFilename && f !== '.gitkeep'
    );
  } catch {
    // domains/ doesn't exist yet — that's fine
    return;
  }

  for (const f of existingFiles) {
    const fullPath = path.join(DOMAINS_DIR, f);
    try {
      const data = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
      if (
        data?.owner?.username &&
        data.owner.username.trim().toLowerCase() === prAuthor
      ) {
        fail(
          `GitHub user "${prAuthor}" already owns the subdomain "${f.slice(0, -5)}". ` +
            `Only one subdomain per user is allowed. ` +
            `To change your record, modify your existing file instead of creating a new one.`
        );
        return;
      }
    } catch {
      // Ignore unreadable/invalid files in the existing tree — they'll be caught on their own PR
    }
  }
}

function report() {
  if (warnings.length > 0) {
    console.log('\n=== Validation Warnings ===');
    warnings.forEach((w) => console.log(w));
  }

  if (errors.length > 0) {
    console.log('\n=== Validation Failed ===');
    errors.forEach((e) => console.log(e));
    console.log(`\n${errors.length} error(s) found. Please fix them and update your PR.`);
    process.exit(1);
  }

  console.log('\n✅ All checks passed. Your domain request is valid.');
}

main();
