#!/usr/bin/env node
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { stat } from 'fs/promises';
import { resolve } from 'path';

// ── CLI args ─────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log(`
log-analyzer — Analyze web server and application logs

Usage:
  npx log-analyzer <file> [options]
  loga <file> [options]

Options:
  --since "<time>"    Filter entries after time (e.g. "1 hour ago", "2024-01-01")
  --errors            Show only error entries (4xx/5xx)
  --ip <address>      Filter to a single IP address
  --tail <N>          Analyze only the last N lines
  --format <fmt>      Output format: table (default) | json
  -h, --help          Show this help

Examples:
  npx log-analyzer access.log
  npx log-analyzer app.log --errors
  npx log-analyzer access.log --ip 192.168.1.1
  npx log-analyzer access.log --since "1 hour ago" --format json
  npx log-analyzer access.log --tail 10000
`);
  process.exit(0);
}

const filePath = resolve(args[0]);
const opts = {
  since: null,
  errorsOnly: args.includes('--errors'),
  ip: null,
  tail: null,
  format: 'table',
};

for (let i = 1; i < args.length; i++) {
  if (args[i] === '--since' && args[i + 1]) opts.since = args[++i];
  else if (args[i] === '--ip' && args[i + 1]) opts.ip = args[++i];
  else if (args[i] === '--tail' && args[i + 1]) opts.tail = parseInt(args[++i], 10);
  else if (args[i] === '--format' && args[i + 1]) opts.format = args[++i];
}

// ── Date parsing ──────────────────────────────────────────────────────────────
function parseSince(str) {
  if (!str) return null;
  const now = new Date();
  const m = str.match(/^(\d+)\s+(second|minute|hour|day|week)s?\s+ago$/i);
  if (m) {
    const n = parseInt(m[1], 10);
    const unit = m[2].toLowerCase();
    const ms = { second: 1e3, minute: 6e4, hour: 36e5, day: 864e5, week: 6048e5 }[unit];
    return new Date(now - n * ms);
  }
  const d = new Date(str);
  return isNaN(d) ? null : d;
}

const sinceDate = parseSince(opts.since);

// ── Log format parsers ────────────────────────────────────────────────────────

// Nginx/Apache Combined: IP - - [date] "METHOD /path HTTP/x" status size [ref] [ua]
const NGINX_RE = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+([^"]+)\s+\S+"\s+(\d+)\s+(\d+)/;

// Common Log Format (no ref/ua)
const CLF_RE = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+([^"]+)\s+\S+"\s+(\d+)\s+(\d+)/;

const NGINX_DATE_RE = /(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/;
const MONTHS = { Jan:0, Feb:1, Mar:2, Apr:3, May:4, Jun:5, Jul:6, Aug:7, Sep:8, Oct:9, Nov:10, Dec:11 };

function parseNginxDate(str) {
  const m = str.match(NGINX_DATE_RE);
  if (!m) return null;
  return new Date(Date.UTC(+m[3], MONTHS[m[2]], +m[1], +m[4], +m[5], +m[6]));
}

function parseNginx(line) {
  const m = line.match(NGINX_RE);
  if (!m) return null;
  const ts = parseNginxDate(m[2]);
  if (!ts) return null;
  return { ip: m[1], ts, method: m[3], url: m[4].split('?')[0], status: parseInt(m[5], 10), bytes: parseInt(m[6], 10) };
}

function parseJson(line) {
  try {
    const o = JSON.parse(line);
    const ts = o.time || o.timestamp || o.date || o['@timestamp'];
    const d = ts ? new Date(ts) : null;
    return {
      ip: o.ip || o.remote_addr || o.host || '-',
      ts: d && !isNaN(d) ? d : null,
      method: o.method || '-',
      url: (o.url || o.path || o.uri || '-').split('?')[0],
      status: parseInt(o.status || o.statusCode || o.status_code || 0, 10),
      bytes: parseInt(o.bytes || o.size || o.content_length || 0, 10),
    };
  } catch {
    return null;
  }
}

// ── Stats accumulators ────────────────────────────────────────────────────────
class Stats {
  constructor() {
    this.total = 0;
    this.parsed = 0;
    this.statusCodes = new Map();
    this.ips = new Map();
    this.urls = new Map();
    this.urlTimes = new Map();
    this.hourBuckets = new Map();
    this.minBuckets = new Map();
    this.errors = new Map(); // "STATUS url" -> count
    this.earliest = null;
    this.latest = null;
  }

  add(entry) {
    if (!entry) return;
    const { ip, ts, url, status, bytes } = entry;

    this.parsed++;

    // status codes
    this.statusCodes.set(status, (this.statusCodes.get(status) || 0) + 1);

    // IPs
    this.ips.set(ip, (this.ips.get(ip) || 0) + 1);

    // URLs
    this.urls.set(url, (this.urls.get(url) || 0) + 1);
    if (bytes > 0) {
      const prev = this.urlTimes.get(url) || { sum: 0, count: 0 };
      this.urlTimes.set(url, { sum: prev.sum + bytes, count: prev.count + 1 });
    }

    // Errors
    if (status >= 400) {
      const key = `${status} ${url}`;
      this.errors.set(key, (this.errors.get(key) || 0) + 1);
    }

    // Timeline
    if (ts) {
      if (!this.earliest || ts < this.earliest) this.earliest = ts;
      if (!this.latest || ts > this.latest) this.latest = ts;

      const hKey = `${ts.getUTCFullYear()}-${String(ts.getUTCMonth()+1).padStart(2,'0')}-${String(ts.getUTCDate()).padStart(2,'0')} ${String(ts.getUTCHours()).padStart(2,'0')}h`;
      this.hourBuckets.set(hKey, (this.hourBuckets.get(hKey) || 0) + 1);

      const mKey = `${ts.getUTCFullYear()}-${String(ts.getUTCMonth()+1).padStart(2,'0')}-${String(ts.getUTCDate()).padStart(2,'0')} ${String(ts.getUTCHours()).padStart(2,'0')}:${String(ts.getUTCMinutes()).padStart(2,'0')}`;
      this.minBuckets.set(mKey, (this.minBuckets.get(mKey) || 0) + 1);
    }
  }

  peakPerMin() {
    let peak = 0;
    for (const v of this.minBuckets.values()) if (v > peak) peak = v;
    return peak;
  }

  avgPerSec() {
    if (!this.earliest || !this.latest || this.earliest === this.latest) return 0;
    const secs = (this.latest - this.earliest) / 1000;
    return secs > 0 ? (this.parsed / secs).toFixed(2) : 0;
  }

  errorRate() {
    let errs = 0;
    for (const [k, v] of this.statusCodes) if (k >= 400) errs += v;
    return this.parsed > 0 ? ((errs / this.parsed) * 100).toFixed(1) : '0.0';
  }

  topN(map, n = 10) {
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  }

  suspiciousIPs() {
    const suspicious = [];
    for (const [ip, count] of this.ips) {
      if (!this.earliest || !this.latest) continue;
      const mins = Math.max(1, (this.latest - this.earliest) / 60000);
      if (count / mins > 100) suspicious.push({ ip, count, rate: (count / mins).toFixed(1) });
    }
    return suspicious;
  }

  floodIPs() {
    // IPs with >100 404s
    const ip404 = new Map();
    return ip404; // populated separately
  }
}

// ── Renderer ──────────────────────────────────────────────────────────────────
function bar(val, max, width = 20) {
  const filled = max > 0 ? Math.round((val / max) * width) : 0;
  const empty = width - filled;
  return '█'.repeat(filled) + '░'.repeat(empty);
}

function pad(str, n) {
  return String(str).padEnd(n);
}

function padL(str, n) {
  return String(str).padStart(n);
}

function renderTable(stats, fileName, totalLines, format) {
  if (format === 'json') {
    const out = {
      file: fileName,
      total_lines: totalLines,
      parsed: stats.parsed,
      date_range: {
        from: stats.earliest?.toISOString() || null,
        to: stats.latest?.toISOString() || null,
      },
      traffic: {
        requests: stats.parsed,
        avg_req_sec: parseFloat(stats.avgPerSec()),
        peak_req_min: stats.peakPerMin(),
        error_rate_pct: parseFloat(stats.errorRate()),
      },
      status_codes: Object.fromEntries(stats.statusCodes),
      top_ips: stats.topN(stats.ips),
      top_urls: stats.topN(stats.urls).map(([url, hits]) => ({
        url,
        hits,
        avg_bytes: stats.urlTimes.get(url) ? Math.round(stats.urlTimes.get(url).sum / stats.urlTimes.get(url).count) : null,
      })),
      errors: stats.topN(stats.errors),
      hourly_timeline: [...stats.hourBuckets.entries()].sort(),
      suspicious_ips: stats.suspiciousIPs(),
    };
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  const SEP = '━'.repeat(50);
  console.log(`\nlog-analyzer · ${fileName} (${totalLines.toLocaleString()} lines)`);
  console.log(SEP);

  // Traffic summary
  const dateRange = stats.earliest
    ? `${stats.earliest.toISOString().slice(0,16).replace('T',' ')} → ${stats.latest.toISOString().slice(0,16).replace('T',' ')} UTC`
    : 'unknown';
  console.log(`\nTraffic: ${stats.parsed.toLocaleString()} requests · ${stats.avgPerSec()} req/sec · peak ${stats.peakPerMin()}/min`);
  console.log(`Period:  ${dateRange}`);
  console.log(`Errors:  ${stats.errorRate()}% error rate`);

  // Status codes
  console.log('\nStatus Codes:');
  const statusEntries = [...stats.statusCodes.entries()].sort((a, b) => b[1] - a[1]);
  for (const [code, count] of statusEntries) {
    const pct = ((count / stats.parsed) * 100).toFixed(1);
    const flag = code >= 500 ? '  \x1b[31m🔴\x1b[0m' : code >= 400 ? '  \x1b[33m⚠\x1b[0m' : '';
    console.log(`  ${pad(code + ' ', 8)} ${padL(count.toLocaleString(), 8)}  (${padL(pct, 5)}%)${flag}`);
  }

  // Top IPs
  console.log('\nTop 10 IPs by requests:');
  const suspicious = new Set(stats.suspiciousIPs().map(s => s.ip));
  for (const [ip, count] of stats.topN(stats.ips)) {
    const flag = suspicious.has(ip) ? '  \x1b[33m⚠ suspicious\x1b[0m' : '';
    console.log(`  ${pad(ip, 18)} ${padL(count.toLocaleString(), 8)} requests${flag}`);
  }

  // Top URLs
  console.log('\nTop 10 URLs by hits:');
  for (const [url, hits] of stats.topN(stats.urls)) {
    const t = stats.urlTimes.get(url);
    const avg = t ? `  ${Math.round(t.sum / t.count)} avg bytes` : '';
    const display = url.length > 40 ? url.slice(0, 37) + '...' : url;
    console.log(`  ${pad(display, 42)} ${padL(hits.toLocaleString(), 8)} hits${avg}`);
  }

  // Error log
  if (stats.errors.size > 0) {
    console.log('\nError Log (4xx/5xx):');
    for (const [key, count] of stats.topN(stats.errors, 20)) {
      const display = key.length > 50 ? key.slice(0, 47) + '...' : key;
      console.log(`  ${padL(count.toLocaleString(), 6)}x  ${display}`);
    }
  }

  // Hourly timeline
  if (stats.hourBuckets.size > 0) {
    console.log('\nTraffic Timeline (hourly):');
    const sorted = [...stats.hourBuckets.entries()].sort();
    const maxVal = Math.max(...sorted.map(([,v]) => v));
    for (const [label, count] of sorted) {
      const b = bar(count, maxVal, 24);
      const hourLabel = label.slice(-3); // "XXh"
      console.log(`  ${hourLabel}  ${b}  ${count.toLocaleString()}`);
    }
  }

  // Suspicious patterns
  const susp = stats.suspiciousIPs();
  if (susp.length > 0) {
    console.log('\n\x1b[33mSuspicious Patterns:\x1b[0m');
    for (const { ip, count, rate } of susp) {
      console.log(`  ⚠ ${ip}  ${count.toLocaleString()} reqs  (${rate} req/min — possible bot/scanner)`);
    }
  }

  console.log('\n' + SEP);
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  let fileSize = 0;
  try {
    const info = await stat(filePath);
    fileSize = info.size;
  } catch {
    console.error(`Error: Cannot open file: ${filePath}`);
    process.exit(1);
  }

  const fileName = filePath.split('/').pop();
  const stats = new Stats();
  let lineCount = 0;
  let detectedFormat = null;
  let allLines = [];
  const useBuffer = opts.tail !== null;

  process.stderr.write(`Scanning ${fileName}...`);

  const rl = createInterface({
    input: createReadStream(filePath),
    crlfDelay: Infinity,
  });

  for await (const line of rl) {
    if (!line.trim()) continue;
    lineCount++;

    // Show progress every 50k lines
    if (lineCount % 50000 === 0) {
      process.stderr.write(` ${lineCount.toLocaleString()}...`);
    }

    if (useBuffer) {
      allLines.push(line);
    } else {
      processLine(line, lineCount, stats, detectedFormat, (fmt) => { detectedFormat = fmt; });
    }
  }

  process.stderr.write(' done.\n');

  // Apply --tail
  if (useBuffer) {
    const slice = allLines.slice(-opts.tail);
    for (const line of slice) {
      processLine(line, lineCount, stats, detectedFormat, (fmt) => { detectedFormat = fmt; });
    }
  }

  if (opts.format === 'json') {
    renderTable(stats, fileName, lineCount, 'json');
  } else {
    renderTable(stats, fileName, lineCount, 'table');
    console.log(`Format: ${detectedFormat || 'unknown'} · Parsed: ${stats.parsed.toLocaleString()}/${lineCount.toLocaleString()} lines`);
  }
}

function processLine(line, lineNum, stats, detectedFormat, setFormat) {
  // Detect format on first parseable line
  if (!detectedFormat) {
    if (tryJson(line)) {
      setFormat('JSON/NDJSON');
    } else if (NGINX_RE.test(line)) {
      setFormat('Nginx/Apache Combined');
    } else {
      setFormat('Common Log Format');
    }
  }

  let entry = null;
  const fmt = detectedFormat;

  if (fmt === 'JSON/NDJSON') {
    entry = parseJson(line);
  } else {
    entry = parseNginx(line);
  }

  if (!entry) return;

  // Filters
  if (opts.ip && entry.ip !== opts.ip) return;
  if (opts.errorsOnly && entry.status < 400) return;
  if (sinceDate && entry.ts && entry.ts < sinceDate) return;

  stats.total++;
  stats.add(entry);
}

function tryJson(line) {
  try { JSON.parse(line); return true; } catch { return false; }
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
