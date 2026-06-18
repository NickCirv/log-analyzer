<div align="center">

# log-analyzer

**Instant traffic analysis for Nginx, Apache, and JSON logs — right in your terminal**

[![License: MIT](https://img.shields.io/badge/license-MIT-brightgreen?labelColor=0B0A09)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?labelColor=0B0A09)](package.json)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen?labelColor=0B0A09)](package.json)

</div>

## Install

```bash
npx github:NickCirv/log-analyzer access.log
```

## Usage

```bash
# Analyze a log file
npx github:NickCirv/log-analyzer access.log

# Show only errors (4xx/5xx), last 10 000 lines, output as JSON
npx github:NickCirv/log-analyzer access.log --errors --tail 10000 --format json
```

| Flag | Description |
|------|-------------|
| `--errors` | Show only 4xx/5xx error entries |
| `--ip <address>` | Filter to a single IP address |
| `--since "<time>"` | Entries after a time, e.g. `"1 hour ago"` or `"2024-01-01"` |
| `--tail <N>` | Analyze only the last N lines |
| `--format json\|table` | Output format (default: `table`) |
| `-h, --help` | Show help |

## What it does

Reads Nginx/Apache combined logs or NDJSON log files and prints a summary of traffic volume, status code breakdown, top IPs and URLs, an hourly timeline, and any IPs exceeding 100 requests/minute (flagged as suspicious). The `--format json` flag outputs the same data as structured JSON, suitable for piping into other tools.

---
<sub>Zero dependencies · Node 18+ · MIT · by <a href="https://github.com/NickCirv">NickCirv</a></sub>
