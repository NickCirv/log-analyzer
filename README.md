# log-analyzer
> Analyze web server logs instantly. Traffic patterns, errors, suspicious IPs, timeline.

```bash
npx log-analyzer access.log
npx log-analyzer app.log --errors
```

```
log-analyzer · access.log (42,891 lines)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Traffic: 42,891 requests · 14.2 req/sec · peak 87/min

Status Codes:
  200 OK          38,421  (89.6%)
  404 Not Found    1,847   (4.3%)  ⚠
  500 Error          514   (1.2%)  🔴

Top IPs:
  192.168.1.42   2,341 requests  ⚠ suspicious

Traffic Timeline (hourly):
  12h  ████████████████████  8,421
  13h  ███████████░░░░░░░░░  4,209
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Commands
| Command | Description |
|---------|-------------|
| `log-analyzer <file>` | Analyze log file |
| `--errors` | Show only errors |
| `--ip <address>` | Filter to one IP |
| `--tail N` | Last N lines only |
| `--format json\|table` | Output format |

## Install
```bash
npx log-analyzer access.log
npm install -g log-analyzer
```

---
**Zero dependencies** · **Node 18+** · Made by [NickCirv](https://github.com/NickCirv) · MIT
