# Content Monitor

`monitor.py` is an asyncio-based reconnaissance helper that detects newly added
 domains, endpoints and JavaScript-referenced URLs as soon as they appear.
It is optimised for low latency, Discord-friendly alerting and zero disk usage,
making it suitable for long-running VPS deployments.

## Features

- HTTP/2-enabled asynchronous fetching with polite per-host rate limiting.
- Change detection backed by SHA-256 fingerprints, diff summarisation and
  confirmation re-fetches to reduce false positives.
- Lightweight HTML/JS scraping heuristics that ignore tracking parameters,
  cookie/session artefacts and trusted third-party hosts.
- In-memory LRU cache to keep memory bounded (default 1,024 resources ≈ <5 MiB).
- Discord webhook notifications with confidence scoring and direct source links.

## Quick start

```bash
python3 monitor.py --domain example.com --webhook https://discord.com/api/webhooks/... \
  --trusted-third-party google-analytics.com cdnjs.cloudflare.com
```

To watch several domains at once:

```bash
python3 monitor.py --domains-file targets.txt --webhook https://discord.com/api/webhooks/...
```

`targets.txt` should list one domain per line.

## Configuration

| Flag | Description | Default |
| ---- | ----------- | ------- |
| `--webhook` | Discord webhook endpoint (required). | – |
| `--domain` | Single domain to monitor. | – |
| `--domains-file` | File containing domains to monitor. | – |
| `--concurrency` | Maximum concurrent requests. | 10 |
| `--per-host-delay` | Minimum delay between requests to the same host (seconds). | 0.2 |
| `--verification-delay` | Delay before the second confirming fetch (seconds). | 0.5 |
| `--cache-size` | Maximum cached resource fingerprints. | 1024 |
| `--trusted-third-party` | Domains ignored when referenced from JS. | [] |
| `--allow-domains` | Optional allowlist. | None |
| `--deny-domains` | Optional denylist. | None |

## Discord payload format

Each notification includes:

- **Title** – concise change summary (e.g. `Endpoint change detected on foo.tld`).
- **Type** – one of `new-domain`, `new-endpoint`, `changed-js-url`.
- **Domain** – the monitored target.
- **Source** – page that triggered the detection.
- **File** – when the change originates from a JavaScript asset.
- **Confidence** – 0–1 score showing whether the confirmation fetch matched.

## Operational notes

- The LRU cache keeps only the most recent 1,024 fingerprints, ensuring the
  process stays under 10 MiB RSS in typical workloads. Tune `--cache-size`
  for larger portfolios.
- The second fetch confirmation (with a configurable delay) provides a simple
  frequency threshold to avoid alerting on jittery responses.
- Consider running via `systemd` or `pm2` and exporting secrets through
  environment variables.
