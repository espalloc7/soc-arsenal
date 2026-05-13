# Defender XDR Arsenal

**Version:** 2.0

Defender XDR Arsenal is a local, browser-based CTI workspace for building and reviewing hunting queries.
It combines two focused tools:

- `Indicator Composer` for assembling indicator lists and generating Advanced Hunting KQL
- `Phishing Query Helper` for building phishing-focused KQL from senders, URLs, subjects, and hashes

The project is designed for fast analyst workflows, lightweight local usage, and easy sharing.

## What it does

- Builds KQL from indicator and phishing inputs
- Keeps a compact query history inside the Arsenal launcher
- Lets you load previous work back into either workspace
- Includes guard-driven enrichment and provider lookups through the local broker
- Runs entirely as a local HTML-based experience, with no build step required

## Project structure

- `Arsenal.html` - main launcher and history hub
- `src/indicators.html` - indicator composer workspace
- `src/phishing.html` - phishing query helper workspace
- `guard_broker_env.js` - optional local guard broker for reputation and enrichment checks
- `.env` - API keys for the broker, if you want external provider lookups

## Getting started

1. Open `Arsenal.html` in a browser.
2. Use the left navigation to switch between the indicator and phishing workspaces.
3. Add indicators or phishing inputs, generate the KQL, and copy or review the output.

## Optional broker

If you want the enrichment layer and provider-backed guard checks to run locally:

```bash
npm install
npm start
```

The broker listens on `127.0.0.1:8787` by default.

## Environment variables

The broker reads provider keys from `.env`:

- `VT_API_KEY`
- `ABUSEIPDB_API_KEY`
- `IPINFO_API_KEY`
- `OTX_API_KEY`
- `URLHAUS_API_KEY`

Some providers work without a key, while others use the key only if you configure it.

## Notes

- The UI is intentionally local-first and analyst-friendly.
- `Arsenal.html` loads the workspace pages from `src/`.
- There is no separate frontend build pipeline.
