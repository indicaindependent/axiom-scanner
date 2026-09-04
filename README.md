<div align="center">

# Axiom

**A free, read-only web-security scanner you run from Discord — `/scan yoursite.com` and get a graded vulnerability report card in seconds.**

Built for the "vibe-coded" era: solo devs and no-code builders shipping real apps who never had a security review. Axiom gives them one, free, at the edge.

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare_Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![Discord Bot](https://img.shields.io/badge/Discord-Slash_Command-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.com/developers/docs/interactions/application-commands)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=for-the-badge)](.github/CONTRIBUTING.md)

</div>

---

## What it is

Axiom is two small Cloudflare Workers, both on the free tier:

1. **`axiom-scanner`** — the engine. Give it a URL, it fetches the page (and its same-origin JS, and a few well-known paths), runs a battery of non-intrusive checks, and returns a JSON report with a weighted **A+ → F** grade.
2. **`axiom-bot`** — a Discord slash-command front end. `/scan target:<url>` in your server calls the engine and posts the report back as an embed card. Ed25519-verified, guild- and channel-lockable.

You can run the scanner on its own over HTTP, or wire the bot on top for a one-command Discord experience.

---

## What it checks

Axiom targets the vulnerability surface that actually bites indie / no-code apps:

- **Security headers** — HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy. (Meta-tag equivalents are counted — a browser-enforced meta CSP still protects you.)
- **Exposed secrets** — scans the HTML *and* same-origin JS bundles for leaked API keys and tokens: AWS, Google, Stripe live keys, OpenAI, Anthropic, GitHub tokens, JWTs, private keys, and Supabase `service_role` keys. Reports a redacted sample and tells you to rotate.
- **Permissive CORS** (`Access-Control-Allow-Origin: *`) and **mixed content** (HTTPS page pulling `http://` assets).
- **Exposed sensitive paths** — `.env`, `.env.local`, `.git/config`, `config.json`, `firebase.json`, `backup.zip`, `.DS_Store`, and source maps. Content-confirmed and SPA-fallback-aware, so it doesn't false-positive on catch-all routes.
- **Unprotected forms** — public forms with no captcha / honeypot / rate-limit, i.e. a signup-flood and abuse vector.
- **Backend fingerprint** — identifies Supabase, Firebase, Google Apps Script, Base44, Vercel, Netlify, GitHub Pages and other no-code/edge backends so the advice fits your stack.
- **Cookie flags** — missing `Secure`, `HttpOnly`, `SameSite`.
- **Clickjacking** exposure and `X-Powered-By` stack leaks.

Findings are weighted by severity (Critical/High/Medium/Low) and rolled into a single score and letter grade.

---

## Safety — it's read-only by design

Axiom is a **non-intrusive** scanner. It performs `GET` requests only: the page, its same-origin scripts, and a short list of well-known paths. It **does not** submit forms, brute-force anything, send payloads, or attempt exploitation. It is safe to point at any site you're allowed to test.

An **SSRF guard** rejects internal targets (localhost, RFC1918 / private ranges, link-local) so the scanner can't be turned into a pivot against internal infrastructure.

> Only scan sites you own or have permission to test. This is a defensive audit tool, not an attack tool.

---

## Endpoints (scanner)

| Method / Path | Purpose |
|---|---|
| `GET /health` | Liveness check → `{ ok: true }` |
| `POST /scan` `{ "target": "https://example.com" }` | Full report as JSON |
| `GET /scan?target=example.com` | Same, via query string |

**Auth:** optional. If `AXIOM_SCAN_KEY` is set, requests must send `x-axiom-key: <key>` (the Discord bot sends it automatically). Leave it unset for a fully public scanner, or set it to gate access.

---

## Discord bot

`/scan target:<url>` → the bot immediately sends a *deferred* response (beating Discord's 3-second rule), calls the scanner, then edits in the graded report card.

- **Ed25519** request-signature verification (required by Discord).
- Optional **guild lock** (`AXIOM_GUILD_ID`) and **channel lock** (`AXIOM_BOTS_COMMANDS_CHANNEL`) so `/scan` only works where you want it.
- `POST /admin/commands` (Bearer `INTERNAL_SECRET`) registers the slash command in your guild (instant, no global-propagation wait).

---

## Deploy your own

You'll need a free Cloudflare account and [Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/).

### 1. The scanner
```bash
cd src
cp ../wrangler.scanner.example.toml wrangler.toml   # edit name/route as you like
wrangler deploy
# optional: gate it
wrangler secret put AXIOM_SCAN_KEY
```

### 2. The Discord bot (optional)
Create an application at the [Discord Developer Portal](https://discord.com/developers/applications), then:
```bash
cp ../wrangler.bot.example.toml wrangler.toml
# secrets:
wrangler secret put AXIOM_DISCORD_PUBLIC_KEY   # from the portal
wrangler secret put AXIOM_DISCORD_APP_ID
wrangler secret put AXIOM_DISCORD_TOKEN        # bot token
wrangler secret put AXIOM_SCAN_KEY             # same key the scanner expects
wrangler secret put INTERNAL_SECRET            # to authorize command registration
# plain vars in wrangler.toml: SCANNER_URL, AXIOM_GUILD_ID, AXIOM_BOTS_COMMANDS_CHANNEL
wrangler deploy
```
Then in the portal set the **Interactions Endpoint URL** to your bot worker's URL (it must pass Discord's PING), register the command:
```bash
curl -X POST https://<your-bot-worker>/admin/commands -H "Authorization: Bearer $INTERNAL_SECRET"
```
and invite the bot with the `applications.commands` + `bot` scopes.

See [docs/DEPLOY.md](docs/DEPLOY.md) for the full walkthrough and gotchas.

---

## Grading

Score starts at 100 and drops by a severity weight per finding:

| Grade | Score |
|---|---|
| A+ | 93–100 |
| A  | 85–92 |
| B  | 75–84 |
| C  | 65–74 |
| D  | 50–64 |
| F  | < 50 |

A clean, well-configured site scores A+ with no false positives; a site leaking a `.env` or a live Stripe key drops to F fast.

---

## Files

| File | Purpose |
|---|---|
| [`src/axiom-scanner.js`](src/axiom-scanner.js) | The scan engine (single-file Worker) |
| [`src/axiom-bot.js`](src/axiom-bot.js) | The Discord interactions Worker |
| [`docs/DEPLOY.md`](docs/DEPLOY.md) | Full deploy guide + Discord setup gotchas |

## License

[MIT](LICENSE) — use it, fork it, harden your stuff.

---

<div align="center">
<sub>Built by Indica Independent · part of the VPDLNY mission — security tools for the people who ship alone.</sub>
</div>
