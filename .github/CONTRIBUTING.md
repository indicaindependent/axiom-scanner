# Contributing to Axiom

Thanks for helping harden the web for people who ship alone.

## Setup
1. Fork and clone.
2. Install [Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/).
3. Copy the relevant `wrangler.*.example.toml`, deploy to your own account, test.

## Good contributions
- New **detections** (a real, low-false-positive vulnerability check for indie/no-code stacks).
- Better **backend fingerprints**.
- Clearer report wording / remediation advice.
- False-positive fixes (with the case that triggered them).

## Ground rules
- Keep it **read-only and non-intrusive** — no form submission, no brute force,
  no payloads, no exploitation. That's the whole ethic of this tool.
- Never weaken the **SSRF guard**.
- Don't commit secrets, tokens, or your own Discord/Cloudflare IDs. A clean
  clone must configure entirely through env/secrets.
- One focused change per PR; explain what you changed and why.

By contributing you agree your work is MIT-licensed under this project.
