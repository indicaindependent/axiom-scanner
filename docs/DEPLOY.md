# Deploying Axiom

Both workers run on Cloudflare's free tier. Deploy the scanner first, then
(optionally) the Discord bot on top.

## 1. Scanner (`axiom-scanner`)

```bash
cd src
cp ../wrangler.scanner.example.toml wrangler.toml
wrangler deploy
```

Test it:
```bash
curl -s "https://<your-scanner>/health"
curl -s -X POST "https://<your-scanner>/scan" \
  -H "content-type: application/json" \
  -d '{"target":"https://example.com"}' | jq .
```

To gate it, set a key — then every request must send `x-axiom-key`:
```bash
wrangler secret put AXIOM_SCAN_KEY
```

## 2. Discord bot (`axiom-bot`)

1. Create an app at https://discord.com/developers/applications ("Axiom").
2. Copy the **Public Key**, **Application ID**, and (under Bot) the **Token**.
3. Configure and deploy:
   ```bash
   cp ../wrangler.bot.example.toml wrangler.toml   # set SCANNER_URL + optional locks
   wrangler secret put AXIOM_DISCORD_PUBLIC_KEY
   wrangler secret put AXIOM_DISCORD_APP_ID
   wrangler secret put AXIOM_DISCORD_TOKEN
   wrangler secret put AXIOM_SCAN_KEY        # same value the scanner expects
   wrangler secret put INTERNAL_SECRET
   wrangler deploy
   ```
4. In the portal, set **Interactions Endpoint URL** to your bot worker's URL.
   Discord sends a PING; the worker answers PONG and the URL saves.
5. Register the slash command in your guild (instant):
   ```bash
   curl -X POST https://<your-bot-worker>/admin/commands \
     -H "Authorization: Bearer $INTERNAL_SECRET"
   ```
6. Invite the bot with scopes `applications.commands` + `bot`.
7. In your server: `/scan target: https://example.com`

## Gotchas

- **Custom domain propagation:** right after you add an exact subdomain route,
  requests may briefly hit a wildcard placeholder for ~30s. Wait, then retry.
  If Discord's endpoint save fails during that window
  (`APPLICATION_INTERACTIONS_ENDPOINT_URL_INVALID`), just re-save once the
  route is stable. Verify by POSTing a bogus body — you should get a JSON
  `401 { bad signature }`, not HTML.
- **Ed25519 verification** is mandatory — Discord rejects the endpoint if the
  signature check doesn't round-trip. Don't disable it.
- **Deferred response:** the bot must ACK within 3 seconds. It replies with a
  type-5 (deferred) immediately, then edits in the result. Keep that flow.
