/**
 * ============================================================
 * AXIOM BOT — Discord slash-command front for the edge scanner
 * Cloudflare Worker. Free edge infra. Ed25519 verify + deferred.
 *
 * Command:  /scan target:<url>   (locked to #bots-commands)
 *   -> defers, calls axiom-scanner, posts a clean vuln report card.
 *
 * SECRETS (secret_text bindings):
 *   AXIOM_DISCORD_TOKEN        bot token
 *   AXIOM_DISCORD_PUBLIC_KEY   app public key (for signature verify)
 *   AXIOM_DISCORD_APP_ID       application id
 *   AXIOM_SCAN_KEY             shared key for the scanner
 *   INTERNAL_SECRET            bearer for /admin/commands registration
 * PLAIN vars:
 *   AXIOM_GUILD_ID             allowed guild (server) id
 *   AXIOM_BOTS_COMMANDS_CHANNEL  channel id to lock /scan to
 *   SCANNER_URL                e.g. https://scan.vibemaestro.app
 * ============================================================
 */

const DISCORD_API = 'https://discord.com/api/v10';

function json(d, s = 200) { return new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json' } }); }
function ephemeral(c) { return json({ type: 4, data: { content: c, flags: 64 } }); }
function ack() { return json({ type: 5 }); }

async function followUp(env, token, data) {
  await fetch(`${DISCORD_API}/webhooks/${env.AXIOM_DISCORD_APP_ID}/${token}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...data, allowed_mentions: { parse: [] } }),
  });
}

// ---- Ed25519 signature verification (Discord requirement) ----
function hexToBytes(hex) { const a = new Uint8Array(hex.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.substr(i * 2, 2), 16); return a; }
async function verify(request, body, env) {
  const sig = request.headers.get('x-signature-ed25519');
  const ts = request.headers.get('x-signature-timestamp');
  if (!sig || !ts) return false;
  try {
    const key = await crypto.subtle.importKey('raw', hexToBytes(env.AXIOM_DISCORD_PUBLIC_KEY), { name: 'Ed25519', namedCurve: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, hexToBytes(sig), new TextEncoder().encode(ts + body));
  } catch { return false; }
}

// ---- report card renderer ----
const SEV_EMOJI = { CRITICAL: '🟥', HIGH: '🟧', MEDIUM: '🟨', LOW: '⬜', INFO: '🟦' };

function renderCard(r) {
  if (!r.ok) return { content: `❌ Scan failed: ${r.error}` };
  const c = r.counts;
  const gradeEmoji = r.score >= 85 ? '🟢' : r.score >= 65 ? '🟡' : r.score >= 50 ? '🟠' : '🔴';
  const backend = r.backend.length ? r.backend.map(b => b.name).join(', ') : 'unknown';

  const lines = [];
  const shown = r.findings.filter(f => f.sev !== 'INFO').slice(0, 12);
  for (const f of shown) lines.push(`${SEV_EMOJI[f.sev] || '•'} **${f.title}**\n   ${f.note}`);
  const infos = r.findings.filter(f => f.sev === 'INFO');
  for (const f of infos.slice(0, 3)) lines.push(`🟦 *${f.title}* — ${f.note}`);
  const hidden = r.findings.filter(f => f.sev !== 'INFO').length - shown.length;
  if (hidden > 0) lines.push(`…and ${hidden} more lower-severity item(s).`);

  const desc = [
    `**${gradeEmoji} Grade ${r.grade}** (${r.score}/100)`,
    `🖥️ Stack: **${backend}**`,
    `🔎 ${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low`,
    '',
    lines.join('\n'),
  ].join('\n');

  return {
    embeds: [{
      title: `🛡️ Axiom Security Scan — ${r.target.replace(/^https?:\/\//, '')}`,
      url: r.final_url,
      description: desc.slice(0, 4000),
      color: r.score >= 85 ? 0x22c55e : r.score >= 65 ? 0xeab308 : r.score >= 50 ? 0xf97316 : 0xef4444,
      footer: { text: `Axiom · scanned in ${r.duration_ms}ms · common vibe-app vuln audit` },
      timestamp: r.scanned_at,
    }],
  };
}

// ---- resilient scanner call: tolerates 522/timeouts + retries + fallback host ----
async function scanOnce(host, key, target, timeoutMs) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(`${host}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-axiom-key': key },
      body: JSON.stringify({ target }),
      signal: ctl.signal,
    });
    const text = await res.text();
    // scanner should return JSON; a 5xx edge page (522 etc.) returns HTML -> guard it
    let parsed = null;
    try { parsed = JSON.parse(text); } catch { /* non-JSON */ }
    if (parsed && typeof parsed === 'object') return parsed;
    return { ok: false, _httpStatus: res.status, _nonjson: true };
  } catch (e) {
    return { ok: false, _err: String(e && e.name === 'AbortError' ? 'timeout' : e) };
  } finally {
    clearTimeout(timer);
  }
}

async function callScanner(env, target) {
  const primary = env.SCANNER_URL;
  const fallback = env.SCANNER_FALLBACK_URL; // optional workers.dev host
  const key = env.AXIOM_SCAN_KEY;

  // try primary twice, then fallback once — the edge 522 is almost always transient
  for (let i = 0; i < 2; i++) {
    const r = await scanOnce(primary, key, target, 20000);
    if (r && r.ok) return r;
    if (r && r.ok === false && r.error) return r; // real scanner error (bad target etc.) — surface it
    if (i === 0) await new Promise(res => setTimeout(res, 1500));
  }
  if (fallback) {
    const r = await scanOnce(fallback, key, target, 20000);
    if (r && (r.ok || r.error)) return r;
  }
  return { ok: false, error: 'The scan engine is briefly unreachable (edge timeout). Please run /scan again in a moment.' };
}

// Admin can run /scan ANYWHERE; everyone else is locked to #bot-commands.
function isAdminInvoker(interaction, env) {
  // 1) explicit admin id allowlist (comma/space separated), always wins
  const ids = (env.AXIOM_ADMIN_IDS || '').split(/[\s,]+/).filter(Boolean);
  const uid = interaction.member?.user?.id || interaction.user?.id;
  if (uid && ids.includes(uid)) return true;
  // 2) Discord Administrator permission bit (0x8) on the invoking member
  try {
    const perms = interaction.member?.permissions;
    if (perms && (BigInt(perms) & 8n) === 8n) return true;
  } catch (_) {}
  return false;
}

async function handleScan(interaction, env, ctx) {
  // channel lock — admins bypass it and can scan from any channel
  if (
    env.AXIOM_BOTS_COMMANDS_CHANNEL &&
    interaction.channel_id !== env.AXIOM_BOTS_COMMANDS_CHANNEL &&
    !isAdminInvoker(interaction, env)
  ) {
    return ephemeral(`❌ Please use <#${env.AXIOM_BOTS_COMMANDS_CHANNEL}> for /scan.`);
  }
  const opt = (interaction.data.options || []).find(o => o.name === 'target');
  const target = opt?.value?.trim();
  if (!target) return ephemeral('❌ Usage: `/scan target:example.com`');

  const token = interaction.token;
  ctx.waitUntil((async () => {
    const r = await callScanner(env, target);
    await followUp(env, token, renderCard(r));
  })());
  return ack(); // deferred — beats the 3s rule
}

async function registerCommands(env) {
  const cmds = [{
    name: 'scan',
    description: 'Run a full security scan on any website for common vibe-app vulnerabilities',
    options: [{ name: 'target', description: 'Website URL or domain (e.g. mywebsite.com)', type: 3, required: true }],
  }];
  const scope = env.AXIOM_GUILD_ID
    ? `${DISCORD_API}/applications/${env.AXIOM_DISCORD_APP_ID}/guilds/${env.AXIOM_GUILD_ID}/commands`
    : `${DISCORD_API}/applications/${env.AXIOM_DISCORD_APP_ID}/commands`;
  const res = await fetch(scope, {
    method: 'PUT',
    headers: { Authorization: `Bot ${env.AXIOM_DISCORD_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmds),
  });
  return { status: res.status, body: await res.text() };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/health') return json({ ok: true, service: 'axiom-bot', ts: Date.now() });

    // one-time / manual command registration
    if (url.pathname === '/admin/commands' && request.method === 'POST') {
      if (request.headers.get('authorization') !== `Bearer ${env.INTERNAL_SECRET}`) return json({ error: 'unauthorized' }, 401);
      return json(await registerCommands(env));
    }

    if (url.pathname === '/' && request.method === 'POST') {
      const body = await request.text();
      if (!(await verify(request, body, env))) return json({ error: 'bad signature' }, 401);
      const interaction = JSON.parse(body);

      if (interaction.type === 1) return json({ type: 1 }); // PING -> PONG
      if (interaction.type === 2) { // APPLICATION_COMMAND
        // guild lock
        if (env.AXIOM_GUILD_ID && interaction.guild_id !== env.AXIOM_GUILD_ID) {
          return ephemeral('❌ Axiom is not authorized in this server.');
        }
        if (interaction.data.name === 'scan') return handleScan(interaction, env, ctx);
        return ephemeral('❌ Unknown command.');
      }
      return json({ type: 4, data: { content: 'unsupported interaction' } });
    }

    return json({ ok: true, service: 'axiom-bot', usage: 'POST / (Discord interactions)' });
  },
};
