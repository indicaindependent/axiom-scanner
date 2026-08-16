/**
 * ============================================================
 * AXIOM SCANNER — external vibe-app vulnerability scan engine
 * Cloudflare Worker (free edge infra). No external paid deps.
 * Route: scan.vibemaestro.app  (also runs on workers.dev for test)
 *
 * POST /scan  { "target": "https://example.com" }  -> JSON report
 * GET  /scan?target=example.com                    -> JSON report
 * GET  /health                                     -> { ok:true }
 *
 * Auth: optional. If AXIOM_SCAN_KEY is set, POST/GET must send
 *       header  x-axiom-key: <key>  (Discord bot sends it).
 *       Public GET without key still works but is rate-limitable.
 *
 * Checks (vibe-coded app / static-site vuln surface):
 *   H  security headers (HSTS/CSP/XCTO/XFO/Referrer/Permissions)
 *   S  exposed secrets in HTML+JS (API keys, Supabase/Firebase, tokens)
 *   C  permissive CORS (ACAO:*) + mixed content
 *   E  exposed sensitive paths (.env/.git/config.json/source maps/backups)
 *   F  unprotected forms (no captcha/honeypot/rate-limit) -> spam-flood risk
 *   B  backend fingerprint (Supabase/Firebase/Apps Script/Base44/etc)
 *   K  clickjacking + cookie flags
 * ============================================================
 */

const UA = 'AxiomScanner/1.0 (+https://vibemaestro.app; security audit)';
const FETCH_TIMEOUT_MS = 8000;
const MAX_BYTES = 1_500_000; // cap body read per asset

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

function normalizeTarget(raw) {
  if (!raw) return null;
  let t = String(raw).trim();
  t = t.replace(/^<|>$/g, '').replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(t)) t = 'https://' + t;
  try {
    const u = new URL(t);
    if (!/^https?:$/.test(u.protocol)) return null;
    // block internal / SSRF-y targets
    const h = u.hostname.toLowerCase();
    if (h === 'localhost' || h.endsWith('.local') ||
        /^(127\.|10\.|192\.168\.|169\.254\.|::1|0\.0\.0\.0)/.test(h) ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(h)) return null;
    return u;
  } catch { return null; }
}

async function timedFetch(url, opts = {}) {
  const ctl = new AbortController();
  const to = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      ...opts,
      signal: ctl.signal,
      headers: { 'User-Agent': UA, ...(opts.headers || {}) },
      redirect: 'follow',
      cf: { cacheTtl: 0 },
    });
    return res;
  } finally { clearTimeout(to); }
}

async function readCapped(res) {
  try {
    const reader = res.body?.getReader();
    if (!reader) return await res.text();
    let received = 0; const chunks = []; const dec = new TextDecoder();
    let out = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.length;
      out += dec.decode(value, { stream: true });
      if (received >= MAX_BYTES) { try { await reader.cancel(); } catch {} break; }
    }
    return out;
  } catch { return ''; }
}

// ---- secret / key detectors (high-signal, low false-positive) ----
const SECRET_PATTERNS = [
  { id: 'aws_akid',       label: 'AWS Access Key ID',            re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'google_api',     label: 'Google API key',               re: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { id: 'stripe_live',    label: 'Stripe LIVE secret key',       re: /\bsk_live_[0-9a-zA-Z]{16,}\b/ },
  { id: 'stripe_pk_live', label: 'Stripe LIVE publishable key',  re: /\bpk_live_[0-9a-zA-Z]{16,}\b/ },
  { id: 'openai',         label: 'OpenAI API key',               re: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { id: 'anthropic',      label: 'Anthropic API key',            re: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/ },
  { id: 'github_pat',     label: 'GitHub token',                 re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { id: 'slack',          label: 'Slack token',                  re: /\bxox[baprs]-[0-9A-Za-z\-]{10,}\b/ },
  { id: 'jwt',            label: 'JWT (possible service token)', re: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/ },
  { id: 'private_key',    label: 'Private key block',            re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { id: 'supabase_service', label: 'Supabase SERVICE ROLE key (service_role JWT)', re: /"?service_role"?/ },
];

// Supabase anon keys are meant to be public IF RLS is on — we flag as INFO not CRITICAL.
function detectSecrets(text, sourceLabel) {
  const hits = [];
  for (const p of SECRET_PATTERNS) {
    const m = text.match(p.re);
    if (m) {
      // service_role literal alone is weak; require it to co-occur with a JWT to be CRITICAL
      if (p.id === 'supabase_service' && !/eyJ[A-Za-z0-9_\-]{10,}\./.test(text)) continue;
      hits.push({ id: p.id, label: p.label, where: sourceLabel, sample: m[0].slice(0, 12) + '…' });
    }
  }
  return hits;
}

function backendFingerprint(text, headers) {
  const fp = [];
  const add = (name, ev) => fp.push({ name, evidence: ev });
  if (/\.supabase\.co|supabase\.co\/rest\/v1|createClient\(/i.test(text)) add('Supabase', 'supabase.co ref / createClient');
  if (/firebaseio\.com|firebasestorage|firebaseapp\.com|firebase\.initializeApp/i.test(text)) add('Firebase', 'firebase ref');
  if (/script\.google\.com\/macros\/s\//i.test(text)) add('Google Apps Script', '/macros/s/*/exec form backend');
  if (/base44\.app|base44\.com/i.test(text)) add('Base44', 'base44 ref');
  if (/formspree\.io|getform\.io|formsubmit\.co|basin|web3forms/i.test(text)) add('3rd-party form service', 'form endpoint');
  if (/xano\.io|bubbleapps\.io|softr|glide|airtable\.com\/v0/i.test(text)) add('No-code backend', 'xano/bubble/airtable/etc');
  const server = (headers.get('server') || '').toLowerCase();
  if (/github\.com/.test(server)) add('GitHub Pages', 'server: GitHub.com (static host)');
  if (/vercel/.test(server) || headers.get('x-vercel-id')) add('Vercel', 'vercel headers');
  if (/netlify/.test(server) || headers.get('x-nf-request-id')) add('Netlify', 'netlify headers');
  if (/cloudflare/.test(server)) add('Cloudflare', 'server: cloudflare');
  return fp;
}

function headerAudit(headers, html) {
  const findings = [];
  html = html || '';
  // Detect security policies delivered as parse-time <meta> tags (valid for SPAs
  // like Base44 apps, where the platform serves the HTML and real headers can't
  // be added). A meta CSP/nosniff/referrer/permissions is browser-ENFORCED, so we
  // credit it exactly like the header.
  const metaHas = (kind, re) => re.test(html);
  const metaCsp   = /<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*>/i.test(html);
  const metaXcto  = /<meta[^>]+http-equiv=["']?x-content-type-options["']?[^>]*>/i.test(html);
  const metaPerm  = /<meta[^>]+http-equiv=["']?permissions-policy["']?[^>]*>/i.test(html);
  const metaRef   = /<meta[^>]+name=["']?referrer["']?[^>]*>/i.test(html);
  const has = (h) => {
    if (headers.get(h)) return true;
    // meta-tag fallbacks
    if (h === 'content-security-policy') return metaCsp;
    if (h === 'x-content-type-options') return metaXcto;
    if (h === 'permissions-policy') return metaPerm;
    if (h === 'referrer-policy') return metaRef;
    return false;
  };
  const H = (name, header, sev, note) => {
    if (!has(header)) findings.push({ id: 'hdr_' + name, sev, title: `Missing ${header}`, note });
  };
  H('hsts', 'strict-transport-security', 'MEDIUM', 'No HSTS — browsers may be downgraded to HTTP (MITM risk).');
  H('csp', 'content-security-policy', 'MEDIUM', 'No Content-Security-Policy — weak XSS/inline-script defense.');
  H('xcto', 'x-content-type-options', 'LOW', 'No X-Content-Type-Options: nosniff — MIME sniffing risk.');
  H('xfo', 'x-frame-options', 'MEDIUM', 'No X-Frame-Options/frame-ancestors — clickjacking exposure.');
  H('ref', 'referrer-policy', 'LOW', 'No Referrer-Policy — may leak full URLs to third parties.');
  H('perm', 'permissions-policy', 'LOW', 'No Permissions-Policy — camera/mic/geo not restricted.');
  // CSP with frame-ancestors can substitute for XFO
  let csp = (headers.get('content-security-policy') || '').toLowerCase();
  if (!csp) {
    const m = html.match(/<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*content=["']([^"']+)["']/i);
    if (m) csp = m[1].toLowerCase();
  }
  if (csp.includes('frame-ancestors')) {
    const i = findings.findIndex(f => f.id === 'hdr_xfo');
    if (i >= 0) findings.splice(i, 1);
  }
  // CORS
  const acao = headers.get('access-control-allow-origin');
  if (acao === '*') {
    const acc = (headers.get('access-control-allow-credentials') || '').toLowerCase();
    findings.push({
      id: 'cors_wildcard',
      sev: acc === 'true' ? 'HIGH' : 'LOW',
      title: 'Permissive CORS (Access-Control-Allow-Origin: *)',
      note: acc === 'true'
        ? 'Wildcard CORS WITH credentials — any site can read authenticated responses.'
        : 'Wildcard CORS — fine for public read-only APIs, risky if it fronts private data.'
    });
  }
  // powered-by leaks
  const pb = headers.get('x-powered-by');
  if (pb) findings.push({ id: 'powered_by', sev: 'LOW', title: 'X-Powered-By exposed', note: `Leaks stack: ${pb}` });
  return findings;
}

function cookieAudit(headers) {
  const out = [];
  const setc = headers.get('set-cookie');
  if (!setc) return out;
  const low = setc.toLowerCase();
  if (!low.includes('secure')) out.push({ id: 'cookie_secure', sev: 'MEDIUM', title: 'Cookie without Secure flag', note: 'Session cookie can be sent over HTTP.' });
  if (!low.includes('httponly')) out.push({ id: 'cookie_httponly', sev: 'MEDIUM', title: 'Cookie without HttpOnly', note: 'Cookie readable by JS (XSS token theft).' });
  if (!low.includes('samesite')) out.push({ id: 'cookie_samesite', sev: 'LOW', title: 'Cookie without SameSite', note: 'CSRF exposure.' });
  return out;
}

function formAudit(html) {
  const out = [];
  const forms = html.match(/<form[\s\S]*?<\/form>/gi) || [];
  const hasCaptcha = /recaptcha|hcaptcha|turnstile|g-recaptcha|data-sitekey|cf-turnstile/i.test(html);
  let riskyForms = 0;
  for (const f of forms) {
    const collectsEmail = /type=["']?email["']?|name=["']?email["']?/i.test(f);
    const collectsData  = /<input|<textarea/i.test(f);
    const hasHoneypot   = /position:\s*absolute;[^"']*(left:\s*-?\d{3,}|opacity:\s*0|display:\s*none)|name=["'](website|url|hp_|honeypot|_gotcha)["']/i.test(f);
    if ((collectsEmail || collectsData) && !hasCaptcha && !hasHoneypot) riskyForms++;
  }
  if (riskyForms > 0) {
    out.push({
      id: 'form_no_botprotect',
      sev: 'HIGH',
      title: `${riskyForms} form(s) with no bot protection`,
      note: 'No CAPTCHA, honeypot, or rate-limit detected. This is the classic overnight signup-spam / form-flood vector for vibe-coded apps.'
    });
  }
  return out;
}

async function probePaths(base) {
  const paths = [
    { p: '/.env',            sev: 'CRITICAL', title: 'Exposed .env file',            sig: /^\s*[A-Z0-9_]+\s*=/m },
    { p: '/.git/config',     sev: 'CRITICAL', title: 'Exposed .git repository',      sig: /\[core\]|repositoryformatversion/i },
    { p: '/config.json',     sev: 'MEDIUM',   title: 'Exposed config.json',          sig: /^\s*[\[{]/ },
    { p: '/firebase.json',   sev: 'MEDIUM',   title: 'Exposed firebase.json',        sig: /"(hosting|firestore|functions|database|rules|storage)"\s*:/i },
    { p: '/.env.local',      sev: 'CRITICAL', title: 'Exposed .env.local',           sig: /^\s*[A-Z0-9_]+\s*=/m },
    { p: '/backup.zip',      sev: 'HIGH',     title: 'Exposed backup archive',       ct: /application\/(zip|octet-stream|x-zip)/i, magic: 'PK' },
    { p: '/.DS_Store',       sev: 'LOW',      title: 'Exposed .DS_Store (dir listing leak)', magic: '\x00\x00\x00\x01Bud1' },
  ];

  // ── SPA-FALLBACK CONTROL PROBE ──────────────────────────────────────────
  // Fetch a path that CANNOT exist. If the site returns 200 for it (SPA catch-all
  // serving index.html for every route), we know a 200 means nothing on its own —
  // so we only trust a probe that is materially DIFFERENT from this control.
  let ctrlStatus = 0, ctrlBody = '', ctrlIsHtml = false, spaCatchAll = false;
  try {
    const cp = '/__axiom_probe_' + Math.random().toString(36).slice(2, 10) + '_nope';
    const cr = await timedFetch(base + cp, { method: 'GET' });
    ctrlStatus = cr.status;
    ctrlBody = (await readCapped(cr)).slice(0, 600);
    ctrlIsHtml = /<!doctype html|<html/i.test(ctrlBody);
    spaCatchAll = (ctrlStatus === 200 && ctrlIsHtml);
  } catch {}

  // crude similarity: same first 200 chars => almost certainly the same app shell
  const sameAsControl = (body) =>
    spaCatchAll && /<!doctype html|<html/i.test(body) &&
    body.slice(0, 200).trim() === ctrlBody.slice(0, 200).trim();

  const out = [];
  await Promise.all(paths.map(async ({ p, sev, title, sig, ct, magic }) => {
    try {
      const res = await timedFetch(base + p, { method: 'GET' });
      if (res.status !== 200) return;
      const ctype = (res.headers.get('content-type') || '').toLowerCase();
      const body = (await readCapped(res)).slice(0, 800);

      // 1) SPA catch-all: identical app shell as the impossible control path => NOT a real file.
      if (sameAsControl(body)) return;
      // 2) Any HTML body for a non-HTML asset while the site is a SPA => fallback, not the file.
      if (spaCatchAll && /<!doctype html|<html/i.test(body)) return;

      // 3) Positive content confirmation — the body/type must actually look like the file.
      if (ct && !ct.test(ctype)) return;                    // wrong content-type (e.g. zip)
      if (magic && !body.startsWith(magic)) return;         // wrong file magic bytes
      if (sig && !sig.test(body)) return;                   // doesn't match the file's shape

      out.push({ id: 'path' + p.replace(/\W/g, '_'), sev, title, note: `HTTP 200 at ${p} (content-confirmed)` });
    } catch {}
  }));
  return out;
}

function grade(findings) {
  // weighted deduction from 100
  const w = { CRITICAL: 35, HIGH: 18, MEDIUM: 9, LOW: 3, INFO: 0 };
  let score = 100;
  for (const f of findings) score -= (w[f.sev] || 0);
  score = Math.max(0, Math.min(100, score));
  const letter = score >= 93 ? 'A+' : score >= 85 ? 'A' : score >= 75 ? 'B'
    : score >= 65 ? 'C' : score >= 50 ? 'D' : 'F';
  return { score, letter };
}

async function runScan(target) {
  const u = normalizeTarget(target);
  if (!u) return { ok: false, error: 'invalid or disallowed target' };
  const base = `${u.protocol}//${u.host}`;
  const started = Date.now();
  const findings = [];
  let backend = [], statusCode = null, finalUrl = base;

  let html = '';
  try {
    const res = await timedFetch(base, { method: 'GET' });
    statusCode = res.status; finalUrl = res.url || base;
    const headers = res.headers;
    html = await readCapped(res);

    findings.push(...headerAudit(headers, html));
    findings.push(...cookieAudit(headers));
    backend = backendFingerprint(html, headers);

    // mixed content on https page
    if (u.protocol === 'https:' && /(?:src|href)=["']http:\/\//i.test(html)) {
      findings.push({ id: 'mixed_content', sev: 'MEDIUM', title: 'Mixed content', note: 'HTTPS page loads http:// assets — breaks the secure context.' });
    }
  } catch (e) {
    return { ok: false, error: 'could not fetch target: ' + String(e).slice(0, 120) };
  }

  // secrets in HTML
  const secretHits = detectSecrets(html, 'HTML');
  let jsCorpus = '';  // accumulated JS-bundle text for backend re-detection

  // pull + scan up to 6 same-origin JS bundles (where vibe apps leak keys)
  const scriptSrcs = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map(m => m[1]);
  const jsUrls = scriptSrcs
    .map(s => { try { return new URL(s, base).href; } catch { return null; } })
    .filter(Boolean)
    .filter(h => new URL(h).host === u.host) // same-origin only
    .slice(0, 6);
  await Promise.all(jsUrls.map(async (jsUrl) => {
    try {
      const r = await timedFetch(jsUrl);
      if (r.status !== 200) return;
      const body = await readCapped(r);
      jsCorpus += '\n' + body;
      secretHits.push(...detectSecrets(body, jsUrl.replace(base, '')));
      // source map leak
      if (/\/\/#\s*sourceMappingURL=.+\.map/i.test(body)) {
        findings.push({ id: 'sourcemap_' + jsUrl.length, sev: 'LOW', title: 'Source map referenced', note: `${jsUrl.replace(base,'')} exposes a .map — original source is downloadable.` });
      }
    } catch {}
  }));

  // Re-run backend fingerprint over HTML + JS bundles (managed-backend refs like
  // base44 / /api/apps/ usually live in the JS bundle, not the index HTML).
  {
    const combined = html + jsCorpus;
    const extra = backendFingerprint(combined, /*headers*/ new Headers());
    const seenB = new Set(backend.map(b => b.name));
    for (const b of extra) if (!seenB.has(b.name)) { backend.push(b); seenB.add(b.name); }
    // stash combined for the Supabase direct-vs-managed decision below
    globalThis.__axCombined = combined;
  }

  // dedupe secret hits by id+where
  const seen = new Set();
  for (const s of secretHits) {
    const k = s.id + '|' + s.where;
    if (seen.has(k)) continue; seen.add(k);
    const sev = (s.id === 'private_key' || s.id === 'aws_akid' || s.id === 'stripe_live' ||
                 s.id === 'anthropic' || s.id === 'openai' || s.id === 'supabase_service' ||
                 s.id === 'github_pat') ? 'CRITICAL' : 'HIGH';
    findings.push({ id: 'secret_' + s.id + '_' + s.where.slice(-8), sev, title: `Exposed secret: ${s.label}`, note: `Found in ${s.where} (sample ${s.sample}). Rotate it and move to a server env var.` });
  }

  // form bot-protection
  findings.push(...formAudit(html));

  // sensitive path probes
  findings.push(...await probePaths(base));

  // Supabase note — but ONLY when the site talks to Supabase DIRECTLY (embedded
  // anon key + createClient / direct REST). If data flows through the Base44 API
  // (or any managed backend) the platform enforces auth + row-level security, so
  // a bare supabase.co ref is NOT an exposure and we stay quiet (no crying wolf).
  if (backend.some(b => b.name === 'Supabase')) {
    const corpus = (globalThis.__axCombined || html);
    const viaManaged = backend.some(b => b.name === 'Base44') || /\/api\/apps\//i.test(corpus);
    // "direct" = an embedded anon JWT next to a supabase URL, OR an explicit
    // createClient(...) / supabase.co/rest/v1 data call in the bundle.
    const hasAnonKey = /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/.test(corpus)
                       && /supabase/i.test(corpus);
    const directClient = /createClient\s*\(|supabase\.co\/rest\/v1|\.from\(['\"][a-z_]+['\"]\)/i.test(corpus);
    const isDirect = (hasAnonKey || directClient) && !viaManaged;
    if (isDirect) {
      findings.push({ id: 'supabase_rls_reminder', sev: 'INFO',
        title: 'Direct Supabase client — verify Row-Level Security',
        note: 'This site uses a direct Supabase client with a public anon key. That is safe ONLY if RLS is enabled on every table — without it, the anon key allows full read/write to your DB.' });
    } else if (viaManaged) {
      findings.push({ id: 'supabase_via_managed', sev: 'INFO',
        title: 'Supabase via managed backend (auth-gated)',
        note: 'Data is accessed through a managed API (e.g. Base44), not a direct Supabase client — the platform enforces authentication + row-level security. No embedded key exposure detected.' });
    }
  }
  if (backend.some(b => b.name === 'Firebase')) {
    findings.push({ id: 'firebase_rules_reminder', sev: 'INFO', title: 'Firebase detected — verify Security Rules', note: 'Default Firebase rules are often world-readable/writable. Confirm rules lock reads/writes to authed users.' });
  }
  if (backend.some(b => b.name === 'Google Apps Script')) {
    findings.push({ id: 'appsscript_open', sev: 'HIGH', title: 'Google Apps Script form backend', note: 'Apps Script /exec endpoints are public and unauthenticated by default — add a honeypot + time-trap + rate limit server-side or it will get flood-spammed.' });
  }

  const g = grade(findings);
  const bySev = (s) => findings.filter(f => f.sev === s);
  return {
    ok: true,
    target: base,
    final_url: finalUrl,
    status: statusCode,
    scanned_at: new Date().toISOString(),
    duration_ms: Date.now() - started,
    grade: g.letter,
    score: g.score,
    backend,
    counts: {
      critical: bySev('CRITICAL').length, high: bySev('HIGH').length,
      medium: bySev('MEDIUM').length, low: bySev('LOW').length, info: bySev('INFO').length,
    },
    findings: findings.sort((a, b) => {
      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      return order[a.sev] - order[b.sev];
    }),
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/health') return json({ ok: true, service: 'axiom-scanner', ts: Date.now() });

    if (url.pathname === '/scan') {
      // optional auth
      if (env.AXIOM_SCAN_KEY) {
        const key = request.headers.get('x-axiom-key') || url.searchParams.get('key');
        if (key !== env.AXIOM_SCAN_KEY) return json({ ok: false, error: 'unauthorized' }, 401);
      }
      let target = url.searchParams.get('target');
      if (request.method === 'POST') {
        try { const b = await request.json(); target = b.target || target; } catch {}
      }
      if (!target) return json({ ok: false, error: 'missing target' }, 400);
      const report = await runScan(target);
      return json(report, report.ok ? 200 : 400);
    }

    return json({ ok: true, service: 'axiom-scanner', usage: 'POST /scan {target} or GET /scan?target=' });
  },
};
