// Limitky API — Cloudflare Worker
// Databáza: D1 (SQLite)  |  Obrázky: R2  |  Auth: JWT (HS256)

// ─── CORS ─────────────────────────────────────────────────────────────────────
function corsHeaders(env, request) {
  const origin  = request.headers.get('Origin') || '';
  const allowed = env.ALLOWED_ORIGIN || '*';
  const allowOrigin = allowed === '*' || origin === allowed ? origin || '*' : allowed;
  return {
    'Access-Control-Allow-Origin':  allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-API-Key, Authorization',
    'Access-Control-Max-Age':       '86400',
  };
}

function json(data, status = 200, cors = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  });
}

function err(msg, status, cors) {
  return json({ error: msg }, status, cors);
}

// ─── ID generation ────────────────────────────────────────────────────────────
function newId() {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 20);
}

// ─── PASSWORD HASHING (PBKDF2) ────────────────────────────────────────────────
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key  = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256
  );
  const hash = new Uint8Array(bits);
  return [...salt, ...hash].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password, stored) {
  const bytes        = stored.match(/.{2}/g).map(h => parseInt(h, 16));
  const salt         = new Uint8Array(bytes.slice(0, 16));
  const expectedHash = new Uint8Array(bytes.slice(16));
  const key          = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256
  );
  const hash = new Uint8Array(bits);
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= hash[i] ^ expectedHash[i];
  return diff === 0;
}

// ─── JWT (HS256) ──────────────────────────────────────────────────────────────
function b64url(str) {
  return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function fromb64url(str) {
  return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
}

async function signJWT(payload, secret) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body   = b64url(JSON.stringify(payload));
  const data   = `${header}.${body}`;
  const key    = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig    = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = b64url(String.fromCharCode(...new Uint8Array(sig)));
  return `${data}.${sigB64}`;
}

async function verifyJWT(token, secret) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;
  const key      = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  const sigBytes = Uint8Array.from(fromb64url(sig), c => c.charCodeAt(0));
  const valid    = await crypto.subtle.verify(
    'HMAC', key, sigBytes, new TextEncoder().encode(`${header}.${body}`)
  );
  if (!valid) return null;
  const payload = JSON.parse(fromb64url(body));
  if (payload.exp && payload.exp < Date.now() / 1000) return null;
  return payload;
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
async function authenticate(request, env) {
  const secret = env.JWT_SECRET;
  if (!secret) return true; // JWT_SECRET not set → open

  const authHeader = request.headers.get('Authorization') || '';
  const token      = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const payload    = await verifyJWT(token, secret);
  return !!payload;
}

// ─── ZÁLOHA DÁT DO GITHUBU ────────────────────────────────────────────────────
// UTF-8 reťazec → base64 (pre GitHub Git Data API)
function b64encodeUtf8(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

// Urobí kompletný snímok dát (produkty + fotky + posledné kódy) a commitne ho
// do vetvy "backups" v GitHub repozitári ako dr-backup.json. Vďaka Git Data API
// zvládne aj veľké fotky; história commitov = jednotlivé denné verzie.
async function runBackup(env) {
  const REPO   = env.BACKUP_REPO || 'kolodiazhna-ux/limitky';
  const BRANCH = 'backups';
  const FILE   = 'dr-backup.json';
  const token  = env.GITHUB_TOKEN;
  if (!token) throw new Error('GITHUB_TOKEN nie je nastavený');

  // 1) Dáta z D1
  const stateRow = await env.DB.prepare("SELECT value FROM state WHERE key='products'").first();
  const products = stateRow ? JSON.parse(stateRow.value) : [];
  const { results: photoRows } = await env.DB.prepare('SELECT id, data FROM photos').all();
  const photos = {};
  for (const r of photoRows) photos[r.id] = r.data;
  const { results: recentRows } = await env.DB.prepare('SELECT code FROM recent_codes ORDER BY position ASC').all();
  const recent = recentRows.map(r => r.code);
  const snapshot = {
    generatedAt:  new Date().toISOString(),
    productCount: products.length,
    photoCount:   Object.keys(photos).length,
    products, recent, photos,
  };
  const content = JSON.stringify(snapshot);

  // 2) GitHub Git Data API
  const gh = (p, opts = {}) => fetch(`https://api.github.com/repos/${REPO}${p}`, {
    ...opts,
    headers: {
      'Authorization': `Bearer ${token}`,
      'User-Agent': 'limitky-backup',
      'Accept': 'application/vnd.github+json',
      ...(opts.headers || {}),
    },
  });

  // vetva backups — ak neexistuje, založ ju z main
  let refRes = await gh(`/git/ref/heads/${BRANCH}`);
  if (refRes.status === 404) {
    const mainRef = await gh('/git/ref/heads/main');
    if (!mainRef.ok) throw new Error('main ref ' + mainRef.status);
    const mainSha = (await mainRef.json()).object.sha;
    const cr = await gh('/git/refs', { method: 'POST', body: JSON.stringify({ ref: `refs/heads/${BRANCH}`, sha: mainSha }) });
    if (!cr.ok) throw new Error('create branch ' + cr.status + ' ' + await cr.text());
    refRes = await gh(`/git/ref/heads/${BRANCH}`);
  }
  if (!refRes.ok) throw new Error('ref ' + refRes.status);
  const baseCommitSha = (await refRes.json()).object.sha;
  const baseCommit    = await (await gh(`/git/commits/${baseCommitSha}`)).json();

  const blobRes = await gh('/git/blobs', { method: 'POST', body: JSON.stringify({ content: b64encodeUtf8(content), encoding: 'base64' }) });
  if (!blobRes.ok) throw new Error('blob ' + blobRes.status + ' ' + await blobRes.text());
  const blobSha = (await blobRes.json()).sha;

  const treeRes = await gh('/git/trees', { method: 'POST', body: JSON.stringify({ base_tree: baseCommit.tree.sha, tree: [{ path: FILE, mode: '100644', type: 'blob', sha: blobSha }] }) });
  if (!treeRes.ok) throw new Error('tree ' + treeRes.status);
  const treeSha = (await treeRes.json()).sha;

  const msg = `Záloha dát ${snapshot.generatedAt} — ${snapshot.productCount} produktov, ${snapshot.photoCount} fotiek`;
  const commitRes = await gh('/git/commits', { method: 'POST', body: JSON.stringify({ message: msg, tree: treeSha, parents: [baseCommitSha] }) });
  if (!commitRes.ok) throw new Error('commit ' + commitRes.status);
  const newCommitSha = (await commitRes.json()).sha;

  const upd = await gh(`/git/refs/heads/${BRANCH}`, { method: 'PATCH', body: JSON.stringify({ sha: newCommitSha, force: true }) });
  if (!upd.ok) throw new Error('update ref ' + upd.status);

  return { ok: true, commit: newCommitSha, products: snapshot.productCount, photos: snapshot.photoCount, at: snapshot.generatedAt };
}

// ─── MAIN HANDLER ─────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const cors = corsHeaders(env, request);

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    try {
      // ── GET /api/backup?key=… ──────────────────────────────────────────────
      // Ručné spustenie zálohy (rovnaká logika ako denný cron). Chránené kľúčom.
      if (method === 'GET' && path === '/api/backup') {
        if (!env.BACKUP_KEY || url.searchParams.get('key') !== env.BACKUP_KEY) {
          return err('Unauthorized', 401, cors);
        }
        const res = await runBackup(env);
        return json(res, 200, cors);
      }

      // ── POST /api/auth/register ────────────────────────────────────────────
      if (method === 'POST' && path === '/api/auth/register') {
        const { email, password } = await request.json();
        if (!email || !password) return err('Email and password required', 400, cors);
        if (password.length < 6)  return err('Password too short (min 6)', 400, cors);

        const existing = await env.DB.prepare(
          'SELECT id FROM users WHERE email = ?'
        ).bind(email.toLowerCase()).first();
        if (existing) return err('Email already registered', 409, cors);

        const id   = newId();
        const now  = new Date().toISOString();
        const hash = await hashPassword(password);
        await env.DB.prepare(
          'INSERT INTO users (id, email, password_hash, created_at) VALUES (?,?,?,?)'
        ).bind(id, email.toLowerCase(), hash, now).run();

        const secret = env.JWT_SECRET || 'dev';
        const token  = await signJWT(
          { sub: id, email: email.toLowerCase(), exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30 },
          secret
        );
        return json({ token, email: email.toLowerCase() }, 201, cors);
      }

      // ── POST /api/auth/reset-password ─────────────────────────────────────
      if (method === 'POST' && path === '/api/auth/reset-password') {
        const { email, new_password } = await request.json();
        if (!email || !new_password) return err('Email and new_password required', 400, cors);
        if (new_password.length < 6)  return err('Password too short (min 6)', 400, cors);

        const user = await env.DB.prepare(
          'SELECT id FROM users WHERE email = ?'
        ).bind(email.toLowerCase()).first();
        if (!user) return err('Email nie je zaregistrovaný', 404, cors);

        const hash = await hashPassword(new_password);
        await env.DB.prepare(
          'UPDATE users SET password_hash = ? WHERE email = ?'
        ).bind(hash, email.toLowerCase()).run();
        return json({ ok: true }, 200, cors);
      }

      // ── POST /api/auth/login ───────────────────────────────────────────────
      if (method === 'POST' && path === '/api/auth/login') {
        const { email, password } = await request.json();
        if (!email || !password) return err('Email and password required', 400, cors);

        const user = await env.DB.prepare(
          'SELECT id, email, password_hash FROM users WHERE email = ?'
        ).bind(email.toLowerCase()).first();
        if (!user) return err('Nesprávny email alebo heslo', 401, cors);

        const ok = await verifyPassword(password, user.password_hash);
        if (!ok)  return err('Nesprávny email alebo heslo', 401, cors);

        const secret = env.JWT_SECRET || 'dev';
        const token  = await signJWT(
          { sub: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30 },
          secret
        );
        return json({ token, email: user.email }, 200, cors);
      }

      // ── Auth check for all other routes ───────────────────────────────────
      const authed = await authenticate(request, env);
      if (!authed) return err('Unauthorized', 401, cors);

      // ══ WHOLE-DOCUMENT MODEL ══════════════════════════════════════════════
      // Celý zoznam produktov je jeden JSON blob v tabuľke `state`
      // (key='products'). Fotky sú base64 v tabuľke `photos` (id → data).
      // Vďaka tomu sa dáta zdieľajú medzi všetkými zariadeniami.

      // ── GET /api/products ──────────────────────────────────────────────────
      // Vráti pole produktov (alebo prázdne pole, ak ešte nič nie je uložené).
      if (method === 'GET' && path === '/api/products') {
        const row = await env.DB.prepare(
          "SELECT value FROM state WHERE key = 'products'"
        ).first();
        const list = row ? JSON.parse(row.value) : [];
        return json(list, 200, cors);
      }

      // ── PUT /api/products ──────────────────────────────────────────────────
      // Uloží celé pole produktov naraz (last-write-wins).
      if (method === 'PUT' && path === '/api/products') {
        const list = await request.json();
        if (!Array.isArray(list)) return err('Expected an array', 400, cors);
        const now = new Date().toISOString();
        await env.DB.prepare(
          `INSERT INTO state (key, value, updated_at) VALUES ('products', ?, ?)
           ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
        ).bind(JSON.stringify(list), now).run();
        return json({ ok: true, count: list.length, updated_at: now }, 200, cors);
      }

      // ── GET /api/photos ────────────────────────────────────────────────────
      // Vráti mapu { id: dataUrl } všetkých fotiek.
      if (method === 'GET' && path === '/api/photos') {
        const { results } = await env.DB.prepare(
          'SELECT id, data FROM photos'
        ).all();
        const map = {};
        for (const r of results) map[r.id] = r.data;
        return json(map, 200, cors);
      }

      // ── PUT /api/photos/:id ────────────────────────────────────────────────
      // Uloží / prepíše jednu fotku (telo = { data: "data:image/..." }).
      const photoMatch = path.match(/^\/api\/photos\/([^/]+)$/);
      if (method === 'PUT' && photoMatch) {
        const id   = photoMatch[1];
        const body = await request.json();
        const data = typeof body === 'string' ? body : body.data;
        if (!data) return err('Missing photo data', 400, cors);
        const now = new Date().toISOString();
        await env.DB.prepare(
          `INSERT INTO photos (id, data, updated_at) VALUES (?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`
        ).bind(id, data, now).run();
        return json({ ok: true }, 200, cors);
      }

      // ── DELETE /api/photos/:id ─────────────────────────────────────────────
      if (method === 'DELETE' && photoMatch) {
        const id = photoMatch[1];
        await env.DB.prepare('DELETE FROM photos WHERE id = ?').bind(id).run();
        return json({ ok: true }, 200, cors);
      }

      // ── GET /api/recent ───────────────────────────────────────────────────
      if (method === 'GET' && path === '/api/recent') {
        const { results } = await env.DB.prepare(
          'SELECT code FROM recent_codes ORDER BY position ASC'
        ).all();
        return json(results.map(r => r.code), 200, cors);
      }

      // ── PUT /api/recent ───────────────────────────────────────────────────
      if (method === 'PUT' && path === '/api/recent') {
        const codes = await request.json();
        await env.DB.prepare('DELETE FROM recent_codes').run();
        const stmt = env.DB.prepare('INSERT INTO recent_codes (position, code) VALUES (?, ?)');
        await env.DB.batch(codes.slice(0, 8).map((code, i) => stmt.bind(i, code)));
        return json({ ok: true }, 200, cors);
      }

      return err('Not found', 404, cors);
    } catch (e) {
      console.error(e);
      return err(e.message, 500, cors);
    }
  },

  // ── Denný cron: automatická záloha (nastavené v wrangler.toml) ──────────────
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runBackup(env).catch((e) => console.error('Backup failed:', e)));
  },
};
