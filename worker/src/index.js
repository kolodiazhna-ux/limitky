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

      // ── GET /api/products ──────────────────────────────────────────────────
      if (method === 'GET' && path === '/api/products') {
        const { results } = await env.DB.prepare(
          'SELECT * FROM products ORDER BY created_at DESC'
        ).all();
        return json(results, 200, cors);
      }

      // ── POST /api/products ─────────────────────────────────────────────────
      if (method === 'POST' && path === '/api/products') {
        const b   = await request.json();
        const id  = newId();
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO products
            (id, code, name, qty, price, miesto, date, note, poznamka, status,
             archived, deleted, created_at, updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        `).bind(
          id, b.code, b.name,
          b.qty || '', b.price || '', b.miesto || '', b.date || '',
          b.note || '', b.poznamka || '', b.status || 'stock',
          0, 0,
          b.created_at || now, b.updated_at || now
        ).run();

        const product = await env.DB.prepare(
          'SELECT * FROM products WHERE id = ?'
        ).bind(id).first();
        return json(product, 201, cors);
      }

      // ── PUT /api/products/:id ──────────────────────────────────────────────
      const singleMatch = path.match(/^\/api\/products\/([^/]+)$/);
      if (method === 'PUT' && singleMatch) {
        const id  = singleMatch[1];
        const b   = await request.json();
        const now = new Date().toISOString();
        await env.DB.prepare(`
          UPDATE products
          SET code=?, name=?, qty=?, price=?, miesto=?, date=?,
              note=?, poznamka=?, status=?, archived=?, deleted=?, updated_at=?
          WHERE id=?
        `).bind(
          b.code, b.name,
          b.qty || '', b.price || '', b.miesto || '', b.date || '',
          b.note || '', b.poznamka || '', b.status || 'stock',
          b.archived ? 1 : 0, b.deleted ? 1 : 0,
          b.updated_at || now, id
        ).run();
        const product = await env.DB.prepare(
          'SELECT * FROM products WHERE id = ?'
        ).bind(id).first();
        return json(product, 200, cors);
      }

      // ── DELETE /api/products/:id ───────────────────────────────────────────
      if (method === 'DELETE' && singleMatch) {
        const id  = singleMatch[1];
        const row = await env.DB.prepare(
          'SELECT photo_key FROM products WHERE id = ?'
        ).bind(id).first();
        if (row?.photo_key) await env.PHOTOS.delete(row.photo_key);
        await env.DB.prepare('DELETE FROM products WHERE id = ?').bind(id).run();
        return json({ ok: true }, 200, cors);
      }

      // ── POST /api/products/:id/photo ───────────────────────────────────────
      const photoMatch = path.match(/^\/api\/products\/([^/]+)\/photo$/);
      if (method === 'POST' && photoMatch) {
        const id          = photoMatch[1];
        const contentType = request.headers.get('Content-Type') || 'image/jpeg';
        const key         = `photos/${id}.jpg`;
        await env.PHOTOS.put(key, request.body, { httpMetadata: { contentType } });
        await env.DB.prepare(
          'UPDATE products SET photo_key = ?, updated_at = ? WHERE id = ?'
        ).bind(key, new Date().toISOString(), id).run();
        return json({ ok: true, key }, 200, cors);
      }

      // ── GET /api/products/:id/photo ────────────────────────────────────────
      if (method === 'GET' && photoMatch) {
        const id  = photoMatch[1];
        const row = await env.DB.prepare(
          'SELECT photo_key FROM products WHERE id = ?'
        ).bind(id).first();
        if (!row?.photo_key) return new Response('Not found', { status: 404, headers: cors });
        const obj = await env.PHOTOS.get(row.photo_key);
        if (!obj) return new Response('Not found', { status: 404, headers: cors });
        return new Response(obj.body, {
          headers: {
            ...cors,
            'Content-Type':  obj.httpMetadata?.contentType || 'image/jpeg',
            'Cache-Control': 'public, max-age=31536000, immutable',
          },
        });
      }

      // ── DELETE /api/products/:id/photo ─────────────────────────────────────
      if (method === 'DELETE' && photoMatch) {
        const id  = photoMatch[1];
        const row = await env.DB.prepare(
          'SELECT photo_key FROM products WHERE id = ?'
        ).bind(id).first();
        if (row?.photo_key) await env.PHOTOS.delete(row.photo_key);
        await env.DB.prepare(
          'UPDATE products SET photo_key = NULL, updated_at = ? WHERE id = ?'
        ).bind(new Date().toISOString(), id).run();
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
};
