// Zero-dependency game site: public game library + password-protected admin panel.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'games.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_MS = 1000 * 60 * 60 * 12; // 12 hours

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  console.error('Set ADMIN_PASSWORD (min 8 chars) before starting. Example:\n  ADMIN_PASSWORD="your-long-password" node server.js');
  process.exit(1);
}

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) {
  const sample = fs.readFileSync(path.join(__dirname, 'sample-game.html'), 'utf8');
  fs.writeFileSync(DATA_FILE, JSON.stringify([{
    id: 'click-catcher', title: 'Click Catcher',
    description: 'Sample game: click the targets before they vanish.',
    html: sample, updated: Date.now()
  }], null, 2));
}
const load = () => JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
const save = (g) => {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(g, null, 2));
  fs.renameSync(tmp, DATA_FILE);
};

// ---- auth helpers ----
const sign = (v) => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const safeEq = (a, b) => {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};
const makeToken = () => { const exp = String(Date.now() + SESSION_MS); return exp + '.' + sign(exp); };
const validToken = (t) => {
  if (!t) return false;
  const [exp, sig] = t.split('.');
  return !!sig && safeEq(sig, sign(exp)) && Number(exp) > Date.now();
};
const parseCookies = (h) => Object.fromEntries((h || '').split(';').map(c => c.trim().split('=')).filter(p => p[0]).map(([k, ...v]) => [k, v.join('=')]));
const isAdmin = (req) => validToken(parseCookies(req.headers.cookie).session);

// simple login rate limit: 5 failures / 15 min per IP
const fails = new Map();
const ipOf = (req) => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const blocked = (ip) => { const f = (fails.get(ip) || []).filter(t => Date.now() - t < 900000); fails.set(ip, f); return f.length >= 5; };

// ---- helpers ----
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
const baseHeaders = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' };
const send = (res, code, body, headers = {}) => { res.writeHead(code, { ...baseHeaders, ...headers }); res.end(body); };
const json = (res, code, obj, headers = {}) => send(res, code, JSON.stringify(obj), { 'Content-Type': 'application/json', ...headers });
const readBody = (req) => new Promise((resolve, reject) => {
  let size = 0; const chunks = [];
  req.on('data', c => { size += c.length; if (size > 5e6) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
  req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch (e) { reject(e); } });
});
const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 50) || 'game';
const publicView = ({ id, title, description, updated }) => ({ id, title, description, updated });

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  try {
    // ---- public API ----
    if (p === '/api/games' && req.method === 'GET') return json(res, 200, load().map(publicView));

    // play a game: sandboxed (no same-origin) so game code can never touch admin cookies/API
    let m = p.match(/^\/play\/([a-z0-9-]+)$/);
    if (m && req.method === 'GET') {
      const g = load().find(x => x.id === m[1]);
      if (!g) return send(res, 404, 'Not found');
      return send(res, 200, g.html, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': 'sandbox allow-scripts allow-pointer-lock allow-popups' });
    }

    // ---- admin API ----
    if (p === '/api/admin/login' && req.method === 'POST') {
      const ip = ipOf(req);
      if (blocked(ip)) return json(res, 429, { error: 'Too many attempts. Try again later.' });
      const body = await readBody(req);
      if (safeEq(body.password || '', ADMIN_PASSWORD)) {
        const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
        return json(res, 200, { ok: true }, { 'Set-Cookie': `session=${makeToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${secure}` });
      }
      fails.get(ip).push(Date.now());
      return json(res, 401, { error: 'Wrong password' });
    }
    if (p === '/api/admin/logout' && req.method === 'POST') return json(res, 200, { ok: true }, { 'Set-Cookie': 'session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
    if (p === '/api/admin/me') return json(res, 200, { admin: isAdmin(req) });

    if (p.startsWith('/api/admin/')) {
      if (!isAdmin(req)) return json(res, 401, { error: 'Not authorized' });
      if (req.method !== 'GET' && !(req.headers['content-type'] || '').includes('application/json')) return json(res, 415, { error: 'JSON only' });
      const games = load();

      if (p === '/api/admin/games' && req.method === 'GET') return json(res, 200, games);

      if (p === '/api/admin/games' && req.method === 'POST') {
        const b = await readBody(req);
        if (!b.title || !b.html) return json(res, 400, { error: 'Title and game code are required' });
        let id = slug(b.title); let n = 2;
        while (games.some(g => g.id === id)) id = slug(b.title) + '-' + n++;
        const g = { id, title: String(b.title).slice(0, 100), description: String(b.description || '').slice(0, 300), html: String(b.html), updated: Date.now() };
        games.push(g); save(games); return json(res, 201, g);
      }

      m = p.match(/^\/api\/admin\/games\/([a-z0-9-]+)$/);
      if (m) {
        const i = games.findIndex(g => g.id === m[1]);
        if (i < 0) return json(res, 404, { error: 'Not found' });
        if (req.method === 'PUT') {
          const b = await readBody(req);
          if (!b.title || !b.html) return json(res, 400, { error: 'Title and game code are required' });
          games[i] = { ...games[i], title: String(b.title).slice(0, 100), description: String(b.description || '').slice(0, 300), html: String(b.html), updated: Date.now() };
          save(games); return json(res, 200, games[i]);
        }
        if (req.method === 'DELETE') { games.splice(i, 1); save(games); return json(res, 200, { ok: true }); }
      }
      return json(res, 404, { error: 'Not found' });
    }

    // ---- static files ----
    let file = p === '/' ? '/index.html' : p === '/admin' ? '/admin.html' : p;
    const full = path.normalize(path.join(PUBLIC_DIR, file));
    if (!full.startsWith(PUBLIC_DIR) || !fs.existsSync(full) || fs.statSync(full).isDirectory()) return send(res, 404, 'Not found');
    return send(res, 200, fs.readFileSync(full), { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
  } catch (e) {
    return json(res, 500, { error: 'Server error' });
  }
}).listen(PORT, () => console.log(`Game site running on http://localhost:${PORT}  (admin: /admin)`));
