// HealthTrack API — 로그인 토큰 검증 + 암호문 저장. 서버는 비밀번호와 평문 기록을 알지 못한다.
const te = new TextEncoder();
const HDR = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' };
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: HDR });
const err = (m, s = 400, extra = {}) => json({ error: m, ...extra }, s);
const MAX_BODY = 3_000_000, MAX_BLOB = 2_500_000;

async function sha256b64(s) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(s)));
  let r = ''; d.forEach(b => (r += String.fromCharCode(b))); return btoa(r);
}
function eq(a, b) { // 상수 시간 비교
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0;
}
const validName = n => typeof n === 'string' && n.length > 0 && n.length <= 40;
const validTok = t => typeof t === 'string' && /^[A-Za-z0-9+/=]{40,48}$/.test(t);
const validSalt = s => typeof s === 'string' && /^[A-Za-z0-9+/=]{8,64}$/.test(s);
const getRow = (env, name) => env.DB.prepare('SELECT * FROM accounts WHERE name = ?').bind(name).first();

// 로그인 토큰 검증 + 연속 실패 시 잠금(5회부터 30초, 60초, 120초… 최대 1시간)
async function verify(env, row, token) {
  const now = Math.floor(Date.now() / 1000);
  if (row && row.locked_until > now) return err('too_many', 429, { retry: row.locked_until - now });
  const ok = row && row.verifier && validTok(token) && eq(await sha256b64(token), row.verifier);
  if (!ok) {
    if (row) {
      const fails = row.fails + 1, lock = fails >= 5 ? now + Math.min(30 * 2 ** (fails - 5), 3600) : 0;
      await env.DB.prepare('UPDATE accounts SET fails = ?, locked_until = ? WHERE name = ?').bind(fails, lock, row.name).run();
    }
    return err('bad_credentials', 401);
  }
  if (row.fails) await env.DB.prepare('UPDATE accounts SET fails = 0, locked_until = 0 WHERE name = ?').bind(row.name).run();
  return null;
}

async function api(req, env, url) {
  const p = url.pathname;
  if (req.method === 'GET' && p === '/api/salt') {
    const name = url.searchParams.get('name'); if (!validName(name)) return err('bad_request');
    const row = await getRow(env, name);
    if (!row) return json({ authSalt: (await sha256b64('hts|' + name)).slice(0, 22), unclaimed: false });
    return json({ authSalt: row.auth_salt, unclaimed: !row.verifier });
  }
  if (req.method !== 'POST' && req.method !== 'PUT') return err('not_found', 404);
  const text = await req.text(); if (text.length > MAX_BODY) return err('too_large', 413);
  let b; try { b = JSON.parse(text); } catch (e) { return err('bad_json'); }
  if (!b || !validName(b.name)) return err('bad_request');
  const row = await getRow(env, b.name), now = Math.floor(Date.now() / 1000);

  if (req.method === 'POST' && p === '/api/login') {
    const bad = await verify(env, row, b.token); if (bad) return bad;
    return json({ blob: row.blob, version: row.version });
  }
  if (req.method === 'PUT' && p === '/api/data') {
    if (typeof b.blob !== 'string' || b.blob.length > MAX_BLOB || !Number.isInteger(b.version)) return err('bad_request');
    const bad = await verify(env, row, b.token); if (bad) return bad;
    const r = await env.DB.prepare('UPDATE accounts SET blob = ?, version = version + 1, updated_at = ? WHERE name = ? AND version = ?').bind(b.blob, now, row.name, b.version).run();
    if (!r.meta.changes) return err('conflict', 409);
    return json({ version: b.version + 1 });
  }
  if (req.method === 'POST' && p === '/api/claim') { // 주인 없는 계정에 처음 비밀번호를 정함
    if (!row || row.verifier) return err('conflict', 409);
    if (!validTok(b.token) || !validSalt(b.authSalt) || typeof b.blob !== 'string' || b.blob.length > MAX_BLOB) return err('bad_request');
    const r = await env.DB.prepare('UPDATE accounts SET auth_salt = ?, verifier = ?, blob = ?, version = 1, updated_at = ? WHERE name = ? AND verifier IS NULL').bind(b.authSalt, await sha256b64(b.token), b.blob, now, row.name).run();
    if (!r.meta.changes) return err('conflict', 409);
    return json({ version: 1 });
  }
  if (req.method === 'POST' && p === '/api/password') { // 비밀번호 변경(기록은 새 키로 다시 암호화해서 같이 저장)
    if (!validTok(b.newToken) || !validSalt(b.newAuthSalt) || typeof b.blob !== 'string' || b.blob.length > MAX_BLOB || !Number.isInteger(b.version)) return err('bad_request');
    const bad = await verify(env, row, b.token); if (bad) return bad;
    const r = await env.DB.prepare('UPDATE accounts SET auth_salt = ?, verifier = ?, blob = ?, version = version + 1, updated_at = ? WHERE name = ? AND version = ?').bind(b.newAuthSalt, await sha256b64(b.newToken), b.blob, now, row.name, b.version).run();
    if (!r.meta.changes) return err('conflict', 409);
    return json({ version: b.version + 1 });
  }
  return err('not_found', 404);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/api/')) {
      try { return await api(req, env, url); } catch (e) { return err('server_error', 500); }
    }
    return env.ASSETS.fetch(req);
  },
};
