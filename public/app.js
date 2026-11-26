(() => {
'use strict';
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const KEY = 'healthtrack.v2', OLD_KEY = 'healthtrack.v1', DEFAULT_NAMES = ['쭌', '쏘'];
const LABEL = { ok: '정상', warn: '주의', bad: '이상', none: '-' };
const RANK = { ok: 0, warn: 1, bad: 2 };
const uid = () => Math.random().toString(36).slice(2, 9);

/* ---------- 저장소: 서버(Cloudflare D1)에 암호문으로 저장 ---------- */
// 서버는 비밀번호도 평문 기록도 알지 못한다. 브라우저에서 비밀번호로 암호화한 덩어리(blob)만 저장한다.
function load() {
  try {
    const r = JSON.parse(localStorage.getItem(KEY));
    if (r && Array.isArray(r.profiles) && r.profiles.length) return { profiles: r.profiles.map(p => ({ id: p.id, name: p.name })), current: r.profiles.some(p => p.id === r.current) ? r.current : r.profiles[0].id, data: {}, acct: {} };
  } catch (e) {}
  return { profiles: DEFAULT_NAMES.map(n => ({ id: n, name: n })), current: DEFAULT_NAMES[0], data: {}, acct: {} };
}
let S = load();
function saveLocal() { try { localStorage.setItem(KEY, JSON.stringify({ profiles: S.profiles.map(p => ({ id: p.id, name: p.name })), current: S.current })); } catch (e) {} }
const keys = {}; // 로그인한 사람의 키·토큰(메모리에만 보관, 새로고침하면 다시 로그인)

/* ---------- 암호화 (PBKDF2 → AES-GCM) ---------- */
const ITER = 200000;
const te = new TextEncoder();
const b64e = u8 => { let s = ''; u8.forEach(b => s += String.fromCharCode(b)); return btoa(s); };
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const rand = n => crypto.getRandomValues(new Uint8Array(n));
async function deriveKey(pass, salt, iter) {
  const km = await crypto.subtle.importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
// 서버 로그인용 토큰: 암호화 키와는 별개로 비밀번호에서 한 번 더 유도한다(서버는 토큰의 해시만 저장)
async function makeToken(pass, authSalt) {
  const km = await crypto.subtle.importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveBits']);
  return b64e(new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: te.encode('auth|' + authSalt), iterations: ITER, hash: 'SHA-256' }, km, 256)));
}
async function encData(k, obj) {
  const iv = rand(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k.key, te.encode(JSON.stringify(obj))));
  return { s: b64e(k.salt), i: b64e(iv), c: b64e(ct), n: k.iter };
}
async function decData(key, blob) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(blob.i) }, key, b64d(blob.c));
  return JSON.parse(new TextDecoder().decode(pt));
}

/* ---------- 서버 통신·저장 ---------- */
async function api(method, path, body) {
  let r;
  try { r = await fetch(path, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }); }
  catch (e) { const er = new Error('network'); er.status = 0; throw er; }
  let j = {}; try { j = await r.json(); } catch (e) {}
  if (!r.ok) { const er = new Error(j.error || 'http_' + r.status); er.status = r.status; er.data = j; throw er; }
  return j;
}
const dirty = new Set(); let saveQ = Promise.resolve(), saveT = 0;
function setSync(t, cls) { const el = $('#sync'); if (el) { el.textContent = t; el.className = 'sync ' + (cls || ''); } }
function save() { dirty.add(S.current); setSync('저장 대기…'); clearTimeout(saveT); saveT = setTimeout(persist, 700); }
function persist() {
  clearTimeout(saveT);
  saveQ = saveQ.then(async () => {
    for (const id of [...dirty]) {
      const k = keys[id], data = S.data[id];
      if (!k || !data) { dirty.delete(id); continue; }
      setSync('저장 중…');
      try {
        data.sex = (S.profiles.find(p => p.id === id) || {}).sex || 'M';
        const r = await api('PUT', '/api/data', { name: id, token: k.token, blob: JSON.stringify(await encData(k, data)), version: k.version });
        k.version = r.version; dirty.delete(id);
      } catch (e) {
        setSync('⚠ 저장 실패', 'bad');
        toast(e.status === 409 ? '다른 기기에서 먼저 수정했어요. 새로고침 후 다시 로그인해서 입력하세요' : e.status === 0 ? '서버에 연결할 수 없어요. 저장되지 않았어요' : '서버 저장 실패: ' + e.message);
        return;
      }
    }
    setSync('☁ 저장됨', 'ok');
  });
  return saveQ;
}
window.addEventListener('beforeunload', e => { if (dirty.size) { e.preventDefault(); e.returnValue = ''; } });
const prof = () => S.profiles.find(p => p.id === S.current) || S.profiles[0];
const pdata = () => (S.data[prof().id] ||= { records: {}, custom: [], exams: [] });
const examList = () => (pdata().exams ||= []);
function toast(m) { const t = $('#toast'); t.textContent = m; t.classList.add('on'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('on'), 2200); }

/* ---------- 항목·판정 ---------- */
function items() {
  const c = (pdata().custom || []).map(ci => {
    const n = (ci.min == null && ci.max == null) ? null : [ci.min ?? -INF, ci.max ?? INF];
    return { id: ci.id, name: ci.name, unit: ci.unit || '', cat: '사용자 항목', dec: 2, alias: [], custom: true, incl: true, n, w: n };
  });
  return CATALOG.concat(c);
}
const itemById = id => items().find(i => i.id === id);
const pick = (r, sex) => !r ? null : Array.isArray(r) ? r : (r[sex] || r.M);
const inR = (v, r, incl) => v >= r[0] && (v < r[1] || (incl && v === r[1]));
function statusOf(item, v) {
  const n = pick(item.n, prof().sex);
  if (!n || v == null || isNaN(v)) return 'none';
  if (inR(v, n, item.incl)) return 'ok';
  const w = pick(item.w, prof().sex);
  return w && inR(v, w, item.incl) ? 'warn' : 'bad';
}
function valOf(item, rec) {
  const v = rec.values[item.id];
  if (v != null && v !== '') return +v;
  if (item.id === 'bmi') { const h = +rec.values.height, w = +rec.values.weight; if (h > 0 && w > 0) return w / ((h / 100) ** 2); }
}
const years = () => Object.keys(pdata().records).map(Number).sort((a, b) => a - b);
function series(item) {
  const out = [];
  for (const y of years()) { const rec = pdata().records[y]; const v = valOf(item, rec); if (v != null && !isNaN(v)) out.push({ year: y, value: v, status: statusOf(item, v), date: rec.date }); }
  return out;
}
const fmt = (v, d = 1) => v == null ? '-' : String(+Number(v).toFixed(d));
const fv = (item, v) => fmt(v, item.dec ?? 1);
const sgn = (d, item) => (d > 0 ? '+' : d < 0 ? '' : '±') + fv(item, d);
function rangeText(r) {
  if (!r) return '';
  const [lo, hi] = r;
  if (lo <= 0 && hi !== INF) return `< ${hi}`;
  if (hi === INF) return `≥ ${lo}`;
  if (lo === -INF) return `≤ ${hi}`;
  return `${lo} – ${hi}`;
}
function refText(item) {
  const n = pick(item.n, prof().sex), w = pick(item.w, prof().sex);
  if (!n) return '기준치 없음';
  let t = `정상 ${rangeText(n)}`;
  if (w && (w[0] !== n[0] || w[1] !== n[1])) t += ` · 주의 ${rangeText(w)} 이내`;
  return t + ' · 그 밖은 이상';
}
function stats(item, ser) {
  const vs = ser.map(p => p.value), n = vs.length;
  const last = ser[n - 1], prev = ser[n - 2], first = ser[0];
  const min = ser.reduce((a, b) => b.value < a.value ? b : a), max = ser.reduce((a, b) => b.value > a.value ? b : a);
  let slope = null;
  if (n >= 3) {
    const xs = ser.map(p => p.year), mx = xs.reduce((a, b) => a + b) / n, my = vs.reduce((a, b) => a + b) / n;
    const den = xs.reduce((a, x) => a + (x - mx) ** 2, 0);
    if (den) slope = xs.reduce((a, x, i) => a + (x - mx) * (vs[i] - my), 0) / den;
  }
  let trend = 'same';
  if (prev) { const a = RANK[prev.status], b = RANK[last.status]; if (a != null && b != null) trend = b < a ? 'better' : b > a ? 'worse' : 'same'; }
  return { n, last, prev, first, min, max, avg: vs.reduce((a, b) => a + b) / n, slope, trend };
}

/* ---------- 검색 ---------- */
const CHO = 'ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ';
const chosung = s => [...s].map(c => { const k = c.charCodeAt(0) - 0xAC00; return k >= 0 && k < 11172 ? CHO[Math.floor(k / 588)] : c; }).join('');
const norm = s => String(s).toLowerCase().replace(/[\s\-_()·\/]/g, '');
function matchScore(item, q) {
  const nq = norm(q); if (!nq) return 0;
  const name = norm(item.name), al = item.alias.map(norm);
  if (name === nq || al.includes(nq)) return 100;
  if (name.startsWith(nq)) return 90;
  if (name.includes(nq)) return 80;
  if (al.some(a => a.includes(nq) || (a.length > 1 && nq.includes(a)))) return 60;
  if (/^[ㄱ-ㅎ]+$/.test(nq) && chosung(name).includes(nq)) return 50;
  if (norm(item.cat).includes(nq)) return 40;
  return 0;
}

/* ---------- SVG ---------- */
function niceDomain(vals, item) {
  let lo = Math.min(...vals), hi = Math.max(...vals);
  const span = (hi - lo) || Math.abs(hi) * 0.1 || 1;
  const sex = prof().sex;
  for (const r of [pick(item.n, sex), pick(item.w, sex)]) {
    if (!r) continue;
    for (const b of r) if (isFinite(b) && b >= lo - 1.5 * span && b <= hi + 1.5 * span) { lo = Math.min(lo, b); hi = Math.max(hi, b); }
  }
  const pad = (hi - lo) * 0.1 || 1;
  return [lo - pad, hi + pad];
}
function lineChart(ser, item, o = {}) {
  const W = 640, H = o.compact ? 150 : 260, pl = o.compact ? 12 : 46, pr = 18, pt = 24, pb = o.compact ? 22 : 30;
  const [lo, hi] = niceDomain(ser.map(p => p.value), item);
  const y = v => pt + (1 - (v - lo) / (hi - lo)) * (H - pt - pb);
  const yc = v => y(Math.min(hi, Math.max(lo, v)));
  const ys = ser.map(p => p.year), y0 = Math.min(...ys), y1 = Math.max(...ys);
  const x = yr => y0 === y1 ? (pl + W - pr) / 2 : pl + 16 + (yr - y0) / (y1 - y0) * (W - pl - pr - 32);
  let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(item.name)} 추이">`;
  const sex = prof().sex, nR = pick(item.n, sex), wR = pick(item.w, sex);
  const band = (r, col, op) => { if (!r) return; const a = yc(r[1]), b = yc(r[0]); if (b - a > 0.5) s += `<rect x="${pl}" y="${a}" width="${W - pl - pr}" height="${b - a}" fill="${col}" opacity="${op}"/>`; };
  band(wR, 'var(--warn)', 0.16); band(nR, 'var(--ok)', 0.22);
  if (!o.compact) for (let i = 0; i <= 4; i++) {
    const v = lo + (hi - lo) * i / 4, yy = y(v);
    s += `<line x1="${pl}" x2="${W - pr}" y1="${yy}" y2="${yy}" stroke="var(--line)"/><text x="${pl - 6}" y="${yy + 4}" text-anchor="end">${fmt(v, item.dec ?? 1)}</text>`;
  }
  s += `<polyline fill="none" stroke="var(--accent)" stroke-width="2" points="${ser.map(p => `${x(p.year)},${y(p.value)}`).join(' ')}"/>`;
  ser.forEach((p, i) => {
    const col = p.status === 'none' ? 'var(--accent)' : `var(--${p.status})`;
    s += `<circle cx="${x(p.year)}" cy="${y(p.value)}" r="4.5" fill="${col}" stroke="var(--card)" stroke-width="1.5"><title>${p.year}년 ${esc(item.name)} ${fv(item, p.value)} ${esc(item.unit)} (${LABEL[p.status]})</title></circle>`;
    if (!o.compact || i === ser.length - 1) s += `<text class="vl" x="${x(p.year)}" y="${y(p.value) - 9}" text-anchor="middle">${fv(item, p.value)}</text>`;
    s += `<text x="${x(p.year)}" y="${H - 8}" text-anchor="middle">${o.compact && ser.length > 6 && i % 2 ? '' : p.year}</text>`;
  });
  return s + '</svg>';
}
function spark(ser, item) {
  const W = 84, H = 26, vs = ser.map(p => p.value), lo = Math.min(...vs), hi = Math.max(...vs), rg = hi - lo || 1;
  const pts = ser.map((p, i) => [ser.length === 1 ? W / 2 : 3 + i / (ser.length - 1) * (W - 6), H - 4 - (p.value - lo) / rg * (H - 8)]);
  const l = ser[ser.length - 1], c = l.status === 'none' ? 'var(--accent)' : `var(--${l.status})`;
  return `<svg viewBox="0 0 ${W} ${H}" style="width:${W}px"><polyline fill="none" stroke="var(--muted)" stroke-width="1.5" points="${pts.map(p => p.join(',')).join(' ')}"/><circle cx="${pts[pts.length - 1][0]}" cy="${pts[pts.length - 1][1]}" r="3" fill="${c}"/></svg>`;
}
function stackChart(rows) {
  const W = 640, H = 200, pl = 10, pt = 22, pb = 26, mx = Math.max(...rows.map(r => r.ok + r.warn + r.bad)) || 1;
  const bw = Math.min(54, (W - pl * 2) / rows.length - 12);
  let s = `<svg viewBox="0 0 ${W} ${H}">`;
  rows.forEach((r, i) => {
    const cx = pl + (i + 0.5) * (W - pl * 2) / rows.length; let yy = H - pb;
    for (const k of ['ok', 'warn', 'bad']) {
      const h = r[k] / mx * (H - pt - pb); if (!h) continue; yy -= h;
      s += `<rect x="${cx - bw / 2}" y="${yy}" width="${bw}" height="${h}" fill="var(--${k})" rx="3"><title>${r.year}년 ${LABEL[k]} ${r[k]}개</title></rect>`;
      if (h > 14) s += `<text x="${cx}" y="${yy + h / 2 + 4}" text-anchor="middle" style="fill:#fff;font-weight:600">${r[k]}</text>`;
    }
    s += `<text x="${cx}" y="${H - 8}" text-anchor="middle">${r.year}</text>`;
  });
  return s + '</svg>';
}

/* ---------- 상태 ---------- */
const state = { view: 'summary', from: 'summary', detail: null, q: '', sel: null, inYear: null, sumYear: null, examTag: '', examKind: '', examPlace: '', gsym: '', editExam: null };
const TABS = [['summary', '요약'], ['table', '연도별 표'], ['trend', '추이'], ['exams', '검사 기록'], ['guide', '검사 가이드'], ['family', '가족'], ['input', '수치 입력'], ['data', '설정·데이터']];
const TAGS = { '정상': 'ok', '경과관찰': 'warn', '이상': 'bad', '조치': 'act', '예정': 'plan' };
const tagBadge = t => `<span class="badge ${TAGS[t] || 'none'}">${esc(t)}</span>`;
const badge = st => `<span class="badge ${st}">${LABEL[st]}</span>`;
const dItem = (item, ser) => {
  const s = stats(item, ser); if (!s.prev) return '<span class="flat small">비교 없음</span>';
  const d = s.last.value - s.prev.value;
  const cls = s.trend === 'better' ? 'down' : s.trend === 'worse' ? 'up' : 'flat';
  const ar = d > 0 ? '▲' : d < 0 ? '▼' : '–';
  return `<span class="${cls} small">${ar} ${sgn(d, item)} (전회 ${s.prev.year})${s.trend === 'better' ? ' 호전' : s.trend === 'worse' ? ' 악화' : ''}</span>`;
};
const rowHtml = (item, ser) => {
  const l = ser[ser.length - 1];
  return `<div class="it" data-act="detail" data-id="${esc(item.id)}"><div class="nm">${esc(item.name)}<small>${esc(item.cat)} · ${l.year}년</small></div>${spark(ser, item)}<div style="text-align:right"><div class="val">${fv(item, l.value)} <small class="muted">${esc(item.unit)}</small> ${badge(l.status)}</div>${dItem(item, ser)}</div></div>`;
};
const hasData = () => years().length > 0;

/* 다음에 받을 검사: 직전 기록의 권장 추적 연도 + 예정 항목 */
function upcoming() {
  const list = examList(), map = {}, Y = new Date().getFullYear();
  const doneAfter = (kind, y) => list.some(e => e.kind === kind && e.tag !== '예정' && e.year >= y);
  const latest = {};
  list.filter(e => e.tag !== '예정').forEach(e => { if (!latest[e.kind] || e.year > latest[e.kind].year || (e.year === latest[e.kind].year && (e.date || '') > (latest[e.kind].date || ''))) latest[e.kind] = e; });
  for (const k in latest) { const l = latest[k]; if (l.due && !doneAfter(k, l.due)) map[k] = { kind: k, due: +l.due, last: l, plan: null }; }
  // 기록에 추적 연도가 없는 검사는 일반적인 권장 주기(가이드)로 계산
  GUIDE.filter(g => g.interval).forEach(g => {
    const l = latest[g.kind]; if (!l || l.due || map[g.kind]) return;
    const due = l.year + g.interval; if (due <= Y) map[g.kind] = { kind: g.kind, due, last: l, plan: null, auto: g.interval };
  });
  list.filter(e => e.tag === '예정' && !doneAfter(e.kind, e.year)).forEach(e => { map[e.kind] = { kind: e.kind, due: e.year, last: latest[e.kind] || null, plan: e }; });
  return Object.values(map).sort((a, b) => a.due - b.due || a.kind.localeCompare(b.kind));
}
function dueLabel(u) {
  const Y = new Date().getFullYear(), late = u.due < Y, now = u.due === Y;
  const lab = u.plan ? (late ? '기간 지남' : now ? '올해 예정' : `${u.due}년 예정`)
    : u.auto ? (late ? `${u.auto}년 주기 · 지남` : `올해 권장 (${u.auto}년 주기)`)
    : (late ? `${u.due}년 권장 · 지남` : now ? '올해 권장' : `${u.due}년 권장`);
  return { lab, cls: late ? 'bad' : now ? 'warn' : 'plan' };
}
function upHtml() {
  const up = upcoming(); if (!up.length) return '';
  return `<div class="card"><h3>다음에 받을 검사 (${up.length})</h3><div class="list">${up.map(u => {
    const { lab, cls } = dueLabel(u);
    const info = (u.plan ? u.plan.result : u.last.result) || '';
    const prev = u.plan && u.last ? ` · 직전 ${u.last.year}년: ${u.last.result || ''}` : u.last && !u.plan ? ` · 마지막 ${u.last.year}년` : '';
    return `<div class="it" data-act="filterKind" data-v="${esc(u.kind)}"><div class="nm">${esc(u.kind)}<small>${esc(info + prev)}</small></div><span class="badge ${cls}">${lab}</span></div>`;
  }).join('')}</div></div>`;
}
const examRow = (e, showYear) => `<div class="ex"><div class="exh"><b>${esc(e.kind)}</b> ${tagBadge(e.tag)} <span class="muted small">${showYear ? e.year + '년 ' : ''}${esc(e.date || '')} ${placeLink(e.place)}</span><span class="sp"></span><button class="btn small" data-act="editExam" data-id="${esc(e.id)}">수정</button></div>${e.result ? `<div>${esc(e.result)}</div>` : ''}${e.note ? `<div class="muted small">${esc(e.note)}</div>` : ''}${e.due ? `<div class="small muted">권장 추적: ${esc(e.due)}년</div>` : ''}</div>`;
const placeLink = pl => pl ? `<a href="https://map.naver.com/p/search/${encodeURIComponent(pl)}" target="_blank" rel="noopener noreferrer" title="지도에서 찾기">📍${esc(pl)}</a>` : '';
function withProfile(id, fn) { const prev = S.current; S.current = id; try { return fn(); } finally { S.current = prev; } }
// 결과·메모 문구('1년 뒤', '2년마다', '내년에도')에서 권장 추적 연도를 읽어냄
function inferDue(year, text) {
  const t = text || '', m = t.match(/(\d+)\s*년\s*(뒤|후|마다)/);
  if (m && +m[1] > 0 && +m[1] <= 10) return year + +m[1];
  if (/내년/.test(t)) return year + 1;
  return null;
}
function histLine(kind) {
  const es = examList().filter(e => e.kind === kind && e.tag !== '예정').sort((a, b) => a.year - b.year || (a.date || '').localeCompare(b.date || ''));
  const plan = examList().find(e => e.kind === kind && e.tag === '예정');
  if (!es.length) return `<div class="small muted">내 기록: 아직 없어요${plan ? ` · ${plan.year}년 예정` : ''}</div>`;
  const last = es[es.length - 1], ago = new Date().getFullYear() - last.year, g = GUIDE.find(x => x.kind === kind);
  return `<div class="small">내 기록: ${es.map(e => `${e.year} ${tagBadge(e.tag)}`).join(' · ')} <span class="muted">· 마지막 ${ago ? ago + '년 전' : '올해'}${g && g.interval ? ` · 권장 ${g.interval}년 주기 → ${last.year + g.interval}년` : ''}</span> <a href="#" data-act="filterKind" data-v="${esc(kind)}">기록 보기</a></div>`;
}
const guideCard = (g, open) => `<details class="gd" ${open ? 'open' : ''}><summary><b>${esc(g.kind)}</b> <span class="muted small">${esc(g.cat)}${g.interval ? ' · 권장 ' + g.interval + '년 주기' : ''}</span></summary><div class="gdb"><p>${esc(g.what)}</p><p><b>잘 찾는 것</b> ${esc(g.good)}</p><p><b>준비</b> ${esc(g.prep)}</p><p><b>주기</b> ${esc(g.cycle)}</p>${histLine(g.kind)}</div></details>`;
const termCard = t => `<div class="ex"><b>${esc(t.name)}</b><div>${esc(t.text)}</div></div>`;
const symCard = sy => `<div class="card"><h3>${esc(sy.sym)}</h3><p class="muted small">${esc(sy.note)}</p>${sy.exams.map(k => { const g = GUIDE.find(x => x.kind === k); return g ? guideCard(g, true) : `<div class="ex"><b>${esc(k)}</b></div>`; }).join('')}</div>`;
function defaultYear(ys) {
  const cnt = ys.map(y => items().filter(it => series(it).some(p => p.year === y)).length), mx = Math.max(...cnt);
  for (let i = ys.length - 1; i >= 0; i--) if (cnt[i] >= mx / 2) return ys[i];
  return ys[ys.length - 1];
}
const emptyHtml = () => `<div class="card empty"><h2>아직 검진 결과가 없어요</h2><p>‘입력’ 탭에서 연도별 결과를 넣거나, 샘플 데이터로 먼저 둘러보세요.</p><button class="btn pri" data-act="sample">샘플 데이터 불러오기</button> <button class="btn" data-act="goInput">직접 입력하기</button></div>`;

/* ---------- 뷰 ---------- */
// 요약 화면용 조각들
const SHORT = { bmi: 'BMI', ggt: 'γ-GTP', alt: 'ALT', ast: 'AST', ldl: 'LDL', hdl: 'HDL', tc: '총콜레스테롤', tg: '중성지방', glucose: '공복혈당', hba1c: '당화혈색소', egfr: 'eGFR', hb: '혈색소', uric: '요산', sbp: '수축기 혈압', dbp: '이완기 혈압', waist: '허리둘레', creat: '크레아티닌' };
const shortName = it => SHORT[it.id] || it.name;
const lastOf = ser => ser[ser.length - 1];
function deltaChip(it, ser) {
  const s = stats(it, ser); if (!s.prev) return '<span class="flat">–</span>';
  const d = s.last.value - s.prev.value, cls = s.trend === 'better' ? 'down' : s.trend === 'worse' ? 'up' : 'flat';
  return `<span class="${cls}" title="전회(${s.prev.year}년) ${fv(it, s.prev.value)}">${d > 0 ? '▲' : d < 0 ? '▼' : '–'} ${fv(it, Math.abs(d))}</span>`;
}
const tileHtml = (name, val, unit, st, delta, sp, id) => `<div class="tile ${st}" data-act="detail" data-id="${esc(id)}"><div class="tn">${esc(name)}</div><div class="tv">${esc(val)}<small>${esc(unit)}</small></div><div class="tf">${delta}${sp}</div></div>`;
const KEY_TILES = ['bp', 'glucose', 'hba1c', 'ldl', 'tg', 'bmi', 'alt', 'ggt', 'hdl', 'tc', 'egfr', 'hb', 'uric'];

const views = {
  summary() {
    if (!hasData()) return upHtml() + emptyHtml();
    const ys = years(); const Y = ys.includes(state.sumYear) ? state.sumYear : defaultYear(ys);
    const rec = pdata().records[Y], idx = ys.indexOf(Y);
    const all = items().map(it => ({ it, ser: series(it).filter(p => p.year <= Y) })).filter(x => x.ser.length && lastOf(x.ser).year === Y);
    const cnt = { ok: 0, warn: 0, bad: 0 };
    all.forEach(x => { const st = lastOf(x.ser).status; if (cnt[st] != null) cnt[st]++; });
    const judged = cnt.ok + cnt.warn + cnt.bad, attn = cnt.warn + cnt.bad;
    const need = all.filter(x => ['warn', 'bad'].includes(lastOf(x.ser).status)).sort((a, b) => RANK[lastOf(b.ser).status] - RANK[lastOf(a.ser).status]);
    const better = all.filter(x => stats(x.it, x.ser).trend === 'better').length, worse = all.filter(x => stats(x.it, x.ser).trend === 'worse').length;
    const rows = ys.map(y => { const c = { year: y, ok: 0, warn: 0, bad: 0 }; items().forEach(it => { const p = series(it).find(p => p.year === y); if (p && c[p.status] != null) c[p.status]++; }); return c; });
    const seg = (k, n) => n ? `<span class="s ${k}" style="flex:${n}">${LABEL[k]} ${n}</span>` : '';
    const hero = `<div class="card hero"><div class="row"><h2 style="margin:0">${Y}년 검진</h2>${rec.date ? `<span class="muted small">${esc(rec.date)}</span>` : ''}<span class="sp"></span>
      <select data-chg="sumYear">${ys.slice().reverse().map(y => `<option ${y === Y ? 'selected' : ''}>${y}</option>`).join('')}</select></div>
      <div class="hl">${judged ? (attn ? `${judged}개 항목 중 <b>${attn}개</b>를 확인해야 해요` : `${judged}개 항목이 모두 정상이에요 👍`) : '판정할 수 있는 항목이 없어요'}</div>
      ${judged ? `<div class="sbar">${seg('ok', cnt.ok)}${seg('warn', cnt.warn)}${seg('bad', cnt.bad)}</div>` : ''}
      ${idx > 0 ? `<div class="small muted" style="margin-top:8px">전회(${ys[idx - 1]}년) 대비 &nbsp;좋아진 항목 <b class="down">${better}</b> · 나빠진 항목 <b class="up">${worse}</b></div>` : ''}</div>`;
    const tiles = [];
    for (const id of KEY_TILES) {
      if (tiles.length >= 8) break;
      if (id === 'bp') {
        const a = all.find(x => x.it.id === 'sbp'), b = all.find(x => x.it.id === 'dbp');
        if (a && b) { const la = lastOf(a.ser), lb = lastOf(b.ser); tiles.push(tileHtml('혈압', `${fmt(la.value, 0)}/${fmt(lb.value, 0)}`, 'mmHg', (RANK[la.status] || 0) >= (RANK[lb.status] || 0) ? la.status : lb.status, deltaChip(a.it, a.ser), spark(a.ser, a.it), 'sbp')); }
        continue;
      }
      const x = all.find(x => x.it.id === id); if (!x) continue;
      const l = lastOf(x.ser); tiles.push(tileHtml(shortName(x.it), fv(x.it, l.value), x.it.unit, l.status, deltaChip(x.it, x.ser), spark(x.ser, x.it), id));
    }
    const up = upcoming();
    const todo = up.slice(0, 4).map(u => { const { lab, cls } = dueLabel(u); return `<div class="it" data-act="filterKind" data-v="${esc(u.kind)}"><div class="nm">${esc(u.kind)}</div><span class="badge ${cls}">${lab}</span></div>`; }).join('');
    const two = `<div class="two"><div class="card"><div class="row"><h3 style="margin:0">지금 챙길 것</h3><span class="sp"></span>${up.length > 4 ? `<a href="#" data-act="goExams" class="small">전체 ${up.length}건 →</a>` : ''}</div>${todo ? `<div class="list" style="margin-top:6px">${todo}</div>` : '<p class="muted">받을 검사 알림이 없어요 👍</p>'}</div>
      <div class="card"><h3>주의·이상 항목 (${need.length})</h3>${need.length ? `<div class="pills">${need.map(x => { const l = lastOf(x.ser); return `<span class="pill ${l.status}" data-act="detail" data-id="${esc(x.it.id)}">${esc(shortName(x.it))} <b>${fv(x.it, l.value)}</b></span>`; }).join('')}</div>` : '<p class="muted">없어요 👍</p>'}</div></div>`;
    return `${hero}${tiles.length ? `<div class="tiles">${tiles.join('')}</div>` : ''}${two}<div class="card"><h3>연도별 판정 분포</h3>${stackChart(rows)}</div>`;
  },
  table() {
    if (!hasData()) return emptyHtml();
    const ys = years(); let h = `<div class="card tw"><table><thead><tr><th>항목</th>${ys.map(y => `<th>${y}</th>`).join('')}<th>추이</th></tr></thead><tbody>`;
    const cats = [...new Set(items().map(i => i.cat))].sort((a, b) => CAT_ORDER.indexOf(a) - CAT_ORDER.indexOf(b));
    for (const c of cats) {
      const list = items().filter(i => i.cat === c).map(it => ({ it, ser: series(it) })).filter(x => x.ser.length);
      if (!list.length) continue;
      h += `<tr class="cat"><td colspan="${ys.length + 2}">${esc(c)}</td></tr>`;
      for (const { it, ser } of list) {
        h += `<tr class="link" data-act="detail" data-id="${esc(it.id)}"><td>${esc(it.name)} <small class="muted">${esc(it.unit)}</small></td>`;
        for (const y of ys) { const p = ser.find(p => p.year === y); h += p ? `<td class="${p.status}">${fv(it, p.value)}</td>` : '<td class="muted">·</td>'; }
        h += `<td>${spark(ser, it)}</td></tr>`;
      }
    }
    return h + `</tbody></table></div><p class="muted small">색상: <span class="badge ok">정상</span> <span class="badge warn">주의</span> <span class="badge bad">이상</span> · 항목을 누르면 상세 추이를 봅니다.</p>`;
  },
  trend() {
    if (!hasData()) return emptyHtml();
    const avail = items().map(it => ({ it, ser: series(it) })).filter(x => x.ser.length);
    if (!state.sel) state.sel = new Set(['sbp', 'glucose', 'tc', 'ldl', 'tg', 'bmi'].filter(id => avail.some(x => x.it.id === id)));
    const shown = avail.filter(x => state.sel.has(x.it.id));
    return `<div class="chips">${avail.map(x => `<span class="chip ${state.sel.has(x.it.id) ? 'on' : ''}" data-act="toggle" data-id="${esc(x.it.id)}">${esc(x.it.name)}</span>`).join('')}
      <span class="chip" data-act="selAll">전체</span><span class="chip" data-act="selNone">해제</span></div>
      ${shown.length ? `<div class="grid">${shown.map(({ it, ser }) => { const l = ser[ser.length - 1]; return `<div class="card"><div class="row"><h3 style="margin:0;cursor:pointer" data-act="detail" data-id="${esc(it.id)}">${esc(it.name)}</h3><span class="sp"></span>${badge(l.status)}</div><div class="muted small">${esc(refText(it))} (${esc(it.unit)})</div>${lineChart(ser, it, { compact: true })}<div>${dItem(it, ser)}</div></div>`; }).join('')}</div>` : '<p class="muted">위에서 보고 싶은 항목을 선택하세요.</p>'}`;
  },
  exams() {
    const list = examList(), Z = state.examTag, K = state.examKind;
    const ed = list.find(e => e.id === state.editExam) || { year: new Date().getFullYear(), tag: '정상' };
    const kinds = [...new Set(list.map(e => e.kind))];
    const form = `<details class="card" ${state.editExam || !list.length ? 'open' : ''}><summary><b>${state.editExam ? '검사 기록 수정' : '+ 검사 기록 추가'}</b></summary>
      <div class="flds" style="margin-top:10px">
        <label class="fld"><span>연도</span><input type="number" id="ex_year" value="${esc(ed.year)}"></label>
        <label class="fld"><span>검사일</span><input type="text" id="ex_date" value="${esc(ed.date || '')}" placeholder="2025-05-16"></label>
        <label class="fld"><span>병원·과</span><input type="text" id="ex_place" value="${esc(ed.place || '')}"></label>
        <label class="fld"><span>검사 종류</span><input type="text" id="ex_kind" list="kinds" value="${esc(ed.kind || '')}" placeholder="예) 갑상선 초음파"><datalist id="kinds">${kinds.map(k => `<option value="${esc(k)}">`).join('')}</datalist></label>
        <label class="fld"><span>상태</span><select id="ex_tag">${Object.keys(TAGS).map(t => `<option ${t === ed.tag ? 'selected' : ''}>${t}</option>`).join('')}</select></label>
        <label class="fld"><span>권장 추적 연도 <small>(선택)</small></span><input type="number" id="ex_due" value="${esc(ed.due || '')}" placeholder="예) 2027"></label>
      </div>
      <label class="fld"><span>결과 한 줄</span><input type="text" id="ex_result" value="${esc(ed.result || '')}" style="width:100%"></label>
      <label class="fld" style="display:block;margin-top:8px"><span>상세 소견·메모</span><textarea id="ex_note">${esc(ed.note || '')}</textarea></label>
      <div class="row" style="margin-top:10px"><button class="btn pri" data-act="saveExam">저장</button>${state.editExam ? '<button class="btn" data-act="cancelExam">취소</button><button class="btn del" data-act="delExam">삭제</button>' : ''}</div></details>`;
    if (!list.length) return form + '<div class="card empty">아직 검사 기록이 없어요. 위에서 추가하세요. 시트의 글 소견(내시경·초음파·MRI 결과, 의사 말씀, 다음 검사 계획)을 넣는 곳입니다.</div>';
    const ys = [...new Set(list.map(e => e.year))].sort((a, b) => a - b);
    const kindRows = kinds.map(k => ({ k, n: list.filter(e => e.kind === k).length })).sort((a, b) => b.n - a.n || a.k.localeCompare(b.k));
    const matrix = `<div class="card tw"><h3>검사 이력 <small class="muted">(종류를 누르면 아래에 모아 봅니다)</small></h3><table><thead><tr><th>검사</th>${ys.map(y => `<th>${y}</th>`).join('')}</tr></thead><tbody>${kindRows.map(({ k }) => `<tr class="link" data-act="filterKind" data-v="${esc(k)}"><td>${K === k ? '▶ ' : ''}${esc(k)}</td>${ys.map(y => {
      const es = list.filter(e => e.kind === k && e.year === y); if (!es.length) return '<td class="muted">·</td>';
      const e = es[es.length - 1]; return `<td class="${TAGS[e.tag] || ''}" title="${esc((e.result || '') + (es.length > 1 ? ` (+${es.length - 1}건)` : ''))}">${esc(e.tag)}</td>`;
    }).join('')}</tr>`).join('')}</tbody></table></div>`;
    const places = [...new Set(list.map(e => e.place).filter(Boolean))], PL = state.examPlace;
    const shown = list.filter(e => (!Z || e.tag === Z) && (!K || e.kind === K) && (!PL || e.place === PL));
    const byY = {}; shown.forEach(e => (byY[e.year] ||= []).push(e));
    const tl = Object.keys(byY).map(Number).sort((a, b) => b - a).map(y => `<div class="card"><h3>${y}년 <small class="muted">${byY[y].length}건</small></h3>${byY[y].map(e => examRow(e)).join('')}</div>`).join('');
    return `${form}${upHtml()}${matrix}
      <div class="chips"><span class="chip ${!Z ? 'on' : ''}" data-act="filterTag" data-v="">전체</span>${Object.keys(TAGS).map(t => `<span class="chip ${Z === t ? 'on' : ''}" data-act="filterTag" data-v="${t}">${t}</span>`).join('')}${places.map(pl => `<span class="chip ${PL === pl ? 'on' : ''}" data-act="filterPlace" data-v="${esc(pl)}">📍${esc(pl)}</span>`).join('')}${K ? `<span class="chip on" data-act="filterKind" data-v="${esc(K)}">${esc(K)} ✕</span>` : ''}</div>
      ${tl || '<p class="muted">조건에 맞는 기록이 없어요.</p>'}`;
  },
  guide() {
    const sym = SYMPTOMS.find(x => x.sym === state.gsym), cats = [...new Set(GUIDE.map(g => g.cat))];
    return `<div class="card"><h2>증상으로 검사 찾기</h2><p class="muted small">참고용 안내이며 진단이 아니에요. 증상이 심하거나 갑자기 생기면 검진을 기다리지 말고 바로 진료받으세요. 위 검색창에 ‘MRI’, ‘속쓰림’, ‘갑상선’처럼 입력해도 찾아줘요.</p>
      <div class="chips">${SYMPTOMS.map(x => `<span class="chip ${sym && sym.sym === x.sym ? 'on' : ''}" data-act="pickSym" data-v="${esc(x.sym)}">${esc(x.sym)}</span>`).join('')}</div></div>
      ${sym ? symCard(sym) : ''}
      <div class="card"><h2>MRI·MRA·CT, 뭐가 달라요?</h2>${TERMS.map(termCard).join('')}</div>
      <div class="card"><h2>검사 사전</h2>${cats.map(c => `<h3 class="gcat">${esc(c)}</h3>${GUIDE.filter(g => g.cat === c).map(g => guideCard(g)).join('')}`).join('')}</div>`;
  },
  family() {
    return S.profiles.map(p => {
      if (!keys[p.id]) return `<div class="card"><div class="row"><h3 style="margin:0">${esc(p.name)}</h3><span class="badge none">잠김</span><span class="sp"></span><button class="btn" data-act="pick" data-id="${esc(p.id)}">비밀번호 입력</button></div></div>`;
      return withProfile(p.id, () => {
        const ys = years(), up = upcoming(); let head = '';
        if (ys.length) {
          const Y = defaultYear(ys), c = { ok: 0, warn: 0, bad: 0 };
          items().forEach(it => { const pt = series(it).find(x => x.year === Y); if (pt && c[pt.status] != null) c[pt.status]++; });
          head = `<span class="muted small">${Y}년 검진</span><span class="badge ok">정상 ${c.ok}</span><span class="badge warn">주의 ${c.warn}</span><span class="badge bad">이상 ${c.bad}</span>`;
        }
        const rows = up.slice(0, 6).map(u => { const { lab, cls } = dueLabel(u); return `<div class="it" data-act="pick" data-id="${esc(p.id)}" data-go="exams"><div class="nm">${esc(u.kind)}<small>${esc((u.plan ? u.plan.result : u.last.result) || '')}</small></div><span class="badge ${cls}">${lab}</span></div>`; }).join('');
        return `<div class="card"><div class="row"><h3 style="margin:0">${esc(p.name)}</h3>${head}<span class="sp"></span><button class="btn small" data-act="pick" data-id="${esc(p.id)}" data-go="exams">검사 기록</button></div>${rows ? `<div class="list">${rows}</div>` : '<p class="muted small">받을 검사 알림이 없어요.</p>'}${up.length > 6 ? `<p class="muted small">외 ${up.length - 6}건</p>` : ''}</div>`;
      });
    }).join('') + '<p class="muted small">이 브라우저에서 비밀번호로 잠금을 푼 사람만 보여요. 각자의 기록은 따로 암호화되어 있어서, 서로의 비밀번호 없이 보는 공유는 지원하지 않아요.</p>';
  },
  detail() {
    const it = itemById(state.detail); if (!it) return '<p>항목을 찾을 수 없어요.</p>';
    const ser = series(it), back = `<button class="btn" data-act="back">← 돌아가기</button>`;
    if (!ser.length) return `${back}<div class="card empty">${esc(it.name)} 기록이 없어요.</div>`;
    const s = stats(it, ser), l = s.last, u = esc(it.unit);
    const cell = (k, v) => `<div><small>${k}</small><b>${v}</b></div>`;
    let msg = `${l.year}년 ${esc(it.name)} <b>${fv(it, l.value)} ${u}</b> — ${badge(l.status)}.`;
    if (s.prev) { const d = l.value - s.prev.value; msg += ` 전회(${s.prev.year}년) 대비 ${sgn(d, it)}${s.trend === 'better' ? ', 판정이 호전됐어요.' : s.trend === 'worse' ? ', 판정이 나빠졌어요.' : '.'}`; }
    if (s.slope != null) msg += ` 연평균 약 ${sgn(s.slope, it)} ${u} 씩 ${s.slope > 0 ? '오르는' : s.slope < 0 ? '내리는' : '유지되는'} 추세예요.`;
    return `${back}<div class="card" style="margin-top:12px"><div class="row"><h2 style="margin:0">${esc(it.name)}</h2><span class="muted">${u} · ${esc(it.cat)}</span><span class="sp"></span>${badge(l.status)}</div>
      <div class="muted small" style="margin:4px 0 8px">기준: ${esc(refText(it))}${it.n ? ` · <span style="color:var(--ok)">■</span> 정상 <span style="color:var(--warn)">■</span> 주의` : ''}</div>
      ${lineChart(ser, it)}<p>${msg}</p>
      <div class="stats">${cell('최근값', `${fv(it, l.value)} ${u}`)}${cell('직전 대비', s.prev ? sgn(l.value - s.prev.value, it) : '-')}${cell('최초 대비', ser.length > 1 ? sgn(l.value - s.first.value, it) : '-')}${cell('평균', fv(it, s.avg))}${cell('최저', `${fv(it, s.min.value)} (${s.min.year})`)}${cell('최고', `${fv(it, s.max.value)} (${s.max.year})`)}${cell('연간 추세', s.slope != null ? sgn(s.slope, it) : '3회 이상 필요')}${cell('기록 수', s.n + '회')}</div>
      <div class="tw"><table><thead><tr><th>연도</th><th>검진일</th><th>값</th><th>판정</th></tr></thead><tbody>${ser.slice().reverse().map(p => `<tr><td>${p.year}</td><td>${esc(p.date || '-')}</td><td>${fv(it, p.value)} ${u}</td><td>${badge(p.status)}</td></tr>`).join('')}</tbody></table></div></div>`;
  },
  search() {
    const q = state.q.trim(), nq = norm(q);
    let h = '';
    if (/^\d{4}$/.test(q) && pdata().records[q]) {
      const list = items().map(it => ({ it, p: series(it).find(p => p.year === +q) })).filter(x => x.p);
      const exy = examList().filter(e => e.year === +q);
      return `<div class="card"><h2>${q}년 검진 결과 (${list.length}개 항목)</h2><div class="list">${list.map(({ it, p }) => `<div class="it" data-act="detail" data-id="${esc(it.id)}"><div class="nm">${esc(it.name)}<small>${esc(it.cat)}</small></div><div class="val">${fv(it, p.value)} <small class="muted">${esc(it.unit)}</small> ${badge(p.status)}</div></div>`).join('')}</div></div>${exy.length ? `<div class="card"><h2>${q}년 검사 기록 (${exy.length}건)</h2>${exy.map(e => examRow(e)).join('')}</div>` : ''}`;
    }
    if (/^\d{4}$/.test(q) && examList().some(e => e.year === +q)) {
      const exy = examList().filter(e => e.year === +q);
      return `<div class="card"><h2>${q}년 검사 기록 (${exy.length}건)</h2>${exy.map(e => examRow(e)).join('')}</div>`;
    }
    if (LABEL.ok === q || LABEL.warn === q || LABEL.bad === q) {
      const st = Object.keys(LABEL).find(k => LABEL[k] === q);
      const list = items().map(it => ({ it, ser: series(it) })).filter(x => x.ser.length && x.ser[x.ser.length - 1].status === st);
      return `<div class="card"><h2>최근 결과가 ‘${q}’인 항목 (${list.length})</h2>${list.length ? `<div class="list">${list.map(x => rowHtml(x.it, x.ser)).join('')}</div>` : '<p class="muted">해당 항목이 없어요.</p>'}</div>`;
    }
    const res = items().map(it => ({ it, sc: matchScore(it, q) })).filter(x => x.sc).sort((a, b) => b.sc - a.sc);
    const exm = examList().filter(e => norm([e.kind, e.result, e.note, e.place, e.tag].join(' ')).includes(nq)).sort((a, b) => b.year - a.year || (b.date || '').localeCompare(a.date || ''));
    const gm = GUIDE.filter(g => norm([g.kind, ...g.aliases].join(' ')).includes(nq) || (nq.length >= 2 && norm(g.what + g.good).includes(nq))).slice(0, 8);
    const tm = TERMS.filter(t => norm(t.name).includes(nq));
    const sm = SYMPTOMS.filter(x => norm(x.sym).includes(nq) || x.keys.some(k => norm(k).includes(nq) || (norm(k).length > 1 && nq.includes(norm(k))))).slice(0, 3);
    if (!res.length && !exm.length && !gm.length && !tm.length && !sm.length) return `<div class="card empty">‘${esc(q)}’에 해당하는 검사를 찾지 못했어요.<br><span class="small">예: 콜레스테롤, 혈압, 간, 신장, 빈혈, 갑상선, 내시경, ㅎㅅㅅ(초성)</span></div>`;
    const withData = res.map(r => ({ ...r, ser: series(r.it) }));
    h = `<p class="muted">‘${esc(q)}’ 검색 결과 — 검사 안내 ${gm.length + tm.length}건 · 내 검사 기록 ${exm.length}건 · 수치 항목 ${res.length}건</p>`;
    if (tm.length) h += `<div class="card"><h3>용어 설명</h3>${tm.map(termCard).join('')}</div>`;
    h += sm.map(symCard).join('');
    if (gm.length) h += `<div class="card"><h3>검사 안내 (${gm.length})</h3>${gm.map(g => guideCard(g, gm.length <= 2)).join('')}</div>`;
    if (exm.length) h += `<div class="card"><h3>검사 기록 (${exm.length})</h3>${exm.slice(0, 40).map(e => examRow(e, true)).join('')}${exm.length > 40 ? '<p class="muted small">상위 40건만 표시했어요. 검색어를 더 좁혀 보세요.</p>' : ''}</div>`;
    h += '<div class="grid">';
    for (const { it, ser } of withData) {
      if (!ser.length) { h += `<div class="card" style="opacity:.6"><h3>${esc(it.name)}</h3><div class="muted small">${esc(refText(it))}</div><p class="muted">기록 없음</p></div>`; continue; }
      const s = stats(it, ser), l = s.last;
      h += `<div class="card"><div class="row"><h3 style="margin:0;cursor:pointer" data-act="detail" data-id="${esc(it.id)}">${esc(it.name)}</h3><span class="sp"></span>${badge(l.status)}</div>
        <div class="muted small">${esc(refText(it))} (${esc(it.unit)})</div>${lineChart(ser, it, { compact: true })}
        <div class="row"><span class="val">${fv(it, l.value)} ${esc(it.unit)}</span>${dItem(it, ser)}</div>
        <div class="muted small" style="margin-top:4px">평균 ${fv(it, s.avg)} · 최저 ${fv(it, s.min.value)}(${s.min.year}) · 최고 ${fv(it, s.max.value)}(${s.max.year}) · ${s.n}회</div></div>`;
    }
    return h + '</div>';
  },
  input() {
    const ys = years(); if (!state.inYear) state.inYear = ys.length ? ys[ys.length - 1] : new Date().getFullYear();
    const Y = state.inYear, rec = pdata().records[Y] || { values: {} };
    const cats = [...new Set(items().map(i => i.cat))].sort((a, b) => CAT_ORDER.indexOf(a) - CAT_ORDER.indexOf(b));
    return `<div class="card"><div class="row"><h2 style="margin:0">검진 결과 입력</h2><span class="sp"></span>
        <label>연도 <input type="number" id="inY" value="${Y}" min="1990" max="2100" style="width:90px"></label>
        <label>검진일 <input type="text" id="inD" value="${esc(rec.date || '')}" placeholder="2025-05-20" style="width:120px"></label></div>
      ${ys.length ? `<div class="chips" style="margin:10px 0 0">${ys.map(y => `<span class="chip ${y === Y ? 'on' : ''}" data-act="loadYear" data-y="${y}">${y}</span>`).join('')}</div>` : ''}</div>
      <div class="card"><h3>붙여넣기 일괄 입력 <small class="muted">(선택)</small></h3>
        <textarea id="bulk" placeholder="결과지 내용을 한 줄에 하나씩 붙여넣으세요. 예)&#10;공복혈당 98&#10;혈압 124/82&#10;LDL 콜레스테롤 131&#10;AST 25"></textarea>
        <div style="margin-top:8px"><button class="btn" data-act="bulk">아래 칸에 채우기</button></div></div>
      <div class="card">${cats.map(c => `<fieldset><legend>${esc(c)}</legend><div class="flds">${items().filter(i => i.cat === c).map(it => {
        const v = rec.values[it.id]; const n = pick(it.n, prof().sex);
        return `<label class="fld"><span>${esc(it.name)} <small>${esc(it.unit)}${n ? ' · ' + esc(rangeText(n)) : ''}</small></span><input class="vin" type="number" step="any" data-id="${esc(it.id)}" value="${v ?? ''}" ${it.id === 'bmi' ? 'placeholder="신장·체중으로 자동 계산"' : ''} data-st="${v != null && v !== '' ? statusOf(it, +v) : ''}"></label>`;
      }).join('')}</div></fieldset>`).join('')}
        <div class="row"><button class="btn pri" data-act="saveYear">${Y}년 저장</button>${pdata().records[Y] ? `<button class="btn del" data-act="delYear">${Y}년 삭제</button>` : ''}</div></div>`;
  },
  data() {
    const p = prof(), cu = pdata().custom || [];
    return `<div class="card"><h3>사람(계정)</h3><p class="muted small">각 사람의 기록은 비밀번호로 <b>암호화되어 서버에 저장</b>됩니다. 성별에 따라 일부 기준치(γ-GTP, 혈색소, 허리둘레, 요산)가 달라집니다.</p>
      <div class="row"><b>${esc(p.name)}</b><select id="ps"><option value="M" ${p.sex === 'M' ? 'selected' : ''}>남성</option><option value="F" ${p.sex === 'F' ? 'selected' : ''}>여성</option></select>
      <button class="btn" data-act="saveProf">성별 저장</button><span class="sp"></span><button class="btn" data-act="addProf">+ 이름 추가</button><button class="btn del" data-act="delProf">목록에서 빼기</button></div></div>
    <div class="card"><h3>비밀번호 변경 — ${esc(p.name)}</h3>
      <p class="muted small">비밀번호는 서버에 저장되지 않고, 이 비밀번호로 기록이 암호화됩니다. <b>잊으면 복구할 수 없어요.</b> 숫자 몇 자리는 추측되기 쉬우니 민감한 기록은 더 긴 비밀번호를 권장합니다.</p>
      <div class="row"><input type="password" id="lp1" placeholder="새 비밀번호" autocomplete="new-password" style="width:150px"><input type="password" id="lp2" placeholder="한 번 더" autocomplete="new-password" style="width:150px"><button class="btn" data-act="changePw">비밀번호 변경</button><span class="sp"></span><button class="btn" data-act="relock">지금 잠그기</button></div></div>
    ${legacyProfiles().length ? `<div class="card"><h3>이 브라우저에 남아 있는 예전 기록</h3><p class="muted small">서버 저장 방식으로 바꾸기 전에 이 브라우저에만 저장돼 있던 기록이에요. 현재 사람(${esc(p.name)})의 서버 기록으로 옮길 수 있어요.</p>
      <div class="row">${legacyProfiles().map(x => `<button class="btn" data-act="legacy" data-id="${esc(x.id)}">‘${esc(x.name)}’ 기록 옮기기</button>`).join('')}<span class="sp"></span><button class="btn del" data-act="legacyDel">예전 기록 삭제</button></div></div>` : ''}
    <div class="card"><h3>사용자 항목 추가</h3><p class="muted small">카탈로그에 없는 검사(예: 비타민D, PSA)를 직접 추가합니다.</p>
      <div class="row"><input type="text" id="cn" placeholder="항목명" style="width:150px"><input type="text" id="cu" placeholder="단위" style="width:90px"><input type="number" step="any" id="cmin" placeholder="정상 하한" style="width:100px"><input type="number" step="any" id="cmax" placeholder="정상 상한" style="width:100px"><button class="btn" data-act="addCustom">추가</button></div>
      ${cu.length ? `<div class="chips" style="margin-top:10px">${cu.map(c => `<span class="chip">${esc(c.name)} <span data-act="delCustom" data-id="${esc(c.id)}" title="삭제">✕</span></span>`).join('')}</div>` : ''}</div>
    <div class="card"><h3>백업·이전</h3><p class="muted small">기록은 서버에 암호화되어 저장됩니다. 내보내기 파일은 <b>암호화되지 않은 평문</b>이니 보관에 주의하세요.</p>
      <div class="row"><button class="btn" data-act="exportJson">내 기록 JSON 내보내기(평문)</button><button class="btn" data-act="exportCsv">CSV 내보내기</button><button class="btn" data-act="importJson">JSON 가져오기</button><span class="sp"></span><button class="btn" data-act="sample">샘플 데이터 넣기</button><button class="btn del" data-act="wipe">이 사람 기록 전체 삭제</button></div></div>`;
  },
};

/* ---------- 렌더 ---------- */
function render() {
  $('#prof').innerHTML = S.profiles.map(p => `<option value="${p.id}" ${p.id === S.current ? 'selected' : ''}>${esc(p.name)}</option>`).join('');
  $('#tabs').innerHTML = TABS.filter(([k]) => k !== 'family' || S.profiles.length > 1).map(([k, n]) => `<button data-tab="${k}" class="${state.view === k || (state.view === 'detail' && state.from === k) ? 'on' : ''}">${n}</button>`).join('');
  $('#lockbtn').hidden = isLocked();
  const gate = isLocked() && !['guide', 'search'].includes(state.view); // 가이드·검색은 로그인 없이도 볼 수 있음
  $('#main').innerHTML = gate ? lockHtml() : views[state.view]();
  if (gate && S.acct[prof().id] === undefined) loadAcct();
  const pw = $('#pw') || $('#pw1'); if (pw && document.activeElement !== $('#q')) pw.focus();
}
const isLocked = () => !keys[prof().id];
function lockHtml() {
  const p = prof(), st = S.acct[p.id];
  let body;
  if (st === 'unclaimed') body = `<p class="muted small">처음 사용하는 이름이에요. 이 사람의 비밀번호를 정하세요. 기록은 이 비밀번호로 암호화되어 서버에 저장되고, <b>잊으면 복구할 수 없어요.</b></p><input type="password" id="pw1" placeholder="새 비밀번호 (4자 이상)" autocomplete="new-password" style="width:100%;text-align:center;margin:6px 0"><input type="password" id="pw2" placeholder="한 번 더" autocomplete="new-password" style="width:100%;text-align:center;margin:6px 0"><button class="btn pri" style="width:100%" data-act="claim">비밀번호 정하고 시작</button>`;
  else if (st === 'error') body = `<p class="muted">서버에 연결하지 못했어요.</p><button class="btn" data-act="retryAcct">다시 시도</button>`;
  else if (st === 'claimed') body = `<p class="muted small">비밀번호를 입력하면 서버에 저장된 기록을 불러옵니다.</p><input type="password" id="pw" inputmode="numeric" autocomplete="off" placeholder="비밀번호" style="width:100%;text-align:center;font-size:18px;margin:8px 0"><button class="btn pri" style="width:100%" data-act="unlock">열기</button>`;
  else body = '<p class="muted">서버 확인 중…</p>';
  return `<div class="card empty" style="max-width:380px;margin:40px auto"><div style="font-size:40px">🔒</div><h2 style="margin:6px 0">‘${esc(p.name)}’</h2>${body}<p style="margin-top:18px"><a href="#" class="muted small" data-act="delLocked">이 이름을 목록에서 빼기</a></p></div>`;
}
async function loadAcct() {
  const id = prof().id;
  try { const r = await api('GET', '/api/salt?name=' + encodeURIComponent(id)); S.acct[id] = r.unclaimed ? 'unclaimed' : 'claimed'; }
  catch (e) { S.acct[id] = 'error'; }
  if (prof().id === id) render();
}
function go(view, extra = {}) { Object.assign(state, extra); state.view = view; if (view !== 'search') { state.q = ''; $('#q').value = ''; } render(); window.scrollTo(0, 0); }

/* ---------- 이벤트 ---------- */
$('#tabs').addEventListener('click', e => { const b = e.target.closest('[data-tab]'); if (b) { if (b.dataset.tab === 'input') state.inYear = null; go(b.dataset.tab); } });
$('#prof').addEventListener('change', e => { S.current = e.target.value; state.sel = null; state.inYear = null; state.examKind = ''; state.examTag = ''; saveLocal(); render(); });
$('#q').addEventListener('input', e => {
  state.q = e.target.value;
  if (state.q.trim()) { if (state.view !== 'search') state.from = state.view === 'detail' ? state.from : state.view; state.view = 'search'; }
  else if (state.view === 'search') state.view = state.from || 'summary';
  render();
});

function collectValues() {
  const values = {};
  document.querySelectorAll('.vin').forEach(i => { if (i.value !== '' && !isNaN(+i.value)) values[i.dataset.id] = +i.value; });
  return values;
}
function bulkParse(text) {
  const toks = [];
  items().forEach((it, idx) => [it.name, ...it.alias].forEach(t => { const n = norm(t); if (n.length >= 2 || /^[a-z]/.test(n)) toks.push({ n, it, idx }); }));
  toks.sort((a, b) => b.n.length - a.n.length || a.idx - b.idx);
  const out = {}; let miss = 0;
  for (const line of text.split(/\n/)) {
    const nl = norm(line); if (!nl) continue;
    const bp = line.match(/(\d{2,3})\s*[\/\\]\s*(\d{2,3})/);
    if (bp && /혈압|bp/.test(nl)) { out.sbp = +bp[1]; out.dbp = +bp[2]; continue; }
    const t = toks.find(t => nl.includes(t.n));
    if (!t) { miss++; continue; }
    const rest = nl.slice(nl.indexOf(t.n) + t.n.length), m = rest.match(/\d+(\.\d+)?/);
    if (m) out[t.it.id] = +m[0]; else miss++;
  }
  return { out, miss };
}
function download(name, text, type) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }

const actions = {
  detail(t) { go('detail', { detail: t.dataset.id, from: state.view === 'search' ? (state.from || 'summary') : state.view === 'detail' ? state.from : state.view }); },
  back() { go(state.from || 'summary'); },
  goInput() { go('input'); },
  toggle(t) { const id = t.dataset.id; state.sel.has(id) ? state.sel.delete(id) : state.sel.add(id); render(); },
  selAll() { state.sel = new Set(items().filter(i => series(i).length).map(i => i.id)); render(); },
  selNone() { state.sel = new Set(); render(); },
  loadYear(t) { state.inYear = +t.dataset.y; render(); },
  saveYear() {
    const Y = +$('#inY').value; if (!Y) return toast('연도를 입력하세요');
    const values = collectValues(); if (!Object.keys(values).length) return toast('입력된 값이 없어요');
    pdata().records[Y] = { date: $('#inD').value.trim(), values }; state.inYear = Y; save(); render(); toast(`${Y}년 결과를 저장했어요`);
  },
  delYear() { const Y = state.inYear; if (confirm(`${Y}년 기록을 삭제할까요?`)) { delete pdata().records[Y]; state.inYear = null; save(); render(); } },
  bulk() {
    const { out, miss } = bulkParse($('#bulk').value); const keys = Object.keys(out);
    if (!keys.length) return toast('인식된 항목이 없어요');
    keys.forEach(k => { const i = document.querySelector(`.vin[data-id="${k}"]`); if (i) { i.value = out[k]; i.dispatchEvent(new Event('input', { bubbles: true })); } });
    toast(`${keys.length}개 항목을 채웠어요${miss ? ` (인식 못한 줄 ${miss})` : ''} — 확인 후 저장하세요`);
  },
  goExams(t, e) { go('exams'); },
  filterTag(t) { state.examTag = t.dataset.v; render(); },
  filterPlace(t) { state.examPlace = state.examPlace === t.dataset.v ? '' : t.dataset.v; render(); },
  pickSym(t) { state.gsym = state.gsym === t.dataset.v ? '' : t.dataset.v; render(); },
  pick(t) { S.current = t.dataset.id; state.sel = null; state.inYear = null; saveLocal(); go(keys[S.current] ? (t.dataset.go || 'summary') : 'summary'); },
  filterKind(t) { const v = t.dataset.v; go('exams', { examKind: state.view === 'exams' && state.examKind === v ? '' : v }); },
  editExam(t) { go('exams', { editExam: t.dataset.id }); },
  cancelExam() { state.editExam = null; render(); },
  saveExam() {
    const g = id => $(id).value.trim(), year = +g('#ex_year'), kind = g('#ex_kind');
    if (!year || !kind) return toast('연도와 검사 종류는 꼭 입력하세요');
    const rec = { year, date: g('#ex_date'), place: g('#ex_place'), kind, tag: g('#ex_tag'), result: g('#ex_result'), due: g('#ex_due') ? +g('#ex_due') : null, note: g('#ex_note') };
    let inferred = false;
    if (!rec.due) { const d = inferDue(year, rec.result + ' ' + rec.note); if (d) { rec.due = d; inferred = true; } }
    const list = examList(), ex = list.find(e => e.id === state.editExam);
    if (ex) Object.assign(ex, rec); else list.push({ id: 'e' + uid(), ...rec });
    state.editExam = null; save(); render(); toast(inferred ? `저장했어요. 문구를 보고 권장 추적 연도를 ${rec.due}년으로 잡았어요` : '검사 기록을 저장했어요');
  },
  delExam() { if (confirm('이 검사 기록을 삭제할까요?')) { pdata().exams = examList().filter(e => e.id !== state.editExam); state.editExam = null; save(); render(); } },
  sample() {
    if (hasData() && !confirm('현재 사람의 기존 기록에 샘플 데이터를 덮어씁니다. 계속할까요?')) return;
    const recs = {}; SAMPLE_YEARS.forEach((y, i) => { const values = {}; for (const k in SAMPLE) if (SAMPLE[k][i] != null) values[k] = SAMPLE[k][i]; recs[y] = { date: `${y}-05-20`, values }; });
    pdata().records = recs; state.sel = null; state.inYear = null; save(); go('summary'); toast('샘플 데이터를 불러왔어요');
  },
  saveProf() { prof().sex = $('#ps').value; save(); render(); toast('저장했어요'); },
  addProf() {
    const name = (prompt('추가할 이름(서버에 이미 만들어 둔 계정 이름)') || '').trim(); if (!name) return;
    if (!S.profiles.some(p => p.id === name)) S.profiles.push({ id: name, name });
    S.current = name; state.sel = null; state.inYear = null; saveLocal(); render();
  },
  delProf() {
    if (S.profiles.length < 2) return toast('마지막 한 명은 목록에서 뺄 수 없어요');
    if (!confirm(`‘${prof().name}’을(를) 이 브라우저의 목록에서 뺄까요? (서버에 저장된 기록은 지워지지 않아요)`)) return;
    const id = prof().id; S.profiles = S.profiles.filter(p => p.id !== id); delete S.data[id]; delete keys[id]; delete S.acct[id];
    S.current = S.profiles[0].id; state.sel = null; saveLocal(); render();
  },
  delLocked(t, e) { e && e.preventDefault(); actions.delProf(); },
  retryAcct() { S.acct[prof().id] = undefined; render(); },
  async unlock() {
    const p = prof(), pw = ($('#pw') || {}).value; if (!pw) return;
    toast('확인 중…');
    try {
      const s = await api('GET', '/api/salt?name=' + encodeURIComponent(p.id));
      const token = await makeToken(pw, s.authSalt);
      const r = await api('POST', '/api/login', { name: p.id, token });
      const blob = JSON.parse(r.blob), salt = b64d(blob.s), iter = blob.n || ITER;
      const key = await deriveKey(pw, salt, iter), data = await decData(key, blob);
      keys[p.id] = { key, salt, iter, token, version: r.version, authSalt: s.authSalt };
      S.data[p.id] = data; p.sex = data.sex || 'M'; state.sel = null; state.inYear = null; state.sumYear = null;
      setSync('☁ 서버와 연결됨', 'ok'); render(); toast('불러왔어요');
    } catch (e) {
      if (e.status === 429) toast(`시도가 너무 많아요. ${e.data.retry}초 뒤에 다시 해보세요`);
      else if (e.status === 0) toast('서버에 연결할 수 없어요');
      else { await new Promise(r => setTimeout(r, 600)); toast('비밀번호가 맞지 않아요'); }
      const el = $('#pw'); if (el) { el.value = ''; el.focus(); }
    }
  },
  async claim() {
    const p = prof(), a = $('#pw1').value, b = $('#pw2').value;
    if (a.length < 4) return toast('비밀번호는 4자 이상으로 하세요');
    if (a !== b) return toast('두 비밀번호가 달라요');
    toast('만드는 중…');
    try {
      const authSalt = b64e(rand(16)), token = await makeToken(a, authSalt), salt = rand(16);
      const k = { key: await deriveKey(a, salt, ITER), salt, iter: ITER, token, version: 0, authSalt };
      const data = { records: {}, custom: [], exams: [], sex: 'M' };
      const r = await api('POST', '/api/claim', { name: p.id, token, authSalt, blob: JSON.stringify(await encData(k, data)) });
      k.version = r.version; keys[p.id] = k; S.data[p.id] = data; S.acct[p.id] = 'claimed'; p.sex = 'M'; setSync('☁ 저장됨', 'ok'); render(); toast('비밀번호를 정했어요');
    } catch (e) { toast(e.status === 409 ? '이미 다른 사람이 비밀번호를 정한 이름이에요' : '실패: ' + e.message); S.acct[p.id] = undefined; render(); }
  },
  async relock() {
    const id = prof().id; await persist();
    if (dirty.has(id) && !confirm('서버에 저장되지 않은 변경이 있어요. 그래도 잠글까요?')) return;
    delete keys[id]; delete S.data[id]; dirty.delete(id); state.view = 'summary'; render(); toast('잠갔어요');
  },
  async changePw() {
    const p = prof(), k = keys[p.id], a = $('#lp1').value, b = $('#lp2').value;
    if (a.length < 4) return toast('비밀번호는 4자 이상으로 하세요');
    if (a !== b) return toast('두 비밀번호가 달라요');
    if (!confirm('비밀번호를 바꿉니다. 새 비밀번호를 잊으면 복구할 수 없어요. 계속할까요?')) return;
    try {
      await persist();
      const authSalt = b64e(rand(16)), token = await makeToken(a, authSalt), salt = rand(16);
      const nk = { key: await deriveKey(a, salt, ITER), salt, iter: ITER, token, version: k.version, authSalt };
      S.data[p.id].sex = p.sex;
      const r = await api('POST', '/api/password', { name: p.id, token: k.token, newToken: token, newAuthSalt: authSalt, blob: JSON.stringify(await encData(nk, S.data[p.id])), version: k.version });
      nk.version = r.version; keys[p.id] = nk; render(); toast('비밀번호를 바꿨어요');
    } catch (e) { toast('변경 실패: ' + e.message); }
  },
  legacy(t) {
    const src = legacyProfiles().find(x => x.id === t.dataset.id); if (!src) return;
    const d = pdata(), had = Object.keys(d.records || {}).length + (d.exams || []).length;
    if (had && !confirm(`현재 ‘${prof().name}’에 이미 기록이 있어요. 예전 기록으로 덮어쓸까요?`)) return;
    S.data[prof().id] = { records: src.data.records || {}, custom: src.data.custom || [], exams: src.data.exams || [] };
    save(); go('summary'); toast('서버로 옮겼어요. 아래 ‘예전 기록 삭제’로 이 브라우저의 사본을 지우세요');
  },
  legacyDel() { if (confirm('이 브라우저에 남은 예전(서버 이전) 기록을 지울까요? 서버로 옮긴 기록은 그대로예요.')) { try { localStorage.removeItem(OLD_KEY); } catch (e) {} render(); } },
  addCustom() {
    const name = $('#cn').value.trim(); if (!name) return toast('항목명을 입력하세요');
    const num = id => { const v = $(id).value; return v === '' ? null : +v; };
    pdata().custom.push({ id: 'c_' + uid(), name, unit: $('#cu').value.trim(), min: num('#cmin'), max: num('#cmax') }); save(); render(); toast('추가했어요. 입력 탭에서 값을 넣으세요');
  },
  delCustom(t) { if (confirm('이 사용자 항목과 입력된 값을 삭제할까요?')) { const id = t.dataset.id; pdata().custom = pdata().custom.filter(c => c.id !== id); for (const y in pdata().records) delete pdata().records[y].values[id]; save(); render(); } },
  exportJson() { download(`healthtrack-${prof().name}-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify({ format: 'healthtrack-profile', name: prof().name, sex: prof().sex, data: pdata() }, null, 1), 'application/json'); },
  exportCsv() {
    const ys = years(); const rows = [['항목', '단위', ...ys]];
    items().forEach(it => { const ser = series(it); if (ser.length) rows.push([it.name, it.unit, ...ys.map(y => { const p = ser.find(p => p.year === y); return p ? fv(it, p.value) : ''; })]); });
    download(`healthtrack-${prof().name}.csv`, '﻿' + rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n'), 'text/csv');
  },
  importJson() { $('#file').click(); },
  wipe() { if (confirm(`‘${prof().name}’의 기록을 모두 지웁니다(서버에 저장된 것도 지워져요). 되돌릴 수 없어요. 계속할까요?`)) { S.data[prof().id] = { records: {}, custom: [], exams: [] }; state.sel = null; state.inYear = null; save(); go('summary'); } },
};
$('#main').addEventListener('click', e => { const t = e.target.closest('[data-act]'); if (t && actions[t.dataset.act]) { if (t.tagName === 'A') e.preventDefault(); actions[t.dataset.act](t, e); } });
$('#main').addEventListener('keydown', e => { if (e.key !== 'Enter') return; if (e.target.id === 'pw') actions.unlock(); else if (e.target.id === 'pw2') actions.claim(); });
$('#lockbtn').addEventListener('click', () => actions.relock());
$('#main').addEventListener('change', e => {
  if (e.target.dataset.chg === 'sumYear') { state.sumYear = +e.target.value; render(); }
  else if (e.target.id === 'inY') { const y = +e.target.value; if (y && pdata().records[y]) { state.inYear = y; render(); } else state.inYear = y; }
});
$('#main').addEventListener('input', e => {
  if (e.target.classList.contains('vin')) { const it = itemById(e.target.dataset.id); e.target.dataset.st = e.target.value === '' ? '' : statusOf(it, +e.target.value); }
});
function legacyProfiles() {
  try {
    const r = JSON.parse(localStorage.getItem(OLD_KEY)); if (!r || !r.profiles || !r.data) return [];
    return r.profiles.filter(p => !p.locked && r.data[p.id] && (Object.keys(r.data[p.id].records || {}).length || (r.data[p.id].exams || []).length)).map(p => ({ id: p.id, name: p.name, data: r.data[p.id] }));
  } catch (e) { return []; }
}
$('#file').addEventListener('change', async e => {
  const f = e.target.files[0]; e.target.value = ''; if (!f) return;
  try {
    const r = JSON.parse(await f.text()); let d = null;
    if (r.format === 'healthtrack-profile') d = r.data;
    else if (r.records || r.exams) d = r;
    else if (r.profiles && r.data) { const q = r.profiles.find(x => x.name === prof().name) || r.profiles[0]; if (q.locked) { toast('암호화된 예전 백업 파일은 가져올 수 없어요'); return; } d = r.data[q.id]; }
    if (!d || typeof (d.records || {}) !== 'object') throw 0;
    if (!confirm(`‘${prof().name}’의 기록을 파일 내용으로 바꿉니다. 계속할까요?`)) return;
    S.data[prof().id] = { records: d.records || {}, custom: d.custom || [], exams: d.exams || [] };
    state.sel = null; state.inYear = null; state.examKind = ''; state.examTag = ''; save(); go('summary'); toast('가져왔어요');
  } catch (err) { toast('올바른 HealthTrack 기록 파일이 아니에요'); }
});

render();
})();
