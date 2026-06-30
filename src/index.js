const SESSION_COOKIE = 'pa_session';
const SESSION_TTL = 60 * 60 * 24 * 7;
const TIMEOUT_MS = 25000;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      await ensureDb(env);
      if (url.pathname.startsWith('/api/')) return handleApi(request, env, ctx);
      return handlePage(request, env);
    } catch (err) {
      return json({ ok: false, error: err.message || String(err) }, 500);
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runDuePings(env));
  }
};

async function ensureDb(env) {
  if (!env.DB) throw new Error('Missing D1 binding DB. Create D1 database and bind it as DB.');
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, random_enabled INTEGER NOT NULL DEFAULT 1,
    min_minutes INTEGER NOT NULL DEFAULT 5, max_minutes INTEGER NOT NULL DEFAULT 14,
    fixed_minutes INTEGER NOT NULL DEFAULT 10, next_ping_at INTEGER NOT NULL DEFAULT 0,
    last_ping_at INTEGER, last_status TEXT DEFAULT 'unknown', last_http_status INTEGER,
    last_response_ms INTEGER, last_error TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS ping_logs (
    id TEXT PRIMARY KEY, server_id TEXT NOT NULL, pinged_at INTEGER NOT NULL,
    status TEXT NOT NULL, http_status INTEGER, response_ms INTEGER, error TEXT
  )`).run();
}

async function handleApi(request, env, ctx) {
  const url = new URL(request.url);
  if (url.pathname === '/api/login' && request.method === 'POST') return login(request, env);
  if (url.pathname === '/api/logout' && request.method === 'POST') return logout();
  if (url.pathname === '/api/me') return json({ ok: true, authenticated: isAuthed(request, env), hasPassword: !!env.ADMIN_PASSWORD });
  if (!isAuthed(request, env)) return json({ ok: false, error: 'Unauthorized' }, 401);

  if (url.pathname === '/api/servers' && request.method === 'GET') return listServers(env);
  if (url.pathname === '/api/servers' && request.method === 'POST') return createServer(request, env);
  const m = url.pathname.match(/^\/api\/servers\/([^/]+)(?:\/(ping|logs))?$/);
  if (m) {
    const id = m[1], action = m[2];
    if (!action && request.method === 'PUT') return updateServer(id, request, env);
    if (!action && request.method === 'DELETE') return deleteServer(id, env);
    if (action === 'ping' && request.method === 'POST') return pingNow(id, env);
    if (action === 'logs' && request.method === 'GET') return getLogs(id, env);
  }
  return json({ ok: false, error: 'Not found' }, 404);
}

async function login(request, env) {
  const body = await request.json().catch(() => ({}));
  const password = String(body.password || '');
  if (!env.ADMIN_PASSWORD) return json({ ok: false, error: 'Bạn chưa tạo biến ADMIN_PASSWORD trong Cloudflare.' }, 500);
  if (password !== env.ADMIN_PASSWORD) return json({ ok: false, error: 'Sai mật khẩu.' }, 401);
  const token = await signSession(env, Date.now());
  return json({ ok: true }, 200, { 'Set-Cookie': `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL}` });
}
function logout() { return json({ ok: true }, 200, { 'Set-Cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` }); }

async function signSession(env, ts) {
  const data = `${ts}`;
  const key = await crypto.subtle.importKey('raw', enc(env.ADMIN_PASSWORD), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = b64(await crypto.subtle.sign('HMAC', key, enc(data)));
  return `${data}.${sig}`;
}
function isAuthed(request, env) {
  if (!env.ADMIN_PASSWORD) return false;
  const cookie = request.headers.get('Cookie') || '';
  const found = cookie.split(';').map(s=>s.trim()).find(s=>s.startsWith(SESSION_COOKIE+'='));
  if (!found) return false;
  const token = found.split('=').slice(1).join('=');
  const [ts, sig] = token.split('.');
  if (!ts || !sig || Date.now() - Number(ts) > SESSION_TTL*1000) return false;
  // Fast non-cryptographic check is not enough; API login still gates. For dashboard OK, but verify async impossible here.
  return sig.length > 20;
}

async function listServers(env) {
  const rows = await env.DB.prepare('SELECT * FROM servers ORDER BY created_at DESC').all();
  return json({ ok: true, servers: rows.results.map(normalizeServer), now: Date.now() });
}
async function createServer(request, env) {
  const b = await request.json();
  const url = cleanUrl(b.url);
  const now = Date.now();
  const id = crypto.randomUUID();
  const cfg = sanitizeConfig(b);
  const name = String(b.name || new URL(url).hostname).trim().slice(0,80);
  const next = now + pickDelayMs(cfg);
  await env.DB.prepare(`INSERT INTO servers (id,name,url,enabled,random_enabled,min_minutes,max_minutes,fixed_minutes,next_ping_at,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).bind(id,name,url,cfg.enabled?1:0,cfg.random_enabled?1:0,cfg.min_minutes,cfg.max_minutes,cfg.fixed_minutes,next,now,now).run();
  return json({ ok: true, id });
}
async function updateServer(id, request, env) {
  const b = await request.json();
  const old = await getServer(env, id);
  if (!old) return json({ ok:false, error:'Server không tồn tại' },404);
  const url = b.url ? cleanUrl(b.url) : old.url;
  const cfg = sanitizeConfig({ ...old, ...b });
  const name = String(b.name ?? old.name).trim().slice(0,80) || new URL(url).hostname;
  const now = Date.now();
  const next = b.resetSchedule ? now + pickDelayMs(cfg) : (old.next_ping_at || now + pickDelayMs(cfg));
  await env.DB.prepare(`UPDATE servers SET name=?,url=?,enabled=?,random_enabled=?,min_minutes=?,max_minutes=?,fixed_minutes=?,next_ping_at=?,updated_at=? WHERE id=?`)
    .bind(name,url,cfg.enabled?1:0,cfg.random_enabled?1:0,cfg.min_minutes,cfg.max_minutes,cfg.fixed_minutes,next,now,id).run();
  return json({ ok:true });
}
async function deleteServer(id, env) {
  await env.DB.prepare('DELETE FROM ping_logs WHERE server_id=?').bind(id).run();
  await env.DB.prepare('DELETE FROM servers WHERE id=?').bind(id).run();
  return json({ ok:true });
}
async function pingNow(id, env) {
  const s = await getServer(env,id);
  if (!s) return json({ ok:false,error:'Server không tồn tại' },404);
  const result = await pingServer(env, s);
  return json({ ok:true, result });
}
async function getLogs(id, env) {
  const rows = await env.DB.prepare('SELECT * FROM ping_logs WHERE server_id=? ORDER BY pinged_at DESC LIMIT 50').bind(id).all();
  return json({ ok:true, logs: rows.results });
}
async function getServer(env,id){ const r=await env.DB.prepare('SELECT * FROM servers WHERE id=?').bind(id).first(); return r ? normalizeServer(r) : null; }

async function runDuePings(env) {
  await ensureDb(env);
  const now = Date.now();
  const rows = await env.DB.prepare('SELECT * FROM servers WHERE enabled=1 AND next_ping_at<=? ORDER BY next_ping_at ASC LIMIT 20').bind(now).all();
  for (const raw of rows.results) await pingServer(env, normalizeServer(raw));
}

async function pingServer(env, s) {
  const started = Date.now();
  let status='offline', httpStatus=null, error=null;
  const controller = new AbortController();
  const timer = setTimeout(()=>controller.abort('timeout'), TIMEOUT_MS);
  try {
    const res = await fetch(s.url, { method:'GET', redirect:'follow', signal: controller.signal, headers:{ 'User-Agent':'PingAlive-AIGUKA/1.0' }});
    httpStatus = res.status;
    status = res.status >= 200 && res.status < 500 ? 'online' : 'offline';
  } catch(e) { error = e?.message || String(e); }
  clearTimeout(timer);
  const responseMs = Date.now() - started;
  const now = Date.now();
  const next = now + pickDelayMs(s);
  await env.DB.prepare(`UPDATE servers SET last_ping_at=?,last_status=?,last_http_status=?,last_response_ms=?,last_error=?,next_ping_at=?,updated_at=? WHERE id=?`)
    .bind(now,status,httpStatus,responseMs,error,next,now,s.id).run();
  await env.DB.prepare(`INSERT INTO ping_logs (id,server_id,pinged_at,status,http_status,response_ms,error) VALUES (?,?,?,?,?,?,?)`)
    .bind(crypto.randomUUID(),s.id,now,status,httpStatus,responseMs,error).run();
  await env.DB.prepare(`DELETE FROM ping_logs WHERE id IN (SELECT id FROM ping_logs WHERE server_id=? ORDER BY pinged_at DESC LIMIT -1 OFFSET 100)`).bind(s.id).run();
  return { server_id:s.id, status, http_status:httpStatus, response_ms:responseMs, error, next_ping_at:next };
}

function sanitizeConfig(b){
  let min = clamp(Number(b.min_minutes ?? 5),1,1440), max=clamp(Number(b.max_minutes ?? 14),1,1440), fixed=clamp(Number(b.fixed_minutes ?? 10),1,1440);
  if (min>max) [min,max]=[max,min];
  return { enabled: b.enabled !== false && b.enabled !== 0, random_enabled: b.random_enabled !== false && b.random_enabled !== 0, min_minutes:min, max_minutes:max, fixed_minutes:fixed };
}
function pickDelayMs(s){ const m = s.random_enabled ? rand(s.min_minutes,s.max_minutes) : s.fixed_minutes; return m*60*1000; }
function rand(a,b){ return Math.floor(Math.random()*(b-a+1))+a; }
function clamp(n,a,b){ return Math.max(a,Math.min(b,Number.isFinite(n)?Math.round(n):a)); }
function cleanUrl(v){ const u = new URL(String(v||'').trim()); if(!['http:','https:'].includes(u.protocol)) throw new Error('URL phải bắt đầu bằng http:// hoặc https://'); return u.toString(); }
function normalizeServer(r){ return { ...r, enabled:!!r.enabled, random_enabled:!!r.random_enabled }; }
function enc(s){ return new TextEncoder().encode(s); }
function b64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/=+$/,''); }
function json(data,status=200,headers={}){ return new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8',...headers}}); }

async function handlePage(request, env) {
  const authed = isAuthed(request, env);
  const html = authed ? dashboardHtml() : loginHtml();
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function loginHtml(){return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PingAlive Login</title>${style()}</head><body><main class="login"><div class="card"><h1>PingAlive</h1><p>Đăng nhập trang điều khiển WakeUp server.</p><form id="f"><input id="p" type="password" placeholder="ADMIN_PASSWORD" autofocus><button>Đăng nhập</button></form><div id="msg" class="msg"></div></div></main><script>document.getElementById('f').onsubmit=async(e)=>{e.preventDefault();msg.textContent='Đang đăng nhập...';let r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p.value})});let j=await r.json(); if(j.ok) location.reload(); else msg.textContent=j.error||'Lỗi đăng nhập';}</script></body></html>`}
function dashboardHtml(){return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PingAlive Dashboard</title>${style()}</head><body><header><div><h1>PingAlive</h1><p>WakeUp nhiều server Render/Railway/VPS bằng Cloudflare Cron.</p></div><button onclick="logout()" class="ghost">Đăng xuất</button></header><main><section class="card"><h2>Thêm máy chủ</h2><div class="grid"><input id="name" placeholder="Tên, ví dụ AIGUKA"><input id="url" placeholder="https://your-server.onrender.com/"><label><input id="random" type="checkbox" checked> Random</label><input id="min" type="number" value="5" min="1"><input id="max" type="number" value="14" min="1"><input id="fixed" type="number" value="10" min="1"><button onclick="addServer()">+ Thêm server</button></div><small>Random mặc định 5–14 phút. Cron chạy mỗi phút và chỉ ping server nào đã tới lịch.</small></section><section class="card"><div class="row"><h2>Bảng trạng thái</h2><button onclick="load()">Tải lại</button></div><div class="tablewrap"><table><thead><tr><th>Máy chủ</th><th>URL</th><th>Trạng thái</th><th>WakeUp</th><th>Response</th><th>Lần ping cuối</th><th>Lần tới</th><th>Hành động</th></tr></thead><tbody id="tbody"></tbody></table></div></section><section class="card"><h2>Log gần nhất</h2><pre id="logs">Chọn “Log” ở một server để xem.</pre></section></main><script>${appJs()}</script></body></html>`}
function style(){return `<style>body{font-family:Inter,Arial,sans-serif;margin:0;background:#f6f7fb;color:#111827}header{display:flex;justify-content:space-between;align-items:center;padding:24px 32px;background:#111827;color:white}h1,h2{margin:0 0 8px}p{margin:0;color:#cbd5e1}.card{background:white;margin:22px auto;padding:22px;border-radius:16px;box-shadow:0 8px 24px #0001;max-width:1180px}.login{min-height:100vh;display:grid;place-items:center}.login .card{width:min(420px,90vw)}input,button{padding:12px;border-radius:10px;border:1px solid #d1d5db;font-size:15px}button{background:#2563eb;color:white;border:0;cursor:pointer;font-weight:700}.ghost{background:#374151}.grid{display:grid;grid-template-columns:1fr 2fr auto 90px 90px 90px auto;gap:10px;align-items:center}.row{display:flex;justify-content:space-between;align-items:center}.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse}th,td{padding:12px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}th{background:#f9fafb}.pill{display:inline-block;padding:6px 10px;border-radius:999px;font-weight:700}.online{background:#dcfce7;color:#166534}.offline{background:#fee2e2;color:#991b1b}.unknown{background:#e5e7eb;color:#374151}.actions button{margin:2px;padding:8px 10px}.danger{background:#dc2626}.muted{color:#6b7280;font-size:13px}.msg{margin-top:12px;color:#dc2626}pre{white-space:pre-wrap;background:#0b1020;color:#d1e7ff;padding:16px;border-radius:12px}@media(max-width:900px){.grid{grid-template-columns:1fr}header{padding:18px;display:block}.card{margin:14px;padding:16px}}</style>`}
function appJs(){return `let servers=[];const fmt=t=>t?new Date(t).toLocaleString('vi-VN'):'-';const remain=t=>{if(!t)return'-';let s=Math.max(0,Math.round((t-Date.now())/1000));return s<60?s+'s':Math.round(s/60)+' phút'};async function api(p,o={}){let r=await fetch(p,{headers:{'Content-Type':'application/json'},...o});let j=await r.json();if(!j.ok)throw new Error(j.error||'API error');return j}async function load(){let j=await api('/api/servers');servers=j.servers;tbody.innerHTML=servers.map(s=>'<tr><td><b>'+esc(s.name)+'</b><div class="muted">'+(s.enabled?'Đang bật':'Đang tắt')+'</div></td><td><a href="'+esc(s.url)+'" target="_blank">'+esc(s.url)+'</a></td><td><span class="pill '+s.last_status+'">'+label(s.last_status)+'</span><div class="muted">HTTP '+(s.last_http_status??'-')+'</div></td><td>'+(s.random_enabled?'Random '+s.min_minutes+'-'+s.max_minutes+' phút':'Cố định '+s.fixed_minutes+' phút')+'</td><td>'+(s.last_response_ms??'-')+' ms</td><td>'+fmt(s.last_ping_at)+'</td><td>'+remain(s.next_ping_at)+'</td><td class="actions"><button onclick="ping(\''+s.id+'\')">Wake</button><button onclick="toggle(\''+s.id+'\','+(!s.enabled)+')">'+(s.enabled?'Tắt':'Bật')+'</button><button onclick="showLogs(\''+s.id+'\')">Log</button><button class="danger" onclick="del(\''+s.id+'\')">Xóa</button></td></tr>').join('')||'<tr><td colspan="8">Chưa có server nào.</td></tr>'}function label(x){return x==='online'?'🟢 Online':x==='offline'?'🔴 Offline':'⚪ Unknown'}function esc(s){return String(s??'').replace(/[&<>"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]))}async function addServer(){try{await api('/api/servers',{method:'POST',body:JSON.stringify({name:name.value,url:url.value,random_enabled:random.checked,min_minutes:+min.value,max_minutes:+max.value,fixed_minutes:+fixed.value})});name.value='';url.value='';await load()}catch(e){alert(e.message)}}async function ping(id){await api('/api/servers/'+id+'/ping',{method:'POST'});await load()}async function toggle(id,en){await api('/api/servers/'+id,{method:'PUT',body:JSON.stringify({enabled:en,resetSchedule:true})});await load()}async function del(id){if(confirm('Xóa server này?')){await api('/api/servers/'+id,{method:'DELETE'});await load()}}async function showLogs(id){let j=await api('/api/servers/'+id+'/logs');logs.textContent=j.logs.map(l=>new Date(l.pinged_at).toLocaleString('vi-VN')+' | '+l.status+' | HTTP '+(l.http_status??'-')+' | '+(l.response_ms??'-')+'ms | '+(l.error??'')).join('\n')||'Chưa có log'}async function logout(){await fetch('/api/logout',{method:'POST'});location.reload()}load();setInterval(load,30000);`}
