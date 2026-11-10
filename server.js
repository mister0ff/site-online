'use strict';
/**
 * Loja "Beleza Essencial" — servidor sem dependências (Node 20+).
 *
 * Segurança / custo (resumo):
 *  - Segredos só em variáveis de ambiente; o front-end nunca recebe chaves.
 *  - Acesso ao e-book só liberado depois de o SERVIDOR consultar o pagamento na API do
 *    Mercado Pago (status approved + valor >= preço + moeda BRL + external_reference do pedido).
 *  - Webhook com assinatura HMAC (x-signature) validada.
 *  - Limites por IP / por e-mail / globais, concorrência máxima, corpo máx. 4 KB.
 *  - Anti-bot: honeypot + tempo mínimo de preenchimento + Cloudflare Turnstile (opcional).
 *  - Cotas diárias (pedidos e chamadas ao MP) reservadas ANTES da chamada paga, de forma síncrona,
 *    então requisições paralelas não furam o limite.
 *  - Sem retry em erro 4xx; no máximo 1 nova tentativa em 5xx/rede; timeout de 8 s.
 *  - Idempotência: mesmo e-mail reaproveita o checkout pendente; um payment_id só vale p/ um pedido.
 *  - Interruptor de emergência (EMERGENCY_STOP=1 ou arquivo data/STOP).
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const TERMS_VERSION = 'v1';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const b64u = (b) => Buffer.from(b).toString('base64url');

function createApp(env = process.env) {
  const cfg = {
    port: Number(env.PORT) || 3000,
    token: env.MP_ACCESS_TOKEN || '',
    webhookSecret: env.MP_WEBHOOK_SECRET || '',
    secret: env.SESSION_SECRET || '',
    baseUrl: (env.BASE_URL || '').replace(/\/$/, ''),
    price: Number(env.PRICE) || 7,
    mpApi: env.MP_API_BASE || 'https://api.mercadopago.com',
    dataDir: env.DATA_DIR || path.join(__dirname, 'data'),
    dailyOrderCap: Number(env.DAILY_ORDER_CAP) || 300,
    dailyMpCap: Number(env.DAILY_MP_CALL_CAP) || 1500,
    trustProxy: env.TRUST_PROXY === '1',
    tsSite: env.TURNSTILE_SITE_KEY || '',
    tsSecret: env.TURNSTILE_SECRET || '',
    tsVerifyUrl: env.TURNSTILE_VERIFY_URL || 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
    maxConcurrent: Number(env.MAX_CONCURRENT_CHECKOUTS) || 20,
    maxSessionsPerOrder: 5,
    seller: env.SELLER_NAME || '[SEU NOME / RAZÃO SOCIAL]',
    support: env.SUPPORT_EMAIL || '[SEU E-MAIL DE SUPORTE]',
  };
  if (cfg.secret.length < 32) throw new Error('SESSION_SECRET precisa ter 32+ caracteres.');
  const secureCookie = cfg.baseUrl.startsWith('https://');

  /* ---------- armazenamento (JSON atômico) ---------- */
  fs.mkdirSync(cfg.dataDir, { recursive: true });
  const dbFile = path.join(cfg.dataDir, 'orders.json');
  let db = { orders: {}, payments: {}, usage: {} };
  try { db = Object.assign(db, JSON.parse(fs.readFileSync(dbFile, 'utf8'))); } catch { /* novo */ }
  function save() {
    const tmp = dbFile + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, dbFile);
  }
  const today = () => new Date().toISOString().slice(0, 10);
  function usage() {
    const d = today();
    if (!db.usage[d]) {
      db.usage[d] = { orders: 0, mpCalls: 0, turnstile: 0, alerted: false };
      // retenção: mantém 30 dias de uso e apaga pedidos pendentes/falhos com +3 dias
      Object.keys(db.usage).sort().slice(0, -30).forEach((k) => delete db.usage[k]);
      const lim = Date.now() - 3 * 864e5;
      for (const [id, o] of Object.entries(db.orders)) if (!o.paid && o.createdAt < lim) delete db.orders[id];
      save();
    }
    return db.usage[d];
  }

  /* ---------- limites ---------- */
  const hits = new Map();
  function limit(key, max, windowMs) {
    const now = Date.now();
    const a = (hits.get(key) || []).filter((t) => now - t < windowMs);
    if (a.length >= max) { hits.set(key, a); return false; }
    a.push(now); hits.set(key, a); return true;
  }
  const gc = setInterval(() => {
    const cut = Date.now() - 3600e3;
    for (const [k, a] of hits) if (!a.length || a[a.length - 1] < cut) hits.delete(k);
  }, 60e3);
  gc.unref();
  let inflightCheckout = 0;
  const inflightByIp = new Map();
  const stopped = () => env.EMERGENCY_STOP === '1' || fs.existsSync(path.join(cfg.dataDir, 'STOP'));

  function clientIp(req) {
    if (cfg.trustProxy) {
      const x = String(req.headers['x-forwarded-for'] || '').split(',').pop().trim();
      if (x) return x;
    }
    return req.socket.remoteAddress || '?';
  }

  /* ---------- Mercado Pago (única saída paga) ---------- */
  function reserveMpCall() {
    const u = usage();
    if (u.mpCalls >= cfg.dailyMpCap) { const e = new Error('budget'); e.code = 'BUDGET'; throw e; }
    u.mpCalls++;
    if (!u.alerted && u.mpCalls >= cfg.dailyMpCap * 0.8) {
      u.alerted = true;
      console.warn(`[ALERTA] 80% da cota diária de chamadas ao Mercado Pago (${u.mpCalls}/${cfg.dailyMpCap}).`);
    }
    save();
  }
  async function mp(method, pth, body, idemKey, attempt = 0) {
    reserveMpCall();
    try {
      const headers = { Authorization: 'Bearer ' + cfg.token, 'Content-Type': 'application/json' };
      if (idemKey) headers['X-Idempotency-Key'] = idemKey;
      const r = await fetch(cfg.mpApi + pth, {
        method, headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(8000),
      });
      if (r.status >= 500 && attempt < 1) { await sleep(400); return mp(method, pth, body, idemKey, attempt + 1); }
      return { status: r.status, body: await r.json().catch(() => ({})) };
    } catch (e) {
      if (e.code === 'BUDGET') throw e;
      if (attempt < 1) { await sleep(400); return mp(method, pth, body, idemKey, attempt + 1); }
      throw e;
    }
  }

  /* ---------- verificação real do pagamento ---------- */
  const confirming = new Map();
  function confirm(paymentId, expectedOrder, force) {
    if (confirming.has(paymentId)) return confirming.get(paymentId);
    const pr = (async () => {
      const known = db.payments[paymentId];
      if (!force && known && db.orders[known] && db.orders[known].paid && (!expectedOrder || expectedOrder === known)) {
        return { state: 'paid', orderId: known };
      }
      const r = await mp('GET', '/v1/payments/' + encodeURIComponent(paymentId));
      if (r.status === 404) return { state: 'invalid' };
      if (r.status !== 200) return { state: 'error' };
      const p = r.body;
      const orderId = String(p.external_reference || '');
      const order = db.orders[orderId];
      if (!order || (expectedOrder && expectedOrder !== orderId)) return { state: 'invalid' };
      if (db.payments[paymentId] && db.payments[paymentId] !== orderId) return { state: 'invalid' };
      if (['refunded', 'charged_back', 'cancelled'].includes(p.status)) {
        if (order.paymentId === paymentId && order.paid) { order.paid = false; order.revoked = p.status; save(); }
        return { state: 'invalid', orderId };
      }
      if (p.status !== 'approved') {
        return { state: ['pending', 'in_process', 'authorized'].includes(p.status) ? 'pending' : 'invalid', orderId };
      }
      if (p.currency_id !== 'BRL' || !(Number(p.transaction_amount) >= cfg.price)) return { state: 'invalid', orderId };
      if (!order.paid) {
        order.paid = true; order.paymentId = paymentId; order.paidAt = Date.now(); order.revoked = undefined;
        db.payments[paymentId] = orderId; save();
      }
      return { state: 'paid', orderId };
    })().finally(() => confirming.delete(paymentId));
    confirming.set(paymentId, pr);
    return pr;
  }

  /* ---------- sessão (cookie assinado) ---------- */
  const sign = (s) => crypto.createHmac('sha256', cfg.secret).update(s).digest('base64url');
  function makeToken(orderId) {
    const payload = b64u(JSON.stringify({ o: orderId, e: Date.now() + 30 * 864e5 }));
    return payload + '.' + sign(payload);
  }
  function readToken(tok) {
    if (typeof tok !== 'string' || !tok.includes('.')) return null;
    const [payload, mac] = tok.split('.');
    const good = sign(payload);
    if (mac.length !== good.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(good))) return null;
    try {
      const j = JSON.parse(Buffer.from(payload, 'base64url').toString());
      return j.e > Date.now() ? j : null;
    } catch { return null; }
  }
  const cookies = (req) => Object.fromEntries(String(req.headers.cookie || '').split(';').map((c) => {
    const i = c.indexOf('='); return i < 0 ? ['', ''] : [c.slice(0, i).trim(), c.slice(i + 1).trim()];
  }));
  function issueSession(order, res) {
    if (order.sessions >= cfg.maxSessionsPerOrder) return false;
    order.sessions = (order.sessions || 0) + 1; save();
    res.setHeader('Set-Cookie', `ebk=${makeToken(order.id)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}${secureCookie ? '; Secure' : ''}`);
    return true;
  }

  /* ---------- helpers HTTP ---------- */
  function secHeaders(res, extra = '') {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    const ts = cfg.tsSite ? ' https://challenges.cloudflare.com' : '';
    res.setHeader('Content-Security-Policy',
      `default-src 'self'; script-src 'self' 'unsafe-inline'${ts}; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; ` +
      `font-src https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; frame-src${ts || " 'none'"}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'` + extra);
  }
  const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
  const redirect = (res, to) => { res.writeHead(302, { Location: to, 'Cache-Control': 'no-store' }); res.end(); };
  function readJson(req, max = 4096) {
    return new Promise((resolve, reject) => {
      let n = 0; const chunks = [];
      let dead = false;
      req.on('data', (c) => { if (dead) return; n += c.length; if (n > max) { dead = true; reject(Object.assign(new Error('big'), { code: 'BIG' })); } else chunks.push(c); });
      req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch { reject(Object.assign(new Error('json'), { code: 'JSON' })); } });
      req.on('error', reject);
    });
  }
  function bodyErr(req, res, e, extra) {
    const big = e && e.code === 'BIG';
    if (big) { res.setHeader('Connection', 'close'); res.on('finish', () => req.destroy()); }
    return json(res, big ? 413 : 400, Object.assign({ error: 'Requisição inválida.' }, extra));
  }
  function sameOrigin(req) {
    if (!String(req.headers['content-type'] || '').startsWith('application/json')) return false;
    const o = req.headers.origin;
    if (!o) return true;
    return o === cfg.baseUrl || o.endsWith('//' + req.headers.host);
  }
  const fileCache = {};
  function readFile(rel) {
    if (!fileCache[rel]) fileCache[rel] = fs.readFileSync(path.join(__dirname, rel));
    return fileCache[rel];
  }
  const PAGES = { '/': 'public/index.html', '/termos': 'public/termos.html', '/retorno': 'public/retorno.html' };

  /* ---------- rotas ---------- */
  async function checkout(req, res) {
    if (stopped()) return json(res, 503, { error: 'As vendas estão temporariamente pausadas. Tente mais tarde.' });
    if (!cfg.token || !cfg.baseUrl) return json(res, 503, { error: 'Pagamento ainda não configurado.' });
    const ip = clientIp(req);
    if (!limit('co:ip:' + ip, 5, 10 * 60e3)) return json(res, 429, { error: 'Muitas tentativas. Aguarde alguns minutos.' });
    if ((inflightByIp.get(ip) || 0) >= 2 || inflightCheckout >= cfg.maxConcurrent) return json(res, 429, { error: 'Servidor ocupado. Tente novamente.' });
    inflightByIp.set(ip, (inflightByIp.get(ip) || 0) + 1); inflightCheckout++;
    try {
      let b;
      try { b = await readJson(req); } catch (e) { return bodyErr(req, res, e); }
      const email = typeof b.email === 'string' ? b.email.trim().toLowerCase() : '';
      if (!/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(email) || email.length > 120) return json(res, 400, { error: 'Digite um e-mail válido.' });
      if (b.accept !== true || b.termsVersion !== TERMS_VERSION) return json(res, 400, { error: 'Você precisa concordar com os Termos para continuar.' });
      // anti-bot
      const age = Date.now() - Number(b.ts);
      if (b.hp || !(age >= 2500 && age <= 6 * 3600e3)) return json(res, 400, { error: 'Não foi possível validar o formulário. Recarregue a página.' });
      if (cfg.tsSecret) {
        if (typeof b.turnstile !== 'string' || !b.turnstile) return json(res, 400, { error: 'Confirme que você não é um robô.' });
        usage().turnstile++;
        try {
          const r = await fetch(cfg.tsVerifyUrl, {
            method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ secret: cfg.tsSecret, response: b.turnstile, remoteip: ip }), signal: AbortSignal.timeout(5000),
          });
          if (!(await r.json()).success) return json(res, 400, { error: 'Verificação anti-robô falhou.' });
        } catch { return json(res, 503, { error: 'Não foi possível verificar agora. Tente novamente.' }); }
      }
      const eh = sha(email).slice(0, 16);
      if (!limit('co:em:' + eh, 3, 3600e3)) return json(res, 429, { error: 'Muitas tentativas com este e-mail. Tente mais tarde.' });

      // idempotência: reaproveita checkout pendente recente do mesmo e-mail
      const now = Date.now();
      const open = Object.values(db.orders).find((o) => o.eh === eh && !o.paid && o.initPoint && now - o.createdAt < 20 * 60e3);
      if (open) return json(res, 200, { url: open.initPoint, orderId: open.id });

      // cota diária reservada ANTES da chamada paga (síncrono → paralelismo não fura)
      const u = usage();
      if (u.orders >= cfg.dailyOrderCap) return json(res, 503, { error: 'Limite diário de pedidos atingido. Volte amanhã.' });
      u.orders++;
      const order = { id: crypto.randomBytes(16).toString('hex'), email, eh, createdAt: now, paid: false, status: 'creating',
        terms: { v: TERMS_VERSION, at: now, ipHash: sha(ip + cfg.secret).slice(0, 16) }, sessions: 0 };
      db.orders[order.id] = order; save();
      try {
        const r = await mp('POST', '/checkout/preferences', {
          items: [{ id: 'ebook-beleza-essencial', title: 'E-book Beleza Essencial', quantity: 1, unit_price: cfg.price, currency_id: 'BRL' }],
          payer: { email }, external_reference: order.id,
          back_urls: { success: cfg.baseUrl + '/retorno', failure: cfg.baseUrl + '/retorno', pending: cfg.baseUrl + '/retorno' },
          auto_return: 'approved', notification_url: cfg.baseUrl + '/api/webhook/mp', statement_descriptor: 'BELEZAESSENCIAL',
          expires: true, expiration_date_to: new Date(now + 24 * 3600e3).toISOString(),
        }, 'pref-' + order.id);
        const url = r.body && (r.body.init_point);
        if (r.status >= 300 || !url) throw new Error('mp ' + r.status);
        order.initPoint = url; order.status = 'pending'; save();
        return json(res, 200, { url, orderId: order.id });
      } catch (e) {
        order.status = 'failed'; save();
        console.error('[checkout] falha ao criar preferência:', e.message);
        return json(res, e.code === 'BUDGET' ? 503 : 502, { error: 'Não foi possível iniciar o pagamento agora. Tente novamente em instantes.' });
      }
    } finally {
      inflightCheckout--; inflightByIp.set(ip, Math.max(0, (inflightByIp.get(ip) || 1) - 1));
    }
  }

  async function verifyRoute(req, res) {
    if (stopped()) return json(res, 503, { state: 'error' });
    const ip = clientIp(req);
    if (!limit('vf:ip:' + ip, 40, 10 * 60e3)) return json(res, 429, { state: 'error' });
    let b; try { b = await readJson(req); } catch (e) { return bodyErr(req, res, e, { state: 'error' }); }
    const orderId = String(b.orderId || ''); const paymentId = b.paymentId == null ? '' : String(b.paymentId);
    if (!/^[a-f0-9]{32}$/.test(orderId) || !db.orders[orderId]) return json(res, 404, { state: 'invalid' });
    if (!limit('vf:o:' + orderId, 40, 3600e3)) return json(res, 429, { state: 'error' });
    const order = db.orders[orderId];
    let state = order.paid ? 'paid' : 'pending';
    if (!order.paid && paymentId) {
      if (!/^\d{3,20}$/.test(paymentId)) return json(res, 400, { state: 'invalid' });
      try { state = (await confirm(paymentId, orderId)).state; } catch (e) { return json(res, e.code === 'BUDGET' ? 503 : 502, { state: 'error' }); }
    }
    if (state === 'paid' && order.paid) {
      if (!issueSession(order, res)) return json(res, 403, { state: 'limit', error: 'Limite de acessos deste pedido atingido. Fale com o suporte.' });
      return json(res, 200, { state: 'paid', url: '/ebook' });
    }
    return json(res, 200, { state });
  }

  function validSignature(req, dataId) {
    const sig = String(req.headers['x-signature'] || '');
    const parts = Object.fromEntries(sig.split(',').map((p) => p.trim().split('=')));
    if (!parts.ts || !parts.v1) return false;
    const id = /^[a-z0-9]+$/i.test(dataId) ? dataId.toLowerCase() : dataId;
    const manifest = `id:${id};request-id:${req.headers['x-request-id'] || ''};ts:${parts.ts};`;
    const good = crypto.createHmac('sha256', cfg.webhookSecret).update(manifest).digest('hex');
    return parts.v1.length === good.length && crypto.timingSafeEqual(Buffer.from(parts.v1), Buffer.from(good));
  }
  async function webhook(req, res, u) {
    if (!cfg.webhookSecret || !cfg.token) return json(res, 503, { ok: false });
    if (!limit('wh:ip:' + clientIp(req), 120, 60e3)) return json(res, 429, { ok: false });
    const dataId = u.searchParams.get('data.id') || '';
    if (!dataId || !validSignature(req, dataId)) return json(res, 401, { ok: false });
    try { await readJson(req, 16384); } catch { /* corpo é irrelevante: o dado vem da API */ }
    if (u.searchParams.get('type') !== 'payment' || !/^\d{3,20}$/.test(dataId)) return json(res, 200, { ok: true });
    try { await confirm(dataId, null, true); return json(res, 200, { ok: true }); } catch (e) {
      return json(res, e.code === 'BUDGET' ? 200 : 500, { ok: false }); // 500 → MP tenta de novo (limitado pelo MP)
    }
  }

  function ebook(req, res) {
    const t = readToken(cookies(req).ebk);
    const o = t && db.orders[t.o];
    if (!o || !o.paid) return redirect(res, '/?acesso=negado');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'private, no-store', 'X-Robots-Tag': 'noindex' });
    res.end(readFile('private/ebook.html'));
  }

  async function handler(req, res) {
    const u = new URL(req.url, 'http://x'); const p = u.pathname;
    secHeaders(res);
    if (p === '/health') { res.writeHead(200); return res.end('ok'); }
    if (!limit('all:' + clientIp(req), 180, 60e3)) return json(res, 429, { error: 'Muitas requisições.' });
    if (req.method === 'GET' && PAGES[p]) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      return res.end(readFile(PAGES[p]));
    }
    if (req.method === 'GET' && p === '/api/config') {
      return json(res, 200, { price: cfg.price, termsVersion: TERMS_VERSION, turnstileSiteKey: cfg.tsSite || null,
        seller: cfg.seller, support: cfg.support, open: !stopped() && !!cfg.token });
    }
    if (req.method === 'POST' && (p === '/api/checkout' || p === '/api/verify')) {
      if (!sameOrigin(req)) return json(res, 403, { error: 'Origem inválida.' });
      return p === '/api/checkout' ? checkout(req, res) : verifyRoute(req, res);
    }
    if (req.method === 'POST' && p === '/api/webhook/mp') return webhook(req, res, u);
    if (req.method === 'GET' && p === '/ebook') return ebook(req, res);
    if (req.method === 'GET' && p.startsWith('/acesso/')) {
      const id = p.slice(8);
      if (!limit('ac:' + clientIp(req), 20, 10 * 60e3)) return redirect(res, '/?acesso=limite');
      const o = /^[a-f0-9]{32}$/.test(id) && db.orders[id];
      if (o && o.paid && issueSession(o, res)) return redirect(res, '/ebook');
      return redirect(res, '/?acesso=negado');
    }
    json(res, 404, { error: 'Não encontrado.' });
  }

  const server = http.createServer((req, res) => {
    handler(req, res).catch((e) => { console.error('[erro]', e); if (!res.headersSent) json(res, 500, { error: 'Erro interno.' }); else res.end(); });
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.maxConnections = 500;
  return { server, cfg, db: () => db, close: () => { clearInterval(gc); server.close(); } };
}

module.exports = { createApp };

if (require.main === module) {
  try {
    const app = createApp();
    app.server.listen(app.cfg.port, () => console.log(`Loja no ar: porta ${app.cfg.port}`));
  } catch (e) { console.error('Erro de configuração:', e.message); process.exit(1); }
}
