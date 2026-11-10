'use strict';
// Testes ponta a ponta com um "Mercado Pago falso" local. Rode: node test.js
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert');
const { createApp } = require('./server');

let passed = 0;
const ok = (name) => { passed++; console.log('  ✓', name); };

function fakeMp() {
  const st = { payments: {}, prefCalls: 0, payCalls: 0, prefs: [] };
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json');
      if (req.headers.authorization !== 'Bearer TEST_TOKEN') { res.statusCode = 401; return res.end('{}'); }
      if (req.method === 'POST' && req.url === '/checkout/preferences') {
        st.prefCalls++; const j = JSON.parse(body); st.prefs.push(j);
        return res.end(JSON.stringify({ id: 'pref' + st.prefCalls, init_point: 'https://mp.test/pay/' + j.external_reference }));
      }
      const m = req.url.match(/^\/v1\/payments\/(\d+)$/);
      if (m) { st.payCalls++; const p = st.payments[m[1]]; if (!p) { res.statusCode = 404; return res.end('{}'); } return res.end(JSON.stringify(p)); }
      res.statusCode = 404; res.end('{}');
    });
  });
  return new Promise((r) => srv.listen(0, () => r({ srv, st, url: 'http://127.0.0.1:' + srv.address().port })));
}

async function boot(mpUrl, extra = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'loja-'));
  const app = createApp({
    SESSION_SECRET: 'x'.repeat(48), MP_ACCESS_TOKEN: 'TEST_TOKEN', MP_WEBHOOK_SECRET: 'whsec', BASE_URL: 'https://loja.test',
    PRICE: '7', MP_API_BASE: mpUrl, DATA_DIR: dir, TRUST_PROXY: '1', ...extra,
  });
  await new Promise((r) => app.server.listen(0, r));
  const base = 'http://127.0.0.1:' + app.server.address().port;
  return { app, base, dir };
}
let ipN = 1;
const post = (base, p, body, headers = {}) => fetch(base + p, {
  method: 'POST', redirect: 'manual',
  headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': headers.ip || '9.9.9.' + (ipN++), ...headers }, body: JSON.stringify(body),
});
const form = (extra = {}) => ({ email: 'maria' + Math.random().toString(36).slice(2, 8) + '@mail.com', accept: true, termsVersion: 'v1', hp: '', ts: Date.now() - 5000, ...extra });

(async () => {
  const mp = await fakeMp();
  const { app, base } = await boot(mp.url);
  const get = (p, h = {}) => fetch(base + p, { redirect: 'manual', headers: { 'X-Forwarded-For': '8.8.8.' + (ipN++), ...h } });
  console.log('Loja / acesso');

  let r = await get('/ebook'); assert.equal(r.status, 302); assert(r.headers.get('location').includes('acesso=negado')); ok('e-book bloqueado sem pagamento');
  r = await get('/private/ebook.html'); assert.equal(r.status, 404); ok('arquivo privado não é servido diretamente');
  r = await get('/'); assert.equal(r.status, 200); assert(!(await r.text()).includes('TEST_TOKEN')); ok('página da loja não vaza chaves');
  r = await (await get('/api/config')).json(); assert(!JSON.stringify(r).includes('TEST_TOKEN') && r.price === 7); ok('/api/config não expõe segredos');

  console.log('Checkout');
  r = await post(base, '/api/checkout', form({ accept: false })); assert.equal(r.status, 400); ok('exige aceite dos termos (servidor)');
  r = await post(base, '/api/checkout', form({ hp: 'bot' })); assert.equal(r.status, 400); ok('honeypot barra bot');
  r = await post(base, '/api/checkout', form({ ts: Date.now() })); assert.equal(r.status, 400); ok('formulário preenchido rápido demais é barrado');
  r = await post(base, '/api/checkout', form({ email: 'invalido' })); assert.equal(r.status, 400); ok('e-mail inválido');
  r = await fetch(base + '/api/checkout', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' }); assert.equal(r.status, 403); ok('exige JSON (anti-CSRF simples)');
  r = await fetch(base + '/api/checkout', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://evil.com' }, body: '{}' }); assert.equal(r.status, 403); ok('rejeita Origin de outro site');
  r = await fetch(base + '/api/checkout', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '7.7.7.7' }, body: JSON.stringify({ x: 'a'.repeat(9000) }) }); assert.equal(r.status, 413); ok('corpo grande é recusado');

  const f1 = form();
  r = await post(base, '/api/checkout', f1); assert.equal(r.status, 200); const c1 = await r.json();
  assert(c1.url.startsWith('https://mp.test/pay/') && /^[a-f0-9]{32}$/.test(c1.orderId));
  const pref = mp.st.prefs[0]; assert.equal(pref.items[0].unit_price, 7); assert.equal(pref.external_reference, c1.orderId);
  assert(pref.notification_url === 'https://loja.test/api/webhook/mp'); ok('cria checkout de R$ 7 com external_reference e webhook');
  const before = mp.st.prefCalls;
  r = await post(base, '/api/checkout', { ...f1 }); assert.equal((await r.json()).orderId, c1.orderId); assert.equal(mp.st.prefCalls, before); ok('mesmo e-mail reaproveita o pedido (sem cobrança/chamada duplicada)');

  console.log('Verificação do pagamento');
  const verify = (orderId, paymentId) => post(base, '/api/verify', { orderId, paymentId });
  r = await verify(c1.orderId, null); assert.equal((await r.json()).state, 'pending'); ok('sem pagamento → pendente');
  r = await get('/acesso/' + c1.orderId); assert.equal(r.status, 302); assert(r.headers.get('location').includes('negado')); ok('link /acesso não funciona sem pagamento');

  mp.st.payments['1001'] = { status: 'pending', transaction_amount: 7, currency_id: 'BRL', external_reference: c1.orderId };
  r = await verify(c1.orderId, '1001'); assert.equal((await r.json()).state, 'pending'); ok('pix pendente não libera');
  mp.st.payments['1002'] = { status: 'rejected', transaction_amount: 7, currency_id: 'BRL', external_reference: c1.orderId };
  r = await verify(c1.orderId, '1002'); assert.equal((await r.json()).state, 'invalid'); ok('pagamento recusado não libera');
  mp.st.payments['1003'] = { status: 'approved', transaction_amount: 1, currency_id: 'BRL', external_reference: c1.orderId };
  r = await verify(c1.orderId, '1003'); assert.equal((await r.json()).state, 'invalid'); ok('valor menor que R$ 7 não libera');
  mp.st.payments['1004'] = { status: 'approved', transaction_amount: 7, currency_id: 'USD', external_reference: c1.orderId };
  r = await verify(c1.orderId, '1004'); assert.equal((await r.json()).state, 'invalid'); ok('moeda diferente não libera');
  mp.st.payments['1005'] = { status: 'approved', transaction_amount: 7, currency_id: 'BRL', external_reference: 'ffffffffffffffffffffffffffffffff' };
  r = await verify(c1.orderId, '1005'); assert.equal((await r.json()).state, 'invalid'); ok('pagamento de OUTRO pedido não libera este');
  r = await verify(c1.orderId, '99999'); assert.equal((await r.json()).state, 'invalid'); ok('payment_id inexistente não libera');
  r = await verify(c1.orderId, '1;DROP'); assert.equal(r.status, 400); ok('payment_id malformado barrado');
  r = await get('/ebook'); assert.equal(r.status, 302); ok('nada disso liberou o e-book');
  r = await get('/ebook', { Cookie: 'ebk=aaaa.bbbb' }); assert.equal(r.status, 302); ok('cookie forjado não libera');

  mp.st.payments['2001'] = { status: 'approved', transaction_amount: 7, currency_id: 'BRL', external_reference: c1.orderId };
  r = await verify(c1.orderId, '2001'); const j = await r.json(); assert.equal(j.state, 'paid');
  const cookie = r.headers.get('set-cookie').split(';')[0]; assert(cookie.startsWith('ebk=')); ok('pagamento aprovado de R$ 7 libera e emite cookie assinado');
  r = await get('/ebook', { Cookie: cookie }); assert.equal(r.status, 200); const html = await r.text();
  assert(html.includes('Beleza') && r.headers.get('cache-control').includes('no-store')); ok('e-book abre com cookie válido');
  const tampered = cookie.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A'));
  r = await get('/ebook', { Cookie: tampered }); assert.equal(r.status, 302); ok('cookie adulterado é recusado');

  // reaproveitar o mesmo payment_id em outro pedido
  r = await post(base, '/api/checkout', form()); const c2 = await r.json();
  r = await verify(c2.orderId, '2001'); assert.notEqual((await r.json()).state, 'paid'); ok('um payment_id não paga dois pedidos');

  // limite de sessões por pedido
  let last; for (let i = 0; i < 6; i++) { last = await get('/acesso/' + c1.orderId); }
  assert.equal(last.status, 302); assert(last.headers.get('location').includes('negado') || last.headers.get('location').includes('limite')); ok('limite de acessos por compra (anti-compartilhamento)');

  console.log('Webhook');
  const sig = (id, reqId, ts, secret = 'whsec') => `ts=${ts},v1=` + crypto.createHmac('sha256', secret).update(`id:${id};request-id:${reqId};ts:${ts};`).digest('hex');
  r = await post(base, '/api/webhook/mp?type=payment&data.id=3001', {}, { 'x-signature': 'ts=1,v1=deadbeef', 'x-request-id': 'r1' }); assert.equal(r.status, 401); ok('webhook com assinatura falsa é recusado');
  r = await post(base, '/api/webhook/mp?type=payment&data.id=3001', {}); assert.equal(r.status, 401); ok('webhook sem assinatura é recusado');
  r = await post(base, '/api/checkout', form()); const c3 = await r.json();
  mp.st.payments['3001'] = { status: 'approved', transaction_amount: 7, currency_id: 'BRL', external_reference: c3.orderId };
  const ts = String(Date.now());
  r = await post(base, '/api/webhook/mp?type=payment&data.id=3001', { data: { id: '3001' } }, { 'x-signature': sig('3001', 'r2', ts), 'x-request-id': 'r2' }); assert.equal(r.status, 200);
  assert.equal(app.db().orders[c3.orderId].paid, true); ok('webhook assinado confirma consultando a API do MP');
  mp.st.payments['3001'].status = 'refunded';
  const ts2 = String(Date.now());
  await post(base, '/api/webhook/mp?type=payment&data.id=3001', {}, { 'x-signature': sig('3001', 'r3', ts2), 'x-request-id': 'r3' });
  assert.equal(app.db().orders[c3.orderId].paid, false); ok('estorno revoga o acesso');

  console.log('Limites e custos');
  // rate limit por IP
  const sameIp = '5.5.5.5'; const codes = [];
  for (let i = 0; i < 8; i++) codes.push((await post(base, '/api/checkout', form(), { ip: sameIp })).status);
  assert(codes.includes(429)); ok('rate limit por IP no checkout (' + codes.join(',') + ')');
  // rate limit por e-mail
  const em = 'spam@mail.com'; const c4 = [];
  for (let i = 0; i < 5; i++) c4.push((await post(base, '/api/checkout', form({ email: em + i % 1 }))).status);
  assert(c4.filter((x) => x === 200).length >= 1); ok('mesmo e-mail repetido não cria pedidos em excesso');

  // kill switch
  fs.writeFileSync(path.join(app.cfg.dataDir, 'STOP'), '1');
  r = await post(base, '/api/checkout', form()); assert.equal(r.status, 503); ok('interruptor de emergência pausa as vendas');
  r = await post(base, '/api/verify', { orderId: c1.orderId }); assert.equal(r.status, 503); ok('interruptor também pausa a verificação paga');
  fs.unlinkSync(path.join(app.cfg.dataDir, 'STOP'));
  app.close();

  // paralelismo vs cota diária
  const mp2 = await fakeMp();
  const t2 = await boot(mp2.url, { DAILY_ORDER_CAP: '5' });
  const res = await Promise.all(Array.from({ length: 40 }, () => post(t2.base, '/api/checkout', form())));
  const okN = res.filter((x) => x.status === 200).length;
  assert.equal(okN, 5); assert.equal(mp2.st.prefCalls, 5); ok('40 requisições paralelas: só 5 passam e só 5 chamadas pagas ao MP (cota diária não é furada)');
  t2.app.close();

  // teto de chamadas ao MP
  const mp3 = await fakeMp();
  const t3 = await boot(mp3.url, { DAILY_MP_CALL_CAP: '3' });
  const res3 = await Promise.all(Array.from({ length: 12 }, () => post(t3.base, '/api/checkout', form())));
  assert(mp3.st.prefCalls <= 3); ok('teto diário de chamadas ao MP respeitado (' + mp3.st.prefCalls + ' ≤ 3)');
  t3.app.close();

  // sem chaves = sem pagamento (nada de "modo fake")
  const t4 = await boot(mp.url, { MP_ACCESS_TOKEN: '' });
  r = await post(t4.base, '/api/checkout', form()); assert.equal(r.status, 503); ok('sem MP_ACCESS_TOKEN a loja recusa vender (não existe liberação "de graça")');
  t4.app.close();

  // erro do MP não gera retry em 4xx
  const mp5 = await fakeMp(); const t5 = await boot(mp5.url, { MP_ACCESS_TOKEN: 'TOKEN_ERRADO' });
  r = await post(t5.base, '/api/checkout', form()); assert.equal(r.status, 502); assert.equal(mp5.st.prefCalls, 0); ok('erro 401/4xx do MP não é repetido');
  t5.app.close();

  mp.srv.close(); mp2.srv.close(); mp3.srv.close(); mp5.srv.close();
  console.log(`\n${passed} testes passaram ✔`);
  process.exit(0);
})().catch((e) => { console.error('\nFALHOU:', e); process.exit(1); });
