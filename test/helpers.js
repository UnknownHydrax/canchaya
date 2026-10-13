'use strict';
process.env.NODE_ENV = 'test';
const { loadConfig } = require('../src/config');
const { openDb } = require('../src/db');
const { createApp } = require('../src/app');
const { seedIfEmpty } = require('../src/seed');

// Reloj controlable: permite probar expiraciones, reglas de 24 h y bloqueos sin esperar tiempo real.
function makeClock(start) {
  let t = start.getTime();
  const fn = () => new Date(t);
  fn.set = (d) => { t = d.getTime(); };
  fn.advanceMin = (m) => { t += m * 60000; };
  return fn;
}

class Client {
  constructor(base) { this.base = base; this.cookie = null; }
  async req(method, path, body, { headers = {}, csrf = true } = {}) {
    const h = { ...headers };
    if (csrf) h['x-requested-with'] = 'CanchaYa';
    if (body !== undefined) h['content-type'] = 'application/json';
    if (this.cookie) h.cookie = this.cookie;
    const res = await fetch(this.base + path, {
      method, headers: h,
      body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body))
    });
    const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const c of setCookie) {
      const m = /^cy_token=([^;]*)/.exec(c);
      if (m) this.cookie = m[1] ? `cy_token=${m[1]}` : null;
    }
    let json = null;
    const text = await res.text();
    try { json = JSON.parse(text); } catch { /* respuesta no JSON */ }
    return { status: res.status, json, text, headers: res.headers, setCookie };
  }
  get(p, o) { return this.req('GET', p, undefined, o); }
  post(p, b, o) { return this.req('POST', p, b === undefined ? {} : b, o); }
}

async function boot(overrides = {}) {
  const config = loadConfig({ bcryptRounds: 4, rateLimit: { authMax: 100000, apiMax: 1000000 }, ...overrides });
  const db = openDb(':memory:');
  const log = console.log; console.log = () => {};
  const cred = seedIfEmpty(db, config);
  console.log = log;
  const clock = makeClock(new Date(2026, 9, 12, 12, 0, 0)); // lunes 12-oct-2026 12:00 (hora Chile)
  const app = createApp({ db, config, now: clock });
  const server = await new Promise((res) => { const s = app.listen(0, '127.0.0.1', () => res(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const creds = Object.fromEntries(cred.map((c) => [c.email, c.password]));
  let n = 0;
  const ctx = {
    db, config, clock, base, creds,
    client: () => new Client(base),
    // Crea un jugador nuevo con sesión iniciada.
    async jugador(prefix = 'jug') {
      n += 1;
      const c = new Client(base);
      const email = `${prefix}${n}_${Date.now() % 100000}@correo.cl`;
      const r = await c.post('/api/auth/registro', {
        nombre: 'Jugador Prueba', email, telefono: '+56912345678',
        password: 'ClaveSegura123', acepta_privacidad: true
      });
      if (r.status !== 201) throw new Error('No se pudo registrar jugador de prueba: ' + r.text);
      c.email = email; c.userId = r.json.usuario.id;
      return c;
    },
    async admin(email = 'admin@elretiro.cl') {
      const c = new Client(base);
      const r = await c.post('/api/auth/login', { email, password: creds[email] });
      if (r.status !== 200) throw new Error('No se pudo iniciar sesión como admin: ' + r.text);
      return c;
    },
    close: () => new Promise((r) => server.close(() => { db.close(); r(); }))
  };
  return ctx;
}

// Fechas de referencia respecto del reloj simulado (hoy = 2026-10-12 12:00).
const HOY = '2026-10-12';
const MANANA = '2026-10-13';
const PASADO = '2026-10-14';

module.exports = { boot, makeClock, Client, HOY, MANANA, PASADO };
