'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { boot, PASADO } = require('./helpers');

describe('Pruebas de seguridad (OWASP Top 10 / ISO 27000)', () => {
  let t;
  before(async () => { t = await boot(); });
  after(async () => { await t.close(); });

  it('CS-01 A03 inyección SQL: payloads en login y filtros no autentican, no filtran datos ni dañan las tablas', async () => {
    const usuariosAntes = t.db.prepare('SELECT COUNT(*) n FROM usuarios').get().n;
    const l1 = await t.client().post('/api/auth/login', { email: "' OR '1'='1' --", password: "' OR '1'='1" });
    assert.ok([400, 401].includes(l1.status));
    const l2 = await t.client().post('/api/auth/login', { email: "admin@elretiro.cl' --", password: 'x' });
    assert.equal(l2.status, 401);
    const f1 = await t.client().get('/api/canchas?deporte=' + encodeURIComponent("' OR '1'='1"));
    assert.ok(f1.status === 400 || (f1.status === 200 && f1.json.canchas.length === 0), 'no debe devolver todo el catálogo');
    const f2 = await t.client().get('/api/canchas?deporte=' + encodeURIComponent("Pádel'; DROP TABLE reservas;--"));
    assert.ok(f2.status === 400 || f2.json.canchas.length === 0);
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM usuarios').get().n, usuariosAntes);
    assert.ok(t.db.prepare("SELECT name FROM sqlite_master WHERE name = 'reservas'").get());
  });

  it('CS-02 A03 XSS: nombres con HTML/script se rechazan y la CSP bloquea scripts externos o en línea', async () => {
    for (const nombre of ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', 'Ana"><svg/onload=alert(1)>']) {
      const r = await t.client().post('/api/auth/registro', { nombre, email: `xss${Math.random()}@correo.cl`.replace('0.', 'a'), telefono: '+56912345678', password: 'ClaveSegura123', acepta_privacidad: true });
      assert.equal(r.status, 400, nombre);
    }
    const adm = await t.admin();
    const pres = await adm.post('/api/recinto/reservas-presenciales', { cancha_id: 1, fecha: PASADO, hora_inicio: 16, cliente_nombre: '<script>x</script>' });
    assert.equal(pres.status, 400);
    const home = await t.client().get('/');
    const csp = home.headers.get('content-security-policy');
    assert.match(csp, /script-src 'self'/);
    assert.match(csp, /object-src 'none'/);
    assert.doesNotMatch(csp, /unsafe-inline.*script|script-src[^;]*unsafe-inline/);
  });

  it('CS-03 A01 control de acceso: sin sesión, los recursos protegidos devuelven 401', async () => {
    const c = t.client();
    for (const ruta of ['/api/reservas/mias', '/api/recinto/reservas?fecha=' + PASADO, '/api/auth/me']) {
      assert.equal((await c.get(ruta)).status, 401, ruta);
    }
    assert.equal((await c.post('/api/reservas', { cancha_id: 1, fecha: PASADO, hora_inicio: 15 })).status, 401);
  });

  it('CS-04 A01 IDOR: un jugador no puede ver, pagar ni cancelar reservas de otro (404) y la reserva no cambia', async () => {
    const a = await t.jugador();
    const b = await t.jugador();
    const r = await a.post('/api/reservas', { cancha_id: 1, fecha: PASADO, hora_inicio: 14 });
    const id = r.json.reserva.id;
    assert.equal((await b.post(`/api/reservas/${id}/pagar`, { medio: 'en_recinto' })).status, 404);
    assert.equal((await b.post(`/api/reservas/${id}/cancelar`)).status, 404);
    assert.equal(t.db.prepare('SELECT estado FROM reservas WHERE id = ?').get(id).estado, 'SOLICITADA');
    assert.ok(!(await b.get('/api/reservas/mias')).text.includes(r.json.reserva.codigo));
  });

  it('CS-05 A01 RBAC: jugador no accede al panel; admin no reserva como jugador ni opera sobre otro recinto', async () => {
    const j = await t.jugador();
    assert.equal((await j.get('/api/recinto/reservas?fecha=' + PASADO)).status, 403);
    assert.equal((await j.post('/api/recinto/canchas', { nombre: 'Hack', deporte: 'Pádel', precio_hora: 5000, hora_apertura: 9, hora_cierre: 20 })).status, 403);

    const retiro = await t.admin('admin@elretiro.cl');
    const padel = await t.admin('admin@padelcenter.cl');
    assert.equal((await retiro.post('/api/reservas', { cancha_id: 1, fecha: PASADO, hora_inicio: 15 })).status, 403);

    const pres = await retiro.post('/api/recinto/reservas-presenciales', { cancha_id: 1, fecha: PASADO, hora_inicio: 17, cliente_nombre: 'Cliente Retiro' });
    assert.equal(pres.status, 201);
    // el admin de Pádel Center intenta tocar el recinto El Retiro
    assert.equal((await padel.post('/api/recinto/reservas-presenciales', { cancha_id: 1, fecha: PASADO, hora_inicio: 18, cliente_nombre: 'Intruso' })).status, 404);
    assert.equal((await padel.post(`/api/recinto/reservas/${pres.json.reserva.id}/cancelar`)).status, 404);
    const calPadel = await padel.get('/api/recinto/reservas?fecha=' + PASADO);
    assert.ok(!calPadel.text.includes(pres.json.reserva.codigo));
    assert.equal(t.db.prepare('SELECT estado FROM reservas WHERE id = ?').get(pres.json.reserva.id).estado, 'CONFIRMADA');
  });

  it('CS-06 A01 asignación masiva: enviar rol=ADMIN_RECINTO al registrarse no otorga privilegios', async () => {
    const c = t.client();
    const r = await c.post('/api/auth/registro', {
      nombre: 'Mallory Gómez', email: 'mallory@correo.cl', telefono: '+56912345678', password: 'ClaveSegura123',
      acepta_privacidad: true, rol: 'ADMIN_RECINTO', admin_id: 1
    });
    assert.equal(r.status, 201);
    assert.equal(r.json.usuario.rol, 'JUGADOR');
    assert.equal(t.db.prepare('SELECT rol FROM usuarios WHERE email = ?').get('mallory@correo.cl').rol, 'JUGADOR');
    assert.equal((await c.get('/api/recinto/reservas?fecha=' + PASADO)).status, 403);
  });

  it('CS-07 A04 integridad de transacciones: el cliente no puede fijar monto ni estado de la reserva', async () => {
    const j = await t.jugador();
    const r = await j.post('/api/reservas', { cancha_id: 2, fecha: PASADO, hora_inicio: 12, monto: 1, estado: 'PAGADA', jugador_id: 1 });
    assert.equal(r.status, 201);
    assert.equal(r.json.reserva.monto, 12000);
    assert.equal(r.json.reserva.estado, 'SOLICITADA');
    const row = t.db.prepare('SELECT jugador_id FROM reservas WHERE id = ?').get(r.json.reserva.id);
    assert.equal(row.jugador_id, j.userId);
  });

  it('CS-08 A07 fuerza bruta: tras 5 intentos fallidos la cuenta se bloquea, incluso con la clave correcta, y luego se libera', async () => {
    const email = 'jugador@correo.cl';
    const c = t.client();
    for (let i = 0; i < 5; i++) {
      const r = await c.post('/api/auth/login', { email, password: 'ClaveIncorrecta1' });
      assert.equal(r.status, 401);
    }
    const bloqueado = await c.post('/api/auth/login', { email, password: t.creds[email] });
    assert.equal(bloqueado.status, 429);
    t.clock.advanceMin(16);
    const libre = await c.post('/api/auth/login', { email, password: t.creds[email] });
    assert.equal(libre.status, 200);
    t.clock.advanceMin(-16);
  });

  it('CS-09 A07 enumeración de usuarios: correo inexistente y clave incorrecta responden igual', async () => {
    const a = await t.client().post('/api/auth/login', { email: 'noexiste@correo.cl', password: 'ClaveIncorrecta1' });
    const b = await t.client().post('/api/auth/login', { email: 'admin@padelcenter.cl', password: 'ClaveIncorrecta1' });
    assert.equal(a.status, b.status);
    assert.equal(a.json.error, b.json.error);
  });

  it('CS-10 A01 CSRF: una petición que modifica datos sin la cabecera X-Requested-With se rechaza aunque traiga cookie válida', async () => {
    const j = await t.jugador();
    const r = await j.post('/api/reservas', { cancha_id: 1, fecha: PASADO, hora_inicio: 13 }, { csrf: false });
    assert.equal(r.status, 403);
    assert.equal(t.db.prepare("SELECT COUNT(*) n FROM reservas WHERE cancha_id = 1 AND fecha = ? AND hora_inicio = 13").get(PASADO).n, 0);
  });

  it('CS-11 A05 cabeceras de seguridad: sin X-Powered-By, nosniff, CSP, anti-clickjacking y no-store en la API', async () => {
    const r = await t.client().get('/api/canchas');
    assert.equal(r.headers.get('x-powered-by'), null);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.match(r.headers.get('cache-control'), /no-store/);
    assert.equal(r.headers.get('x-frame-options'), 'SAMEORIGIN');
  });

  it('CS-12 A02/A07 tokens: firmado con otra clave, alg=none, expirado o de usuario inexistente se rechazan', async () => {
    const mk = (cookie) => { const c = t.client(); c.cookie = cookie; return c; };
    const falso = jwt.sign({ sub: 1, rol: 'ADMIN_RECINTO' }, 'otra-clave-distinta-de-32-caracteres!!');
    assert.equal((await mk('cy_token=' + falso).get('/api/auth/me')).status, 401);
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 1, rol: 'ADMIN_RECINTO' })).toString('base64url');
    assert.equal((await mk(`cy_token=${header}.${payload}.`).get('/api/auth/me')).status, 401);
    const expirado = jwt.sign({ sub: 1, rol: 'JUGADOR' }, t.config.jwtSecret, { expiresIn: -60 });
    assert.equal((await mk('cy_token=' + expirado).get('/api/auth/me')).status, 401);
    const fantasma = jwt.sign({ sub: 99999, rol: 'JUGADOR' }, t.config.jwtSecret, { expiresIn: '5m' });
    assert.equal((await mk('cy_token=' + fantasma).get('/api/auth/me')).status, 401);
  });

  it('CS-13 A07 limitación de tasa: se bloquean los intentos de login repetidos desde una misma IP (429)', async () => {
    const t2 = await boot({ rateLimit: { authMax: 3, apiMax: 1000 } });
    try {
      const c = t2.client();
      const estados = [];
      for (let i = 0; i < 5; i++) estados.push((await c.post('/api/auth/login', { email: 'x@correo.cl', password: 'ClaveIncorrecta1' })).status);
      assert.deepEqual(estados.slice(0, 3), [401, 401, 401]);
      assert.equal(estados[3], 429);
      assert.equal(estados[4], 429);
    } finally { await t2.close(); }
  });

  it('CS-14 A05 manejo de errores: JSON inválido y rutas inexistentes responden sin trazas ni rutas internas', async () => {
    const mal = await t.client().req('POST', '/api/auth/login', '{"email": ', {});
    assert.equal(mal.status, 400);
    const nf = await t.client().get('/api/no-existe');
    assert.equal(nf.status, 404);
    for (const r of [mal, nf]) {
      assert.ok(r.json && typeof r.json.error === 'string');
      assert.doesNotMatch(r.text, /node_modules|\/home\/|at .*\(.*:\d+:\d+\)|SyntaxError/);
    }
  });

  it('CS-15 A09 auditoría: login fallido, bloqueo, creación de reserva y pago quedan registrados', async () => {
    const j = await t.jugador();
    await t.client().post('/api/auth/login', { email: j.email, password: 'ClaveIncorrecta1' });
    const r = await j.post('/api/reservas', { cancha_id: 3, fecha: PASADO, hora_inicio: 21 });
    await j.post(`/api/reservas/${r.json.reserva.id}/pagar`, { medio: 'webpay_simulado', tarjeta: '4242424242424242' });
    const acciones = t.db.prepare('SELECT accion FROM auditoria WHERE usuario_id = ?').all(j.userId).map((x) => x.accion);
    for (const esperada of ['REGISTRO', 'LOGIN_FALLIDO', 'RESERVA_CREADA', 'PAGO_APROBADO']) {
      assert.ok(acciones.includes(esperada), `falta ${esperada}`);
    }
    assert.ok(t.db.prepare("SELECT COUNT(*) n FROM auditoria WHERE accion = 'CUENTA_BLOQUEADA'").get().n >= 1);
    const detalle = t.db.prepare('SELECT detalle FROM auditoria').all().map((x) => x.detalle || '').join(' ');
    assert.ok(!detalle.includes('4242424242424242'), 'la bitácora no debe contener datos de tarjeta');
  });

  it('CS-16 A02/Ley 19.628 datos personales: el teléfono está cifrado en reposo y el administrador solo ve los 4 últimos dígitos', async () => {
    const j = await t.jugador();
    const r = await j.post('/api/reservas', { cancha_id: 1, fecha: PASADO, hora_inicio: 10 });
    assert.equal(r.status, 201);
    const enBd = t.db.prepare('SELECT telefono_enc FROM usuarios WHERE id = ?').get(j.userId).telefono_enc;
    assert.ok(!enBd.includes('56912345678'));
    const adm = await t.admin();
    const cal = await adm.get('/api/recinto/reservas?fecha=' + PASADO);
    const mia = cal.json.reservas.find((x) => x.codigo === r.json.reserva.codigo);
    assert.equal(mia.telefono, '***5678');
    assert.ok(!cal.text.includes('+56912345678'));
  });

  it('CS-17 A03 contaminación de parámetros: repetir un filtro (?deporte=a&deporte=b) se rechaza', async () => {
    const r = await t.client().get('/api/canchas?deporte=Futbol&deporte=Padel');
    assert.equal(r.status, 400);
  });

  it('CS-18 A02 exposición de datos sensibles: ninguna respuesta contiene hashes de contraseña', async () => {
    const j = await t.jugador();
    const textos = [(await j.get('/api/auth/me')).text, (await j.get('/api/reservas/mias')).text, (await t.client().get('/api/canchas')).text];
    for (const x of textos) assert.doesNotMatch(x, /password|\$2[aby]\$|telefono_enc/i);
  });

  it('CS-19 A07 cierre de sesión: tras logout la cookie se elimina y los recursos protegidos dejan de estar disponibles', async () => {
    const j = await t.jugador();
    assert.equal((await j.get('/api/auth/me')).status, 200);
    const out = await j.post('/api/auth/logout');
    assert.equal(out.status, 200);
    assert.equal((await j.get('/api/auth/me')).status, 401);
  });

  it('CS-20 A05 en producción: HSTS activo y cookie de sesión con atributo Secure', async () => {
    const t3 = await boot({ production: true, cookieSecure: true });
    try {
      const c = t3.client();
      const r = await c.post('/api/auth/login', { email: 'jugador@correo.cl', password: t3.creds['jugador@correo.cl'] });
      assert.match(r.setCookie.join(';'), /Secure/i);
      assert.match(r.headers.get('strict-transport-security') || '', /max-age=\d+/);
    } finally { await t3.close(); }
  });

  it('CS-21 A07 sesión: un token robado antes del cierre de sesión deja de ser válido en el servidor (repetición del token)', async () => {
    const j = await t.jugador();
    const tokenCopiado = j.cookie;               // un atacante copió la cookie antes del logout
    await j.post('/api/auth/logout');
    const atacante = t.client();
    atacante.cookie = tokenCopiado;
    assert.equal((await atacante.get('/api/auth/me')).status, 401);
    assert.equal((await atacante.get('/api/reservas/mias')).status, 401);
  });

  it('CS-22 A05 configuración: una ruta inexistente fuera de la API no revela el framework ni usa páginas de error por defecto', async () => {
    const r = await t.client().get('/ruta-que-no-existe');
    assert.equal(r.status, 404);
    assert.doesNotMatch(r.text, /Cannot GET|Express/i);
    assert.match(r.headers.get('content-security-policy') || '', /script-src 'self'/);
  });

  it('CS-25 A07/Ley 21.719 tras eliminar la cuenta, el token anterior queda inválido y el administrador no puede usar esa vía', async () => {
    const j = await t.jugador('supr');
    const tokenCopiado = j.cookie;
    assert.equal((await j.post('/api/auth/eliminar-cuenta', { password: 'ClaveSegura123' })).status, 200);
    const otro = t.client(); otro.cookie = tokenCopiado;
    assert.equal((await otro.get('/api/auth/me')).status, 401);
    const adm = await t.admin();
    assert.equal((await adm.post('/api/auth/eliminar-cuenta', { password: t.creds['admin@elretiro.cl'] })).status, 403);
    assert.equal((await t.client().post('/api/auth/eliminar-cuenta', { password: 'x' })).status, 401);
  });
});
