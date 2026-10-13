'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { boot, HOY, MANANA, PASADO } = require('./helpers');

describe('Pruebas funcionales (caja negra) - flujo principal', () => {
  let t;
  before(async () => { t = await boot(); });
  after(async () => { await t.close(); });

  it('CP-01 registro válido crea cuenta JUGADOR con contraseña hasheada y teléfono cifrado', async () => {
    const c = t.client();
    const r = await c.post('/api/auth/registro', {
      nombre: 'Ana Pérez', email: 'ana@correo.cl', telefono: '+56912345678',
      password: 'ClaveSegura123', acepta_privacidad: true
    });
    assert.equal(r.status, 201);
    assert.equal(r.json.usuario.rol, 'JUGADOR');
    const row = t.db.prepare('SELECT * FROM usuarios WHERE email = ?').get('ana@correo.cl');
    assert.match(row.password_hash, /^\$2[aby]\$/);
    assert.ok(!row.password_hash.includes('ClaveSegura123'));
    assert.ok(!row.telefono_enc.includes('12345678'));
  });

  it('CP-02 login válido entrega cookie HttpOnly + SameSite=Strict y /me devuelve el teléfono descifrado', async () => {
    const c = t.client();
    const r = await c.post('/api/auth/login', { email: 'jugador@correo.cl', password: t.creds['jugador@correo.cl'] });
    assert.equal(r.status, 200);
    const cookie = r.setCookie.join(';');
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=Strict/i);
    const me = await c.get('/api/auth/me');
    assert.equal(me.status, 200);
    assert.equal(me.json.usuario.telefono, '+56933333333');
    assert.ok(!me.text.includes('password'));
  });

  it('CP-03 catálogo filtra por deporte y comuna', async () => {
    const c = t.client();
    const padel = await c.get('/api/canchas?deporte=' + encodeURIComponent('Pádel'));
    assert.equal(padel.json.canchas.length, 2);
    const f7 = await c.get('/api/canchas?deporte=' + encodeURIComponent('Fútbol 7'));
    assert.equal(f7.json.canchas.length, 2);
    const todas = await c.get('/api/canchas?comuna=' + encodeURIComponent('Los Ángeles'));
    assert.equal(todas.json.canchas.length, 5);
  });

  it('CP-04 disponibilidad de una cancha futura muestra todos sus bloques libres con precio', async () => {
    const r = await t.client().get(`/api/canchas/1/disponibilidad?fecha=${PASADO}`);
    assert.equal(r.status, 200);
    assert.equal(r.json.bloques.length, 14); // 9:00 a 23:00
    assert.ok(r.json.bloques.every((b) => b.estado === 'libre' && b.precio === 12000));
  });

  it('CP-05 reservar un bloque libre crea la reserva SOLICITADA con el monto del servidor y lo marca ocupado', async () => {
    const j = await t.jugador();
    const r = await j.post('/api/reservas', { cancha_id: 1, fecha: PASADO, hora_inicio: 18 });
    assert.equal(r.status, 201);
    assert.equal(r.json.reserva.estado, 'SOLICITADA');
    assert.equal(r.json.reserva.monto, 12000);
    assert.match(r.json.reserva.codigo, /^[0-9A-F]{8}$/);
    const disp = await t.client().get(`/api/canchas/1/disponibilidad?fecha=${PASADO}`);
    assert.equal(disp.json.bloques.find((b) => b.hora_inicio === 18).estado, 'ocupado');
  });

  it('CP-06 pagar con tarjeta válida deja la reserva PAGADA, registra el pago y NO guarda la tarjeta', async () => {
    const j = await t.jugador();
    const res = await j.post('/api/reservas', { cancha_id: 2, fecha: PASADO, hora_inicio: 19 });
    const id = res.json.reserva.id;
    const p = await j.post(`/api/reservas/${id}/pagar`, { medio: 'webpay_simulado', tarjeta: '4242 4242 4242 4242' });
    assert.equal(p.status, 200);
    assert.equal(p.json.reserva.estado, 'PAGADA');
    const pago = t.db.prepare('SELECT * FROM pagos WHERE reserva_id = ?').get(id);
    assert.equal(pago.estado, 'APROBADO');
    assert.match(pago.referencia, /^WP-/);
    const volcado = t.db.serialize().toString('latin1');
    assert.ok(!volcado.includes('4242424242424242'), 'el número de tarjeta no debe persistirse');
    assert.ok(!volcado.includes('4242 4242 4242 4242'));
  });

  it('CP-07 un pago rechazado mantiene la reserva SOLICITADA y permite reintentar', async () => {
    const j = await t.jugador();
    const res = await j.post('/api/reservas', { cancha_id: 2, fecha: PASADO, hora_inicio: 20 });
    const id = res.json.reserva.id;
    const mal = await j.post(`/api/reservas/${id}/pagar`, { medio: 'webpay_simulado', tarjeta: '4000000000000002' });
    assert.equal(mal.status, 402);
    assert.equal(t.db.prepare('SELECT estado FROM reservas WHERE id = ?').get(id).estado, 'SOLICITADA');
    const ok = await j.post(`/api/reservas/${id}/pagar`, { medio: 'webpay_simulado', tarjeta: '4242424242424242' });
    assert.equal(ok.status, 200);
    assert.equal(ok.json.reserva.estado, 'PAGADA');
  });

  it('CP-08 pagar en el recinto deja la reserva CONFIRMADA con pago PENDIENTE', async () => {
    const j = await t.jugador();
    const res = await j.post('/api/reservas', { cancha_id: 3, fecha: PASADO, hora_inicio: 10 });
    const p = await j.post(`/api/reservas/${res.json.reserva.id}/pagar`, { medio: 'en_recinto' });
    assert.equal(p.status, 200);
    assert.equal(p.json.reserva.estado, 'CONFIRMADA');
    assert.equal(t.db.prepare('SELECT estado FROM pagos WHERE reserva_id = ?').get(res.json.reserva.id).estado, 'PENDIENTE');
  });

  it('CP-09 "mis reservas" lista solo las reservas del usuario autenticado', async () => {
    const a = await t.jugador();
    const b = await t.jugador();
    await a.post('/api/reservas', { cancha_id: 3, fecha: PASADO, hora_inicio: 11 });
    const ra = await a.get('/api/reservas/mias');
    const rb = await b.get('/api/reservas/mias');
    assert.equal(ra.json.reservas.length, 1);
    assert.equal(rb.json.reservas.length, 0);
  });

  it('CP-10 cancelar con 24 h o más de anticipación devuelve el 100 %; con menos, 0 %', async () => {
    const j = await t.jugador();
    // Mañana 12:00 = exactamente 24 h desde "ahora" (lunes 12:00) -> devolución total
    const r1 = await j.post('/api/reservas', { cancha_id: 4, fecha: MANANA, hora_inicio: 12 });
    await j.post(`/api/reservas/${r1.json.reserva.id}/pagar`, { medio: 'webpay_simulado', tarjeta: '4242424242424242' });
    const c1 = await j.post(`/api/reservas/${r1.json.reserva.id}/cancelar`);
    assert.equal(c1.status, 200);
    assert.equal(c1.json.devolucion, 14000);
    assert.equal(t.db.prepare('SELECT estado FROM pagos WHERE reserva_id = ?').get(r1.json.reserva.id).estado, 'REEMBOLSADO');
    // Mañana 11:00 = 23 h -> sin devolución
    const r2 = await j.post('/api/reservas', { cancha_id: 4, fecha: MANANA, hora_inicio: 11 });
    await j.post(`/api/reservas/${r2.json.reserva.id}/pagar`, { medio: 'webpay_simulado', tarjeta: '4242424242424242' });
    const c2 = await j.post(`/api/reservas/${r2.json.reserva.id}/cancelar`);
    assert.equal(c2.status, 200);
    assert.equal(c2.json.devolucion, 0);
  });

  it('CP-11 una reserva sin pago se cancela a los 10 minutos, libera el bloque y ya no admite pago', async () => {
    const j = await t.jugador();
    const res = await j.post('/api/reservas', { cancha_id: 5, fecha: PASADO, hora_inicio: 15 });
    const id = res.json.reserva.id;
    t.clock.advanceMin(11);
    const disp = await t.client().get(`/api/canchas/5/disponibilidad?fecha=${PASADO}`);
    assert.equal(disp.json.bloques.find((b) => b.hora_inicio === 15).estado, 'libre');
    const p = await j.post(`/api/reservas/${id}/pagar`, { medio: 'en_recinto' });
    assert.equal(p.status, 409);
    // el bloque liberado puede ser tomado por otra persona
    const otro = await t.jugador();
    const r2 = await otro.post('/api/reservas', { cancha_id: 5, fecha: PASADO, hora_inicio: 15 });
    assert.equal(r2.status, 201);
    t.clock.advanceMin(-11);
  });

  it('CP-12 el administrador crea cancha, registra reserva presencial, la completa y consulta el calendario', async () => {
    const adm = await t.admin();
    const nueva = await adm.post('/api/recinto/canchas', { nombre: 'Cancha 4', deporte: 'Fútbol 5', precio_hora: 8000, hora_apertura: 10, hora_cierre: 22 });
    assert.equal(nueva.status, 201);
    const pres = await adm.post('/api/recinto/reservas-presenciales', { cancha_id: nueva.json.cancha.id, fecha: PASADO, hora_inicio: 20, cliente_nombre: 'Equipo Los Pumas' });
    assert.equal(pres.status, 201);
    assert.equal(pres.json.reserva.estado, 'CONFIRMADA');
    const cal = await adm.get(`/api/recinto/reservas?fecha=${PASADO}`);
    assert.equal(cal.status, 200);
    assert.ok(cal.json.reservas.some((r) => r.id === pres.json.reserva.id && r.cliente === 'Equipo Los Pumas'));
    assert.ok(cal.json.resumen.bloques_totales > 0);
    // todavía no comienza el bloque -> no se puede marcar completada
    const antes = await adm.post(`/api/recinto/reservas/${pres.json.reserva.id}/estado`, { estado: 'COMPLETADA' });
    assert.equal(antes.status, 409);
    t.clock.set(new Date(2026, 9, 14, 22, 0, 0));
    const ok = await adm.post(`/api/recinto/reservas/${pres.json.reserva.id}/estado`, { estado: 'COMPLETADA' });
    assert.equal(ok.status, 200);
    t.clock.set(new Date(2026, 9, 12, 12, 0, 0));
  });

  it('CP-13 eliminar la cuenta anonimiza los datos personales, exige contraseña y no se puede con reservas activas', async () => {
    const j = await t.jugador('elim');
    const res = await j.post('/api/reservas', { cancha_id: 5, fecha: PASADO, hora_inicio: 16 });
    const sinClave = await j.post('/api/auth/eliminar-cuenta', { password: 'ClaveIncorrecta1' });
    assert.equal(sinClave.status, 401);
    const conActiva = await j.post('/api/auth/eliminar-cuenta', { password: 'ClaveSegura123' });
    assert.equal(conActiva.status, 409);
    await j.post(`/api/reservas/${res.json.reserva.id}/cancelar`);
    const ok = await j.post('/api/auth/eliminar-cuenta', { password: 'ClaveSegura123' });
    assert.equal(ok.status, 200);
    const fila = t.db.prepare('SELECT * FROM usuarios WHERE id = ?').get(j.userId);
    assert.equal(fila.nombre, 'Usuario eliminado');
    assert.ok(!fila.email.includes(j.email) && fila.email.endsWith('@eliminado.invalid'));
    // la persona ya no puede iniciar sesión y la reserva histórica se conserva sin datos personales
    assert.equal((await t.client().post('/api/auth/login', { email: j.email, password: 'ClaveSegura123' })).status, 401);
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM reservas WHERE jugador_id = ?').get(j.userId).n, 1);
  });
});
