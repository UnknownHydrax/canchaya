'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { boot, HOY, PASADO } = require('./helpers');

describe('Pruebas de valores límite y validación de entradas', () => {
  let t;
  before(async () => { t = await boot(); });
  after(async () => { await t.close(); });

  it('CL-01 horas en el borde del horario: 8 y 23 se rechazan; 9 y 22 se aceptan (cancha abierta de 9 a 23)', async () => {
    const j = await t.jugador();
    for (const h of [8, 23]) {
      const r = await j.post('/api/reservas', { cancha_id: 1, fecha: PASADO, hora_inicio: h });
      assert.equal(r.status, 400, `hora ${h}`);
    }
    for (const h of [9, 22]) {
      const r = await j.post('/api/reservas', { cancha_id: 1, fecha: PASADO, hora_inicio: h });
      assert.equal(r.status, 201, `hora ${h}`);
    }
  });

  it('CL-02 fechas inválidas: pasada, más allá de 60 días, inexistente, texto y bloque ya iniciado hoy', async () => {
    const j = await t.jugador();
    const casos = [
      ['2026-10-11', 'fecha pasada'],
      ['2026-12-12', 'más de 60 días'],
      ['2026-02-30', 'fecha inexistente'],
      ['mañana', 'texto'],
      ['2026/10/14', 'formato incorrecto']
    ];
    for (const [fecha, desc] of casos) {
      const r = await j.post('/api/reservas', { cancha_id: 1, fecha, hora_inicio: 15 });
      assert.equal(r.status, 400, desc);
    }
    const yaIniciado = await j.post('/api/reservas', { cancha_id: 1, fecha: HOY, hora_inicio: 10 });
    assert.equal(yaIniciado.status, 400);
    const limiteOk = await j.post('/api/reservas', { cancha_id: 1, fecha: '2026-12-11', hora_inicio: 15 }); // día 60
    assert.equal(limiteOk.status, 201);
  });

  it('CL-03 hora de inicio no entera o fuera de 0-23 se rechaza', async () => {
    const j = await t.jugador();
    for (const h of [19.5, '19abc', null, -1, 24, '', [19], { a: 1 }]) {
      const r = await j.post('/api/reservas', { cancha_id: 1, fecha: PASADO, hora_inicio: h });
      assert.equal(r.status, 400, `hora ${JSON.stringify(h)}`);
    }
  });

  it('CL-04 precio de cancha negativo, cero, bajo el mínimo, texto o exagerado se rechaza', async () => {
    const adm = await t.admin();
    for (const precio of [-5000, 0, 999, 'mucho', 1e9, null, 12000.5]) {
      const r = await adm.post('/api/recinto/canchas', { nombre: 'Cancha X', deporte: 'Fútbol 5', precio_hora: precio, hora_apertura: 9, hora_cierre: 22 });
      assert.equal(r.status, 400, `precio ${JSON.stringify(precio)}`);
    }
    const mal = await adm.post('/api/recinto/canchas', { nombre: 'Cancha X', deporte: 'Fútbol 5', precio_hora: 8000, hora_apertura: 22, hora_cierre: 9 });
    assert.equal(mal.status, 400);
    const ok = await adm.post('/api/recinto/canchas', { nombre: 'Cancha X', deporte: 'Fútbol 5', precio_hora: 1000, hora_apertura: 9, hora_cierre: 22 });
    assert.equal(ok.status, 201);
  });

  it('CL-05 registro con datos inválidos (contraseña débil, correo, nombre, teléfono, sin consentimiento) se rechaza', async () => {
    const base = { nombre: 'Luis Soto', email: 'luis@correo.cl', telefono: '+56912345678', password: 'ClaveSegura123', acepta_privacidad: true };
    const malos = [
      [{ password: 'Corta1A' }, 'contraseña corta'],
      [{ password: 'todominusculas123' }, 'sin mayúscula'],
      [{ password: 'SinNumerosAquiXY' }, 'sin número'],
      [{ password: 'A'.repeat(73) + 'a1' }, 'contraseña de más de 72'],
      [{ email: 'no-es-correo' }, 'correo inválido'],
      [{ email: 'a@b' }, 'correo sin dominio'],
      [{ nombre: '' }, 'nombre vacío'],
      [{ nombre: 'A' }, 'nombre de 1 letra'],
      [{ telefono: 'abc' }, 'teléfono texto'],
      [{ telefono: '12345' }, 'teléfono corto'],
      [{ acepta_privacidad: false }, 'sin consentimiento'],
      [{ acepta_privacidad: 'true' }, 'consentimiento como texto']
    ];
    for (const [cambio, desc] of malos) {
      const r = await t.client().post('/api/auth/registro', { ...base, ...cambio });
      assert.equal(r.status, 400, desc);
    }
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM usuarios WHERE email = ?').get('luis@correo.cl').n, 0);
  });

  it('CL-06 correo duplicado se rechaza con mensaje neutro (sin confirmar que la cuenta existe)', async () => {
    const body = { nombre: 'Rosa Díaz', email: 'rosa@correo.cl', telefono: '+56912345678', password: 'ClaveSegura123', acepta_privacidad: true };
    assert.equal((await t.client().post('/api/auth/registro', body)).status, 201);
    const dup = await t.client().post('/api/auth/registro', body);
    assert.equal(dup.status, 409);
    assert.ok(!/ya existe|ya est[áa] registrado/i.test(dup.json.error));
  });

  it('CL-07 cuerpo de más de 10 KB se rechaza con 413', async () => {
    const r = await t.client().post('/api/auth/login', { email: 'a@b.cl', password: 'x'.repeat(20000) });
    assert.equal(r.status, 413);
  });

  it('CL-08 20 solicitudes simultáneas al mismo bloque: exactamente una reserva se crea', async () => {
    const jugadores = await Promise.all(Array.from({ length: 20 }, () => t.jugador('conc')));
    const resp = await Promise.all(jugadores.map((j) => j.post('/api/reservas', { cancha_id: 4, fecha: PASADO, hora_inicio: 21 })));
    const ok = resp.filter((r) => r.status === 201).length;
    const conflicto = resp.filter((r) => r.status === 409).length;
    assert.equal(ok, 1);
    assert.equal(conflicto, 19);
    assert.equal(t.db.prepare("SELECT COUNT(*) n FROM reservas WHERE cancha_id = 4 AND fecha = ? AND hora_inicio = 21").get(PASADO).n, 1);
  });

  it('CL-09 bloques consecutivos de la misma cancha no se bloquean entre sí', async () => {
    const j = await t.jugador();
    const a = await j.post('/api/reservas', { cancha_id: 5, fecha: PASADO, hora_inicio: 12 });
    const b = await j.post('/api/reservas', { cancha_id: 5, fecha: PASADO, hora_inicio: 13 });
    assert.equal(a.status, 201);
    assert.equal(b.status, 201);
  });

  it('CL-10 tarjetas con formato inválido o dígito verificador incorrecto se rechazan sin crear pago', async () => {
    const j = await t.jugador();
    const res = await j.post('/api/reservas', { cancha_id: 3, fecha: PASADO, hora_inicio: 15 });
    const id = res.json.reserva.id;
    for (const tarjeta of ['1234', '4242424242424241', 'abcdabcdabcdabcd', '', null, 4242424242424242]) {
      const r = await j.post(`/api/reservas/${id}/pagar`, { medio: 'webpay_simulado', tarjeta });
      assert.equal(r.status, 400, `tarjeta ${JSON.stringify(tarjeta)}`);
    }
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM pagos WHERE reserva_id = ?').get(id).n, 0);
    const medio = await j.post(`/api/reservas/${id}/pagar`, { medio: 'bitcoin' });
    assert.equal(medio.status, 400);
  });

  it('CL-11 identificadores inválidos o inexistentes: 400 y 404 respectivamente', async () => {
    const j = await t.jugador();
    assert.equal((await j.post('/api/reservas/abc/pagar', { medio: 'en_recinto' })).status, 400);
    assert.equal((await j.post('/api/reservas/-1/cancelar')).status, 400);
    assert.equal((await j.post('/api/reservas/999999/pagar', { medio: 'en_recinto' })).status, 404);
    assert.equal((await j.post('/api/reservas', { cancha_id: 0, fecha: PASADO, hora_inicio: 15 })).status, 400);
    assert.equal((await j.post('/api/reservas', { cancha_id: 999, fecha: PASADO, hora_inicio: 15 })).status, 404);
    assert.equal((await t.client().get(`/api/canchas/xyz/disponibilidad?fecha=${PASADO}`)).status, 400);
  });

  it('CL-12 pagar dos veces la misma reserva: el segundo intento se rechaza y queda un solo pago', async () => {
    const j = await t.jugador();
    const res = await j.post('/api/reservas', { cancha_id: 3, fecha: PASADO, hora_inicio: 17 });
    const id = res.json.reserva.id;
    const dobles = await Promise.all([1, 2, 3].map(() => j.post(`/api/reservas/${id}/pagar`, { medio: 'webpay_simulado', tarjeta: '4242424242424242' })));
    assert.equal(dobles.filter((r) => r.status === 200).length, 1);
    assert.equal(dobles.filter((r) => r.status === 409).length, 2);
    assert.equal(t.db.prepare("SELECT COUNT(*) n FROM pagos WHERE reserva_id = ? AND estado = 'APROBADO'").get(id).n, 1);
  });
});
