'use strict';
const crypto = require('node:crypto');
const express = require('express');
const v = require('../validate');
const { HttpError } = require('../errors');
const { authenticate, requireRole } = require('../security');
const { expirarSolicitudes, crearReserva, inicioBloque, vistaReserva } = require('../service');

const SELECT_VISTA = `
  SELECT r.*, c.nombre AS cancha_nombre, c.deporte, rc.nombre AS recinto_nombre
  FROM reservas r JOIN canchas c ON c.id = r.cancha_id JOIN recintos rc ON rc.id = c.recinto_id`;

// Pasarela de pagos SIMULADA (en producción: Webpay Plus de Transbank).
// Por diseño NO se guarda ni se registra el número de tarjeta (PCI DSS / RNF-07).
const TARJETA_RECHAZO_PRUEBA = '4000000000000002';
function pasarelaSimulada(numeroTarjeta) {
  if (numeroTarjeta === TARJETA_RECHAZO_PRUEBA) return { aprobado: false };
  return { aprobado: true, referencia: 'WP-' + crypto.randomBytes(6).toString('hex').toUpperCase() };
}

module.exports = function reservasRoutes(ctx) {
  const { db, config, now, audit } = ctx;
  const router = express.Router();
  router.use(authenticate(db, config), requireRole('JUGADOR'));

  // Obtiene una reserva SOLO si pertenece al usuario autenticado (OWASP A01: evita IDOR).
  function reservaPropia(req) {
    const id = v.id(req.params.id, 'La reserva');
    const r = db.prepare(`${SELECT_VISTA} WHERE r.id = ? AND r.jugador_id = ?`).get(id, req.user.id);
    if (!r) throw new HttpError(404, 'Reserva no encontrada');
    return r;
  }

  router.post('/', (req, res) => {
    const body = req.body || {};
    const canchaId = v.id(body.cancha_id, 'La cancha');
    const fecha = v.fecha(body.fecha, { hoy: now(), maxDias: config.maxDiasAnticipacion });
    const hora = v.entero(body.hora_inicio, 'La hora de inicio', { min: 0, max: 23 });
    // Observe que NO se lee "monto" ni "estado" del cuerpo: los decide el servidor.
    const reserva = crearReserva(ctx, { canchaId, fecha, hora, jugadorId: req.user.id });
    audit(req, 'RESERVA_CREADA', { detalle: `reserva ${reserva.codigo}` });
    const vista = db.prepare(`${SELECT_VISTA} WHERE r.id = ?`).get(reserva.id);
    res.status(201).json({ reserva: vistaReserva(vista), vence_en_min: config.solicitudTtlMin });
  });

  router.get('/mias', (req, res) => {
    expirarSolicitudes(db, config, now);
    const rows = db.prepare(`${SELECT_VISTA} WHERE r.jugador_id = ? ORDER BY r.fecha DESC, r.hora_inicio DESC`).all(req.user.id);
    res.json({ reservas: rows.map(vistaReserva) });
  });

  router.post('/:id/pagar', (req, res) => {
    expirarSolicitudes(db, config, now);
    const reserva = reservaPropia(req);
    if (reserva.estado !== 'SOLICITADA') throw new HttpError(409, `La reserva está ${reserva.estado.toLowerCase()} y no admite pago`);
    const medio = (req.body || {}).medio;

    if (medio === 'en_recinto') {
      db.transaction(() => {
        db.prepare("UPDATE reservas SET estado = 'CONFIRMADA' WHERE id = ?").run(reserva.id);
        db.prepare("INSERT INTO pagos (reserva_id, monto, medio, estado, referencia, creado_en) VALUES (?, ?, 'en_recinto', 'PENDIENTE', NULL, ?)")
          .run(reserva.id, reserva.monto, now().getTime());
      })();
      audit(req, 'RESERVA_CONFIRMADA_PAGO_RECINTO', { detalle: `reserva ${reserva.codigo}` });
      return res.json({ reserva: { ...vistaReserva(reserva), estado: 'CONFIRMADA' } });
    }

    if (medio === 'webpay_simulado') {
      const tarjeta = v.tarjeta((req.body || {}).tarjeta);
      const r = pasarelaSimulada(tarjeta);          // el número de tarjeta no sale de esta función
      if (!r.aprobado) {
        db.prepare("INSERT INTO pagos (reserva_id, monto, medio, estado, referencia, creado_en) VALUES (?, ?, 'webpay_simulado', 'RECHAZADO', NULL, ?)")
          .run(reserva.id, reserva.monto, now().getTime());
        audit(req, 'PAGO_RECHAZADO', { detalle: `reserva ${reserva.codigo}` });
        throw new HttpError(402, 'Pago rechazado por el emisor. Puede reintentar con otra tarjeta.');
      }
      db.transaction(() => {
        db.prepare("UPDATE reservas SET estado = 'PAGADA' WHERE id = ?").run(reserva.id);
        db.prepare("INSERT INTO pagos (reserva_id, monto, medio, estado, referencia, creado_en) VALUES (?, ?, 'webpay_simulado', 'APROBADO', ?, ?)")
          .run(reserva.id, reserva.monto, r.referencia, now().getTime());
      })();
      audit(req, 'PAGO_APROBADO', { detalle: `reserva ${reserva.codigo} ref ${r.referencia}` });
      return res.json({ reserva: { ...vistaReserva(reserva), estado: 'PAGADA' }, comprobante: { referencia: r.referencia, monto: reserva.monto } });
    }

    throw new HttpError(400, 'Medio de pago no válido');
  });

  router.post('/:id/cancelar', (req, res) => {
    expirarSolicitudes(db, config, now);
    const reserva = reservaPropia(req);
    if (!['SOLICITADA', 'CONFIRMADA', 'PAGADA'].includes(reserva.estado)) {
      throw new HttpError(409, `La reserva está ${reserva.estado.toLowerCase()} y no se puede cancelar`);
    }
    const inicio = inicioBloque(reserva.fecha, reserva.hora_inicio);
    if (inicio <= now()) throw new HttpError(409, 'El bloque ya comenzó: no se puede cancelar');
    const horasHasta = (inicio - now()) / 3600000;
    // Política de cancelación del MVP: devolución total si se cancela con 24 horas o más de anticipación.
    const devolucion = reserva.estado === 'PAGADA' && horasHasta >= config.horasCancelacionGratis ? reserva.monto : 0;
    db.transaction(() => {
      db.prepare("UPDATE reservas SET estado = 'CANCELADA' WHERE id = ?").run(reserva.id);
      if (devolucion > 0) {
        db.prepare("UPDATE pagos SET estado = 'REEMBOLSADO' WHERE reserva_id = ? AND estado = 'APROBADO'").run(reserva.id);
      }
    })();
    audit(req, 'RESERVA_CANCELADA', { detalle: `reserva ${reserva.codigo} devolución ${devolucion}` });
    res.json({ reserva: { ...vistaReserva(reserva), estado: 'CANCELADA' }, devolucion });
  });

  return router;
};
