'use strict';
const express = require('express');
const v = require('../validate');
const { HttpError } = require('../errors');
const { authenticate, requireRole } = require('../security');
const { maskPhone, decrypt } = require('../crypto');
const { expirarSolicitudes, crearReserva, inicioBloque } = require('../service');

module.exports = function recintoRoutes(ctx) {
  const { db, config, now, audit } = ctx;
  const router = express.Router();
  router.use(authenticate(db, config), requireRole('ADMIN_RECINTO'));

  // El administrador solo opera sobre SU recinto (aislamiento entre recintos, OWASP A01).
  router.use((req, _res, next) => {
    const rec = db.prepare('SELECT * FROM recintos WHERE admin_id = ?').get(req.user.id);
    if (!rec) return next(new HttpError(403, 'Su cuenta no tiene un recinto asignado'));
    req.recinto = rec;
    next();
  });

  router.get('/reservas', (req, res) => {
    expirarSolicitudes(db, config, now);
    const fecha = v.fecha(req.query.fecha, { hoy: now(), maxDias: config.maxDiasAnticipacion, permitirPasado: true });
    const canchas = db.prepare('SELECT id, nombre, deporte, precio_hora, hora_apertura, hora_cierre FROM canchas WHERE recinto_id = ? AND activa = 1 ORDER BY nombre')
      .all(req.recinto.id);
    const rows = db.prepare(`
      SELECT r.id, r.codigo, r.cancha_id, r.fecha, r.hora_inicio, r.estado, r.monto, r.origen, r.cliente_nombre,
             u.nombre AS jugador_nombre, u.telefono_enc
      FROM reservas r JOIN canchas c ON c.id = r.cancha_id LEFT JOIN usuarios u ON u.id = r.jugador_id
      WHERE c.recinto_id = ? AND r.fecha = ? AND r.estado != 'CANCELADA'
      ORDER BY r.hora_inicio, r.cancha_id`).all(req.recinto.id, fecha);

    const reservas = rows.map((r) => ({
      id: r.id, codigo: r.codigo, cancha_id: r.cancha_id, fecha: r.fecha, hora_inicio: r.hora_inicio,
      estado: r.estado, monto: r.monto, origen: r.origen,
      cliente: r.jugador_nombre || r.cliente_nombre || 'Cliente presencial',
      // Minimización de datos: el administrador ve solo los 4 últimos dígitos del teléfono.
      telefono: r.telefono_enc ? maskPhone(decrypt(r.telefono_enc, config.dataKey)) : null
    }));

    const bloquesTotales = canchas.reduce((a, c) => a + (c.hora_cierre - c.hora_apertura), 0);
    const ingresos = reservas.filter((r) => ['PAGADA', 'COMPLETADA'].includes(r.estado)).reduce((a, r) => a + r.monto, 0);
    res.json({
      recinto: { id: req.recinto.id, nombre: req.recinto.nombre },
      fecha, canchas, reservas,
      resumen: { bloques_totales: bloquesTotales, bloques_ocupados: reservas.length,
                 ocupacion_pct: bloquesTotales ? Math.round((reservas.length / bloquesTotales) * 100) : 0, ingresos }
    });
  });

  router.post('/canchas', (req, res) => {
    const b = req.body || {};
    const nombre = v.texto(b.nombre, 'El nombre de la cancha');
    const deporte = v.texto(b.deporte, 'El deporte');
    const precio = v.entero(b.precio_hora, 'El precio por hora', { min: 1000, max: 200000 });
    const apertura = v.entero(b.hora_apertura, 'La hora de apertura', { min: 0, max: 23 });
    const cierre = v.entero(b.hora_cierre, 'La hora de cierre', { min: 1, max: 24 });
    if (cierre <= apertura) throw new HttpError(400, 'La hora de cierre debe ser posterior a la de apertura');
    const info = db.prepare('INSERT INTO canchas (recinto_id, nombre, deporte, precio_hora, hora_apertura, hora_cierre) VALUES (?, ?, ?, ?, ?, ?)')
      .run(req.recinto.id, nombre, deporte, precio, apertura, cierre);
    audit(req, 'CANCHA_CREADA', { detalle: `cancha ${info.lastInsertRowid}` });
    res.status(201).json({ cancha: { id: Number(info.lastInsertRowid), nombre, deporte, precio_hora: precio, hora_apertura: apertura, hora_cierre: cierre } });
  });

  router.post('/reservas-presenciales', (req, res) => {
    const b = req.body || {};
    const canchaId = v.id(b.cancha_id, 'La cancha');
    const fecha = v.fecha(b.fecha, { hoy: now(), maxDias: config.maxDiasAnticipacion });
    const hora = v.entero(b.hora_inicio, 'La hora de inicio', { min: 0, max: 23 });
    const cliente = v.nombre(b.cliente_nombre);
    const r = crearReserva(ctx, { canchaId, fecha, hora, clienteNombre: cliente, origen: 'PRESENCIAL', estado: 'CONFIRMADA', recintoId: req.recinto.id });
    audit(req, 'RESERVA_PRESENCIAL', { detalle: `reserva ${r.codigo}` });
    res.status(201).json({ reserva: { id: r.id, codigo: r.codigo, fecha: r.fecha, hora_inicio: r.hora_inicio, estado: r.estado, monto: r.monto } });
  });

  // Reserva que pertenece a una cancha del recinto del administrador; si no, 404.
  function reservaDelRecinto(req) {
    const id = v.id(req.params.id, 'La reserva');
    const r = db.prepare(`SELECT r.* FROM reservas r JOIN canchas c ON c.id = r.cancha_id WHERE r.id = ? AND c.recinto_id = ?`).get(id, req.recinto.id);
    if (!r) throw new HttpError(404, 'Reserva no encontrada');
    return r;
  }

  router.post('/reservas/:id/estado', (req, res) => {
    const r = reservaDelRecinto(req);
    const estado = (req.body || {}).estado;
    if (!['COMPLETADA', 'NO_PRESENTADA'].includes(estado)) throw new HttpError(400, 'Estado no válido');
    if (!['CONFIRMADA', 'PAGADA'].includes(r.estado)) throw new HttpError(409, `La reserva está ${r.estado.toLowerCase()}`);
    if (inicioBloque(r.fecha, r.hora_inicio) > now()) throw new HttpError(409, 'El bloque aún no comienza');
    db.prepare('UPDATE reservas SET estado = ? WHERE id = ?').run(estado, r.id);
    audit(req, 'RESERVA_' + estado, { detalle: `reserva ${r.codigo}` });
    res.json({ reserva: { id: r.id, codigo: r.codigo, estado } });
  });

  router.post('/reservas/:id/cancelar', (req, res) => {
    const r = reservaDelRecinto(req);
    if (!['SOLICITADA', 'CONFIRMADA', 'PAGADA'].includes(r.estado)) throw new HttpError(409, `La reserva está ${r.estado.toLowerCase()}`);
    db.transaction(() => {
      db.prepare("UPDATE reservas SET estado = 'CANCELADA' WHERE id = ?").run(r.id);
      db.prepare("UPDATE pagos SET estado = 'REEMBOLSADO' WHERE reserva_id = ? AND estado = 'APROBADO'").run(r.id);
    })();
    audit(req, 'RESERVA_CANCELADA_POR_RECINTO', { detalle: `reserva ${r.codigo}` });
    res.json({ reserva: { id: r.id, codigo: r.codigo, estado: 'CANCELADA' } });
  });

  return router;
};
