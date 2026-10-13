'use strict';
const express = require('express');
const v = require('../validate');
const { HttpError } = require('../errors');
const { expirarSolicitudes, inicioBloque } = require('../service');

module.exports = function canchasRoutes(ctx) {
  const { db, config, now } = ctx;
  const router = express.Router();

  // Catálogo público (sin datos personales). Filtros validados y consultas parametrizadas.
  router.get('/', (req, res) => {
    const where = ['c.activa = 1'];
    const params = [];
    if (req.query.deporte !== undefined) { where.push('c.deporte = ?'); params.push(v.texto(req.query.deporte, 'Deporte')); }
    if (req.query.comuna !== undefined) { where.push('r.comuna = ?'); params.push(v.texto(req.query.comuna, 'Comuna')); }
    const rows = db.prepare(`
      SELECT c.id, c.nombre, c.deporte, c.precio_hora, c.hora_apertura, c.hora_cierre,
             r.nombre AS recinto, r.comuna, r.direccion
      FROM canchas c JOIN recintos r ON r.id = c.recinto_id
      WHERE ${where.join(' AND ')}
      ORDER BY r.nombre, c.nombre`).all(...params);
    res.json({ canchas: rows });
  });

  router.get('/:id/disponibilidad', (req, res) => {
    const id = v.id(req.params.id, 'La cancha');
    const fecha = v.fecha(req.query.fecha, { hoy: now(), maxDias: config.maxDiasAnticipacion });
    expirarSolicitudes(db, config, now);
    const cancha = db.prepare('SELECT * FROM canchas WHERE id = ? AND activa = 1').get(id);
    if (!cancha) throw new HttpError(404, 'Cancha no encontrada');
    const ocupadas = new Set(db.prepare(`SELECT hora_inicio FROM reservas
      WHERE cancha_id = ? AND fecha = ? AND estado IN ('SOLICITADA','CONFIRMADA','PAGADA','COMPLETADA','NO_PRESENTADA')`)
      .all(id, fecha).map((r) => r.hora_inicio));
    const bloques = [];
    for (let h = cancha.hora_apertura; h < cancha.hora_cierre; h++) {
      let estado = 'libre';
      if (inicioBloque(fecha, h) <= now()) estado = 'pasado';
      else if (ocupadas.has(h)) estado = 'ocupado';
      bloques.push({ hora_inicio: h, hora_fin: h + 1, estado, precio: cancha.precio_hora });
    }
    res.json({ cancha: { id: cancha.id, nombre: cancha.nombre, deporte: cancha.deporte }, fecha, bloques });
  });

  return router;
};
