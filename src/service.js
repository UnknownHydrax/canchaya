'use strict';
const crypto = require('node:crypto');
const { HttpError } = require('./errors');

// Reglas de negocio de reservas, compartidas por las rutas de jugador y de administrador.

function inicioBloque(fecha, hora) {
  const [y, m, d] = fecha.split('-').map(Number);
  return new Date(y, m - 1, d, hora, 0, 0, 0);
}

// RF-11: una reserva solicitada y no pagada se cancela sola pasados N minutos y libera el bloque.
function expirarSolicitudes(db, config, now) {
  const limite = now().getTime() - config.solicitudTtlMin * 60 * 1000;
  return db.prepare("UPDATE reservas SET estado = 'CANCELADA' WHERE estado = 'SOLICITADA' AND creada_en < ?").run(limite).changes;
}

function generarCodigo() {
  return crypto.randomBytes(4).toString('hex').toUpperCase(); // 8 caracteres, no adivinable
}

/**
 * Crea una reserva dentro de una transacción.
 * El precio SIEMPRE se toma de la base de datos (integridad: el cliente no puede fijar el monto).
 * La unicidad del bloque la garantiza el índice único parcial ux_bloque_ocupado (RF-08).
 */
function crearReserva(ctx, { canchaId, fecha, hora, jugadorId = null, clienteNombre = null, origen = 'APP', estado = 'SOLICITADA', recintoId = null }) {
  const { db, config, now } = ctx;
  const tx = db.transaction(() => {
    expirarSolicitudes(db, config, now);
    const cancha = db.prepare('SELECT * FROM canchas WHERE id = ? AND activa = 1').get(canchaId);
    if (!cancha || (recintoId !== null && cancha.recinto_id !== recintoId)) throw new HttpError(404, 'Cancha no encontrada');
    if (hora < cancha.hora_apertura || hora >= cancha.hora_cierre) {
      throw new HttpError(400, `El horario de esta cancha es de ${cancha.hora_apertura}:00 a ${cancha.hora_cierre}:00`);
    }
    if (inicioBloque(fecha, hora) <= now()) throw new HttpError(400, 'El bloque horario ya comenzó o pasó');
    try {
      const info = db.prepare(`INSERT INTO reservas
        (codigo, cancha_id, jugador_id, cliente_nombre, origen, fecha, hora_inicio, estado, monto, creada_en)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(generarCodigo(), cancha.id, jugadorId, clienteNombre, origen, fecha, hora, estado, cancha.precio_hora, now().getTime());
      return db.prepare('SELECT * FROM reservas WHERE id = ?').get(info.lastInsertRowid);
    } catch (e) {
      if (e && typeof e.code === 'string' && e.code.startsWith('SQLITE_CONSTRAINT')) {
        throw new HttpError(409, 'Ese bloque ya fue reservado. Elija otro horario.');
      }
      throw e;
    }
  });
  return tx();
}

function vistaReserva(r) {
  return {
    id: r.id, codigo: r.codigo, fecha: r.fecha, hora_inicio: r.hora_inicio, hora_fin: r.hora_inicio + 1,
    estado: r.estado, monto: r.monto, origen: r.origen,
    cancha: r.cancha_nombre, deporte: r.deporte, recinto: r.recinto_nombre
  };
}

module.exports = { inicioBloque, expirarSolicitudes, crearReserva, vistaReserva };
