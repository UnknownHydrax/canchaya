'use strict';
const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS usuarios (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre           TEXT    NOT NULL,
  email            TEXT    NOT NULL UNIQUE,
  telefono_enc     TEXT    NOT NULL,            -- cifrado AES-256-GCM (ISO 27001 / Ley 19.628)
  password_hash    TEXT    NOT NULL,            -- bcrypt, nunca la contraseña en claro
  rol              TEXT    NOT NULL CHECK (rol IN ('JUGADOR','ADMIN_RECINTO')),
  intentos_fallidos INTEGER NOT NULL DEFAULT 0,
  token_version    INTEGER NOT NULL DEFAULT 0,  -- se incrementa al cerrar sesión: invalida los tokens emitidos
  bloqueado_hasta  INTEGER,                     -- epoch ms
  creado_en        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS recintos (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre    TEXT NOT NULL,
  comuna    TEXT NOT NULL,
  direccion TEXT NOT NULL,
  admin_id  INTEGER NOT NULL REFERENCES usuarios(id)
);

CREATE TABLE IF NOT EXISTS canchas (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  recinto_id    INTEGER NOT NULL REFERENCES recintos(id),
  nombre        TEXT    NOT NULL,
  deporte       TEXT    NOT NULL,
  precio_hora   INTEGER NOT NULL CHECK (precio_hora > 0),
  hora_apertura INTEGER NOT NULL CHECK (hora_apertura BETWEEN 0 AND 23),
  hora_cierre   INTEGER NOT NULL CHECK (hora_cierre BETWEEN 1 AND 24),
  activa        INTEGER NOT NULL DEFAULT 1,
  CHECK (hora_cierre > hora_apertura)
);

CREATE TABLE IF NOT EXISTS reservas (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  codigo         TEXT    NOT NULL UNIQUE,
  cancha_id      INTEGER NOT NULL REFERENCES canchas(id),
  jugador_id     INTEGER REFERENCES usuarios(id),   -- NULL en reservas presenciales
  cliente_nombre TEXT,                              -- solo reservas presenciales
  origen         TEXT    NOT NULL DEFAULT 'APP' CHECK (origen IN ('APP','PRESENCIAL')),
  fecha          TEXT    NOT NULL,                  -- YYYY-MM-DD
  hora_inicio    INTEGER NOT NULL,                  -- bloque de 1 hora
  estado         TEXT    NOT NULL CHECK (estado IN
                   ('SOLICITADA','CONFIRMADA','PAGADA','CANCELADA','COMPLETADA','NO_PRESENTADA')),
  monto          INTEGER NOT NULL CHECK (monto > 0),
  creada_en      INTEGER NOT NULL
);

-- Garantía a nivel de base de datos contra dobles reservas (RF-08):
-- un mismo bloque no puede estar tomado dos veces por reservas "vivas".
CREATE UNIQUE INDEX IF NOT EXISTS ux_bloque_ocupado
  ON reservas (cancha_id, fecha, hora_inicio)
  WHERE estado IN ('SOLICITADA','CONFIRMADA','PAGADA','COMPLETADA','NO_PRESENTADA');

CREATE INDEX IF NOT EXISTS ix_reservas_jugador ON reservas (jugador_id);
CREATE INDEX IF NOT EXISTS ix_reservas_fecha   ON reservas (cancha_id, fecha);

CREATE TABLE IF NOT EXISTS pagos (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  reserva_id INTEGER NOT NULL REFERENCES reservas(id),
  monto      INTEGER NOT NULL,
  medio      TEXT    NOT NULL,
  estado     TEXT    NOT NULL CHECK (estado IN ('APROBADO','RECHAZADO','PENDIENTE','REEMBOLSADO')),
  referencia TEXT,                                  -- id de transacción; NUNCA datos de tarjeta
  creado_en  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auditoria (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  usuario_id INTEGER,
  accion     TEXT    NOT NULL,
  detalle    TEXT,
  ip         TEXT
);
`;

function openDb(dbPath) {
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
  }
  const db = new Database(dbPath);
  db.pragma('foreign_keys = ON');
  if (dbPath !== ':memory:') db.pragma('journal_mode = WAL');
  db.exec(SCHEMA);
  // Migración simple para bases creadas antes de agregar token_version.
  const cols = db.prepare('PRAGMA table_info(usuarios)').all().map((c) => c.name);
  if (!cols.includes('token_version')) db.exec('ALTER TABLE usuarios ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0');
  return db;
}

module.exports = { openDb };
