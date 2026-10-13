'use strict';
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const { encrypt } = require('./crypto');

function passwordSeguro() {
  // Contraseña aleatoria fuerte (cumple la política); se muestra una sola vez en consola.
  return 'Cy' + crypto.randomBytes(9).toString('base64url') + '7a';
}

/** Carga datos de demostración si la base está vacía. No usa contraseñas fijas en el código. */
function seedIfEmpty(db, config) {
  const hay = db.prepare('SELECT COUNT(*) AS n FROM usuarios').get().n;
  if (hay > 0) return null;

  const credenciales = [];
  const now = Date.now();
  const insUser = db.prepare(`INSERT INTO usuarios (nombre, email, telefono_enc, password_hash, rol, creado_en) VALUES (?, ?, ?, ?, ?, ?)`);
  const crear = (nombre, email, tel, rol, pass) => {
    const p = pass || passwordSeguro();
    const id = insUser.run(nombre, email, encrypt(tel, config.dataKey), bcrypt.hashSync(p, config.bcryptRounds), rol, now).lastInsertRowid;
    credenciales.push({ rol, email, password: p });
    return Number(id);
  };

  const adminRetiro = crear('Administrador El Retiro', 'admin@elretiro.cl', '+56911111111', 'ADMIN_RECINTO', process.env.SEED_ADMIN_PASSWORD);
  const adminPadel = crear('Administrador Pádel Center', 'admin@padelcenter.cl', '+56922222222', 'ADMIN_RECINTO');
  crear('Jugador de Prueba', 'jugador@correo.cl', '+56933333333', 'JUGADOR');

  const insRec = db.prepare('INSERT INTO recintos (nombre, comuna, direccion, admin_id) VALUES (?, ?, ?, ?)');
  const retiro = Number(insRec.run('Complejo Deportivo El Retiro', 'Los Ángeles', 'Av. Alemania 1200', adminRetiro).lastInsertRowid);
  const padel = Number(insRec.run('Pádel Center Biobío', 'Los Ángeles', 'Calle Colo Colo 850', adminPadel).lastInsertRowid);

  const insCancha = db.prepare('INSERT INTO canchas (recinto_id, nombre, deporte, precio_hora, hora_apertura, hora_cierre) VALUES (?, ?, ?, ?, ?, ?)');
  insCancha.run(retiro, 'Cancha 1', 'Fútbol 7', 12000, 9, 23);
  insCancha.run(retiro, 'Cancha 2', 'Fútbol 7', 12000, 9, 23);
  insCancha.run(retiro, 'Cancha 3', 'Fútbol 5', 9000, 9, 23);
  insCancha.run(padel, 'Pádel A', 'Pádel', 14000, 9, 23);
  insCancha.run(padel, 'Pádel B', 'Pádel', 14000, 9, 23);

  console.log('\n=== Datos de demostración creados. Guarde estas credenciales (se muestran una sola vez) ===');
  for (const c of credenciales) console.log(`  ${c.rol.padEnd(14)} ${c.email.padEnd(26)} ${c.password}`);
  console.log('===========================================================================================\n');
  return credenciales;
}

module.exports = { seedIfEmpty };

if (require.main === module) {
  const { loadConfig } = require('./config');
  const { openDb } = require('./db');
  const cfg = loadConfig();
  const db = openDb(cfg.dbPath);
  if (!seedIfEmpty(db, cfg)) console.log('La base de datos ya tiene datos; no se cargó nada.');
  db.close();
}
