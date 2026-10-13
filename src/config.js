'use strict';
// Zona horaria del negocio (los bloques horarios son hora local de Chile).
process.env.TZ = process.env.TZ || 'America/Santiago';

const crypto = require('node:crypto');

/**
 * Carga la configuración desde variables de entorno.
 * ISO 27001 / OWASP A05: los secretos NO están en el código; en producción son obligatorios.
 */
function loadConfig(overrides = {}) {
  const env = process.env;
  const production = env.NODE_ENV === 'production';

  let jwtSecret = env.JWT_SECRET;
  let dataKeyHex = env.DATA_KEY;

  if (production) {
    if (!jwtSecret || jwtSecret.length < 32) {
      throw new Error('JWT_SECRET es obligatorio en producción (mínimo 32 caracteres).');
    }
    if (!dataKeyHex || dataKeyHex.length < 32) {
      throw new Error('DATA_KEY es obligatorio en producción (mínimo 32 caracteres aleatorios).');
    }
  } else {
    // Solo desarrollo/pruebas: valores derivados para no obligar a configurar nada.
    if (!jwtSecret) jwtSecret = crypto.randomBytes(32).toString('hex');
    if (!dataKeyHex) {
      dataKeyHex = crypto.createHash('sha256').update('canchaya-solo-desarrollo').digest('hex');
      if (env.NODE_ENV !== 'test') {
        console.warn('[config] DATA_KEY no definida: usando clave de DESARROLLO. No usar en producción.');
      }
    }
  }

  const config = {
    production,
    port: Number(env.PORT) || 3000,
    dbPath: env.DB_PATH || 'data/canchaya.db',
    jwtSecret,
    // 64 hex = clave directa de 32 bytes; cualquier otra cadena larga se deriva con SHA-256 (clave AES-256).
    dataKey: /^[0-9a-fA-F]{64}$/.test(dataKeyHex) ? Buffer.from(dataKeyHex, 'hex') : crypto.createHash('sha256').update(dataKeyHex).digest(),
    jwtExpiresIn: '30m',
    bcryptRounds: Number(env.BCRYPT_ROUNDS) || 12,
    cookieSecure: production,
    rateLimit: { windowMs: 15 * 60 * 1000, authMax: 20, apiMax: 600 },
    solicitudTtlMin: 10, // una reserva sin pago se libera a los 10 minutos (RF-11)
    maxIntentosLogin: 5,
    bloqueoMin: 15,
    maxDiasAnticipacion: 60,
    horasCancelacionGratis: 24
  };
  return { ...config, ...overrides, rateLimit: { ...config.rateLimit, ...(overrides.rateLimit || {}) } };
}

module.exports = { loadConfig };
