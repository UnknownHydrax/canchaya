'use strict';
const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

describe('Configuración y gestión de secretos (ISO 27001 / OWASP A05)', () => {
  const original = { ...process.env };
  afterEach(() => { process.env = { ...original }; });
  const cargar = () => { delete require.cache[require.resolve('../src/config')]; return require('../src/config').loadConfig(); };

  it('CS-23 en producción la aplicación NO arranca sin JWT_SECRET ni DATA_KEY, ni con secretos débiles', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.JWT_SECRET; delete process.env.DATA_KEY;
    assert.throws(cargar, /JWT_SECRET/);
    process.env.JWT_SECRET = 'corto';
    process.env.DATA_KEY = crypto.randomBytes(32).toString('hex');
    assert.throws(cargar, /JWT_SECRET/);
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    process.env.DATA_KEY = 'corta';
    assert.throws(cargar, /DATA_KEY/);
  });

  it('CS-24 en producción con secretos fuertes arranca con cookies Secure y clave AES de 32 bytes', () => {
    process.env.NODE_ENV = 'production';
    process.env.JWT_SECRET = crypto.randomBytes(48).toString('base64');
    process.env.DATA_KEY = crypto.randomBytes(24).toString('base64'); // formato típico de un PaaS (no hexadecimal)
    const c = cargar();
    assert.equal(c.cookieSecure, true);
    assert.equal(c.dataKey.length, 32);
  });
});
