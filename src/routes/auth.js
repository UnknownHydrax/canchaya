'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { HttpError, wrap } = require('../errors');
const v = require('../validate');
const { encrypt, decrypt } = require('../crypto');
const crypto = require('node:crypto');
const { expirarSolicitudes } = require('../service');
const { COOKIE, cookieOptions, signToken, authenticate } = require('../security');

module.exports = function authRoutes(ctx) {
  const { db, config, now, audit } = ctx;
  const router = express.Router();
  const requireAuth = authenticate(db, config);

  // Hash ficticio para igualar el tiempo de respuesta cuando el correo no existe (evita enumeración por tiempos).
  const DUMMY_HASH = bcrypt.hashSync('contrasena-ficticia-Aa1', config.bcryptRounds);

  router.post('/registro', wrap(async (req, res) => {
    const body = req.body || {};
    const nombre = v.nombre(body.nombre);
    const email = v.email(body.email);
    const telefono = v.telefono(body.telefono);
    const password = v.password(body.password);
    if (body.acepta_privacidad !== true) {
      throw new HttpError(400, 'Debe aceptar la política de privacidad y el tratamiento de sus datos personales');
    }
    // Nota: el rol NO se lee del cuerpo (evita asignación masiva / escalamiento de privilegios, OWASP A01).
    const existe = db.prepare('SELECT 1 FROM usuarios WHERE email = ?').get(email);
    if (existe) throw new HttpError(409, 'No fue posible completar el registro. Si ya tiene una cuenta, inicie sesión.');

    const hash = await bcrypt.hash(password, config.bcryptRounds);
    let id;
    try {
      id = db.prepare(`INSERT INTO usuarios (nombre, email, telefono_enc, password_hash, rol, creado_en)
                       VALUES (?, ?, ?, ?, 'JUGADOR', ?)`)
        .run(nombre, email, encrypt(telefono, config.dataKey), hash, now().getTime()).lastInsertRowid;
    } catch (e) {
      if (e && String(e.code).startsWith('SQLITE_CONSTRAINT')) {
        throw new HttpError(409, 'No fue posible completar el registro. Si ya tiene una cuenta, inicie sesión.');
      }
      throw e;
    }
    const user = { id: Number(id), nombre, email, rol: 'JUGADOR', token_version: 0 };
    audit(req, 'REGISTRO', { usuarioId: user.id });
    res.cookie(COOKIE, signToken(user, config), cookieOptions(config));
    res.status(201).json({ usuario: user });
  }));

  router.post('/login', wrap(async (req, res) => {
    const body = req.body || {};
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase().slice(0, 254) : '';
    const password = typeof body.password === 'string' ? body.password.slice(0, 200) : '';
    const GENERICO = 'Correo o contraseña incorrectos';

    const user = db.prepare('SELECT * FROM usuarios WHERE email = ?').get(email);
    const t = now().getTime();

    if (user && user.bloqueado_hasta && user.bloqueado_hasta > t) {
      audit(req, 'LOGIN_BLOQUEADO', { usuarioId: user.id });
      throw new HttpError(429, 'Demasiados intentos fallidos. Intente nuevamente más tarde.');
    }

    const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok) {
      if (user) {
        const intentos = user.intentos_fallidos + 1;
        if (intentos >= config.maxIntentosLogin) {
          db.prepare('UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = ? WHERE id = ?')
            .run(t + config.bloqueoMin * 60 * 1000, user.id);
          audit(req, 'CUENTA_BLOQUEADA', { usuarioId: user.id, detalle: `${intentos} intentos fallidos` });
        } else {
          db.prepare('UPDATE usuarios SET intentos_fallidos = ? WHERE id = ?').run(intentos, user.id);
        }
      }
      audit(req, 'LOGIN_FALLIDO', { usuarioId: user ? user.id : null });
      throw new HttpError(401, GENERICO);
    }

    db.prepare('UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?').run(user.id);
    audit(req, 'LOGIN_OK', { usuarioId: user.id });
    const publico = { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol };
    res.cookie(COOKIE, signToken({ ...publico, token_version: user.token_version }, config), cookieOptions(config));
    res.json({ usuario: publico });
  }));

  // Cierre de sesión: además de borrar la cookie, se invalida el token en el servidor (ISO 27001 - control de sesiones).
  router.post('/logout', (req, res) => {
    const token = req.cookies && req.cookies[COOKIE];
    if (token) {
      try {
        const p = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
        db.prepare('UPDATE usuarios SET token_version = token_version + 1 WHERE id = ? AND token_version = ?').run(p.sub, p.ver || 0);
        audit(req, 'LOGOUT', { usuarioId: p.sub });
      } catch { /* token inválido o vencido: solo se limpia la cookie */ }
    }
    res.clearCookie(COOKIE, cookieOptions(config));
    res.json({ ok: true });
  });

  // Derecho de supresión (Ley 19.628 / Ley 21.719): anonimiza los datos personales de la cuenta.
  // Las reservas y pagos se conservan sin datos identificables (respaldo contable del negocio).
  router.post('/eliminar-cuenta', requireAuth, wrap(async (req, res) => {
    if (req.user.rol !== 'JUGADOR') throw new HttpError(403, 'Las cuentas de recinto se gestionan con el administrador de la plataforma');
    const password = typeof (req.body || {}).password === 'string' ? req.body.password.slice(0, 200) : '';
    const fila = db.prepare('SELECT password_hash FROM usuarios WHERE id = ?').get(req.user.id);
    if (!(await bcrypt.compare(password, fila.password_hash))) {
      audit(req, 'ELIMINACION_CUENTA_RECHAZADA');
      throw new HttpError(401, 'Contraseña incorrecta');
    }
    expirarSolicitudes(db, config, now);
    const activas = db.prepare("SELECT COUNT(*) AS n FROM reservas WHERE jugador_id = ? AND estado IN ('SOLICITADA','CONFIRMADA','PAGADA')").get(req.user.id).n;
    if (activas > 0) throw new HttpError(409, 'Cancele sus reservas activas antes de eliminar la cuenta');
    const hashInutilizable = await bcrypt.hash(crypto.randomBytes(24).toString('hex'), config.bcryptRounds);
    db.prepare(`UPDATE usuarios SET nombre = 'Usuario eliminado', email = ?, telefono_enc = ?, password_hash = ?,
                token_version = token_version + 1, intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?`)
      .run(`eliminado-${req.user.id}@eliminado.invalid`, encrypt('eliminado', config.dataKey), hashInutilizable, req.user.id);
    audit(req, 'CUENTA_ELIMINADA', { usuarioId: req.user.id });
    res.clearCookie(COOKIE, cookieOptions(config));
    res.json({ ok: true });
  }));

  router.get('/me', requireAuth, (req, res) => {
    const row = db.prepare('SELECT telefono_enc FROM usuarios WHERE id = ?').get(req.user.id);
    res.json({ usuario: { ...req.user, telefono: decrypt(row.telefono_enc, config.dataKey) } });
  });

  return router;
};
