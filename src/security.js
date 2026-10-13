'use strict';
const jwt = require('jsonwebtoken');
const { HttpError } = require('./errors');

const COOKIE = 'cy_token';

function cookieOptions(config) {
  return {
    httpOnly: true,                 // el JS del navegador no puede leer el token (mitiga robo por XSS)
    secure: config.cookieSecure,    // solo por HTTPS en producción
    sameSite: 'strict',             // mitiga CSRF
    path: '/'
  };
}

function signToken(user, config) {
  return jwt.sign({ sub: user.id, rol: user.rol, ver: user.token_version || 0 }, config.jwtSecret, {
    algorithm: 'HS256', expiresIn: config.jwtExpiresIn
  });
}

// Autenticación: verifica el token (algoritmo fijado a HS256) y que el usuario siga existiendo.
function authenticate(db, config) {
  const find = db.prepare('SELECT id, nombre, email, rol, token_version FROM usuarios WHERE id = ?');
  return (req, _res, next) => {
    const token = req.cookies && req.cookies[COOKIE];
    if (!token) return next(new HttpError(401, 'Debe iniciar sesión'));
    let payload;
    try {
      payload = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
    } catch {
      return next(new HttpError(401, 'Sesión inválida o expirada'));
    }
    const user = find.get(payload.sub);
    // El token solo vale si su versión coincide con la del usuario (logout => versión +1 => tokens viejos inválidos).
    if (!user || user.token_version !== (payload.ver || 0)) return next(new HttpError(401, 'Sesión inválida o expirada'));
    req.user = { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol };
    req.tokenVersion = user.token_version;
    next();
  };
}

// Control de acceso basado en roles (RBAC) — OWASP A01.
function requireRole(...roles) {
  return (req, _res, next) => {
    if (!req.user || !roles.includes(req.user.rol)) return next(new HttpError(403, 'No tiene permisos para esta acción'));
    next();
  };
}

// Protección CSRF adicional a SameSite: las peticiones que modifican datos deben traer una
// cabecera personalizada que un sitio externo no puede enviar sin permiso CORS.
function csrfGuard(req, _res, next) {
  const metodosSeguros = ['GET', 'HEAD', 'OPTIONS'];
  if (metodosSeguros.includes(req.method)) return next();
  if (req.get('x-requested-with') !== 'CanchaYa') return next(new HttpError(403, 'Solicitud no permitida'));
  next();
}

module.exports = { COOKIE, cookieOptions, signToken, authenticate, requireRole, csrfGuard };
