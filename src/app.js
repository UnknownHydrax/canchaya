'use strict';
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { HttpError } = require('./errors');
const { csrfGuard } = require('./security');
const { createAudit } = require('./audit');

function createApp({ db, config, now = () => new Date() }) {
  const app = express();
  const audit = createAudit(db, now);
  const ctx = { db, config, now, audit };

  app.disable('x-powered-by');
  if (config.production) app.set('trust proxy', 1); // detrás del proxy del PaaS (IP real del cliente)

  // Cabeceras de seguridad (OWASP A05). CSP restrictiva: solo scripts y estilos propios => mitiga XSS.
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        baseUri: ["'self'"],
        upgradeInsecureRequests: config.production ? [] : null
      }
    },
    hsts: config.production ? { maxAge: 15552000, includeSubDomains: true } : false
  }));

  app.use(express.json({ limit: '10kb' }));   // limita el tamaño del cuerpo (DoS)
  app.use(cookieParser());

  // Salud del servicio (monitoreo de disponibilidad).
  app.get('/api/salud', (_req, res) => res.json({ estado: 'ok' }));

  const limiteApi = rateLimit({
    windowMs: config.rateLimit.windowMs, limit: config.rateLimit.apiMax,
    standardHeaders: true, legacyHeaders: false,
    message: { error: 'Demasiadas solicitudes. Intente más tarde.' }
  });
  const limiteAuth = rateLimit({
    windowMs: config.rateLimit.windowMs, limit: config.rateLimit.authMax,
    standardHeaders: true, legacyHeaders: false,
    message: { error: 'Demasiados intentos. Intente más tarde.' }
  });

  app.use('/api', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  app.use('/api', limiteApi, csrfGuard);
  app.use('/api/auth/login', limiteAuth);
  app.use('/api/auth/registro', limiteAuth);

  app.use('/api/auth', require('./routes/auth')(ctx));
  app.use('/api/canchas', require('./routes/canchas')(ctx));
  app.use('/api/reservas', require('./routes/reservas')(ctx));
  app.use('/api/recinto', require('./routes/recinto')(ctx));

  app.use('/api', (_req, _res, next) => next(new HttpError(404, 'Recurso no encontrado')));

  app.use(express.static(path.join(__dirname, '..', 'public')));

  // 404 propio para rutas que no son de la API: evita la página de error por defecto que delata el framework.
  app.use((_req, res) => {
    res.status(404).type('html').send('<!doctype html><html lang="es"><meta charset="utf-8"><title>No encontrado</title><body><h1>Página no encontrada</h1><p><a href="/">Volver al inicio</a></p></body></html>');
  });

  // Manejador central de errores: nunca expone trazas ni detalles internos al cliente (OWASP A05/A09).
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'La solicitud es demasiado grande' });
    if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'El cuerpo de la solicitud no es JSON válido' });
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
    console.error('[error]', req.method, req.path, err && err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  });

  return app;
}

module.exports = { createApp };
