'use strict';
const { loadConfig } = require('./config');
const { openDb } = require('./db');
const { createApp } = require('./app');
const { seedIfEmpty } = require('./seed');

const config = loadConfig();
const db = openDb(config.dbPath);

if (process.env.AUTO_SEED !== 'false') seedIfEmpty(db, config);

const app = createApp({ db, config });
const server = app.listen(config.port, () => {
  console.log(`CanchaYa escuchando en http://localhost:${config.port} (${config.production ? 'producción' : 'desarrollo'})`);
});

// Cierre ordenado (disponibilidad / integridad de datos).
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => server.close(() => { db.close(); process.exit(0); }));
}
