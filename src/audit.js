'use strict';
// ISO 27001 (registro y monitoreo) / OWASP A09: bitácora de eventos relevantes de seguridad y negocio.
function createAudit(db, now) {
  const stmt = db.prepare('INSERT INTO auditoria (ts, usuario_id, accion, detalle, ip) VALUES (?, ?, ?, ?, ?)');
  return function audit(req, accion, { usuarioId = null, detalle = null } = {}) {
    const uid = usuarioId ?? req?.user?.id ?? null;
    stmt.run(now().getTime(), uid, accion, detalle ? String(detalle).slice(0, 300) : null, req?.ip || null);
  };
}
module.exports = { createAudit };
