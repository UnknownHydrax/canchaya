# CanchaYa – Prototipo de arriendo de canchas deportivas

Prototipo web (Unidad 3, Ingeniería de Software) para arrendar canchas en recintos de Los Ángeles, Región del Biobío.
Jugadores buscan, reservan, pagan (pasarela **simulada**) y cancelan; los administradores de recinto gestionan canchas y reservas.

**Stack:** Node.js 22 · Express 4 · SQLite (better-sqlite3) · JWT en cookie HttpOnly · frontend HTML/JS sin frameworks.

## Ejecutar

```bash
npm ci
npm run seed      # crea datos de ejemplo; IMPRIME UNA SOLA VEZ las contraseñas generadas
npm start         # http://localhost:3000
npm test          # 50 pruebas (funcionales, límites, seguridad OWASP/ISO 27000)
```

El seed crea 2 recintos (El Retiro y Pádel Center Biobío), 5 canchas, 2 administradores y 1 jugador de ejemplo.
Las contraseñas son aleatorias y se muestran en consola al ejecutar el seed (opcional: `SEED_ADMIN_PASSWORD`).

Tarjetas de prueba (pasarela simulada, no se guardan datos de tarjeta):
`4242 4242 4242 4242` → aprobada · `4000 0000 0000 0002` → rechazada.

## Variables de entorno

| Variable | Descripción |
|---|---|
| `NODE_ENV=production` | Activa cookies `Secure`, HSTS y exige secretos fuertes |
| `JWT_SECRET` | Obligatoria en producción, ≥ 32 caracteres |
| `DATA_KEY` | Obligatoria en producción, ≥ 32 caracteres (cifrado AES-256-GCM de teléfonos) |
| `DB_PATH` | Ruta del archivo SQLite (por defecto `data/canchaya.db`) |
| `PORT` | Puerto (por defecto 3000) |

## Despliegue en la nube (PaaS – Render)

1. Subir el repositorio a GitHub.
2. En Render: *New → Blueprint* y seleccionar el repositorio (usa `render.yaml`; genera `JWT_SECRET` y `DATA_KEY`).
3. Verificar `https://<servicio>.onrender.com/api/salud`.

Limitación: en el plan gratuito el disco es efímero, por lo que SQLite se reinicia al redesplegar. En producción real se debe migrar a PostgreSQL administrado o montar un disco persistente (`DB_PATH`).

## Estructura

```
src/        app, config, db, seguridad, validación, cifrado, rutas (auth, canchas, reservas, recinto)
public/     interfaz web (sin innerHTML; CSP estricta)
test/       funcionales (CP), de límites (CL) y de seguridad (CS)
docs/       diagramas UML (PlantUML), evidencia de pruebas por ronda, capturas, npm audit
```

## Seguridad (resumen)

OWASP Top 10: control de acceso por rol y por dueño (A01), bcrypt + AES-256-GCM + TLS/HSTS (A02), consultas parametrizadas y validación por lista permitida (A03), precio calculado en servidor y índice único contra doble reserva (A04), cabeceras helmet/CSP y errores genéricos (A05), bloqueo por intentos, invalidación de tokens al cerrar sesión (A07), registro de auditoría (A09). Dependencias: `npm audit` sin vulnerabilidades.

## Limitaciones del prototipo

Pagos simulados; sin envío real de correos/notificaciones; una sola instancia con SQLite (sin alta disponibilidad ni respaldos automáticos); sin recuperación de contraseña ni MFA.
