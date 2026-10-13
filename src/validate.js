'use strict';
const { HttpError } = require('./errors');

// Validación de entradas con listas permitidas (OWASP A03 - Inyección / A04 - Diseño inseguro).
const EMAIL_RE = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$/;
const NOMBRE_RE = /^[\p{L}][\p{L} .'-]{1,79}$/u;          // solo letras, espacios y . ' -
const TELEFONO_RE = /^\+?[0-9]{8,12}$/;
const TEXTO_RE = /^[\p{L}\p{N} .,'#-]{2,80}$/u;
const FECHA_RE = /^\d{4}-\d{2}-\d{2}$/;

function bad(msg) { return new HttpError(400, msg); }

function asString(v, campo) {
  if (typeof v !== 'string') throw bad(`${campo} es obligatorio`);
  return v.trim();
}

function nombre(v) {
  const s = asString(v, 'El nombre');
  if (!NOMBRE_RE.test(s)) throw bad('Nombre inválido: use solo letras, espacios, punto, guion o apóstrofe (2 a 80 caracteres)');
  return s;
}

function email(v) {
  const s = asString(v, 'El correo').toLowerCase();
  if (s.length > 254 || !EMAIL_RE.test(s)) throw bad('Correo electrónico inválido');
  return s;
}

function telefono(v) {
  const s = asString(v, 'El teléfono').replace(/[\s-]/g, '');
  if (!TELEFONO_RE.test(s)) throw bad('Teléfono inválido (8 a 12 dígitos, puede iniciar con +)');
  return s;
}

// Política de contraseñas (ISO 27001 A.9 / OWASP A07): 10-72 caracteres, mayúscula, minúscula y número.
function password(v) {
  if (typeof v !== 'string') throw bad('La contraseña es obligatoria');
  if (v.length < 10 || v.length > 72) throw bad('La contraseña debe tener entre 10 y 72 caracteres');
  if (!/[a-z]/.test(v) || !/[A-Z]/.test(v) || !/[0-9]/.test(v)) {
    throw bad('La contraseña debe incluir mayúsculas, minúsculas y números');
  }
  return v;
}

function texto(v, campo) {
  const s = asString(v, campo);
  if (!TEXTO_RE.test(s)) throw bad(`${campo} inválido`);
  return s;
}

function entero(v, campo, { min, max }) {
  const n = typeof v === 'number' ? v : (typeof v === 'string' && /^-?\d+$/.test(v.trim()) ? Number(v) : NaN);
  if (!Number.isInteger(n) || n < min || n > max) throw bad(`${campo} debe ser un entero entre ${min} y ${max}`);
  return n;
}

function id(v, campo = 'id') {
  return entero(v, campo, { min: 1, max: 2147483647 });
}

// Fecha YYYY-MM-DD real (rechaza 2026-02-30) y dentro de la ventana permitida.
function fecha(v, { hoy, maxDias, permitirPasado = false }) {
  const s = asString(v, 'La fecha');
  if (!FECHA_RE.test(s)) throw bad('Fecha inválida (formato AAAA-MM-DD)');
  const [y, m, d] = s.split('-').map(Number);
  const dt = new Date(y, m - 1, d);
  if (dt.getFullYear() !== y || dt.getMonth() !== m - 1 || dt.getDate() !== d) throw bad('La fecha no existe');
  const inicioHoy = new Date(hoy.getFullYear(), hoy.getMonth(), hoy.getDate());
  const dias = Math.round((dt - inicioHoy) / 86400000);
  if (dias < 0 && !permitirPasado) throw bad('No se puede reservar en una fecha pasada');
  if (dias > maxDias) throw bad(`Solo se puede reservar hasta ${maxDias} días de anticipación`);
  return s;
}

// Número de tarjeta: solo para validar el formato (Luhn). NUNCA se guarda ni se registra.
function luhn(num) {
  let sum = 0, alt = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let n = Number(num[i]);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

function tarjeta(v) {
  const s = asString(v, 'La tarjeta').replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(s) || !luhn(s)) throw bad('Número de tarjeta inválido');
  return s;
}

module.exports = { nombre, email, telefono, password, texto, entero, id, fecha, tarjeta };
