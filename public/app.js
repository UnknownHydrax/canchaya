'use strict';
/*
 * CanchaYa - interfaz web del prototipo.
 * Seguridad en el cliente (OWASP A03): NUNCA se usa innerHTML; todo el contenido dinámico se inserta
 * con textContent / nodos de texto, de modo que los datos recibidos no pueden ejecutarse como HTML o script.
 */

const CLP = new Intl.NumberFormat('es-CL', { style: 'currency', currency: 'CLP', maximumFractionDigits: 0 });
const ETIQUETA = {
  SOLICITADA: 'Pendiente de pago', CONFIRMADA: 'Confirmada (pago en recinto)', PAGADA: 'Pagada',
  CANCELADA: 'Cancelada', COMPLETADA: 'Completada', NO_PRESENTADA: 'No se presentó'
};

const estado = {
  usuario: null, vista: 'auth', tabAuth: 'login',
  deporte: '', fecha: '', canchas: null, canchaSel: null, bloques: null, bloqueSel: null, medio: 'webpay_simulado', pendiente: null,
  panelFecha: '', cancelando: null
};

// ---------- utilidades ----------
function h(tag, props, ...hijos) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const hijo of hijos.flat()) {
    if (hijo === null || hijo === undefined || hijo === false) continue;
    el.append(hijo.nodeType ? hijo : document.createTextNode(String(hijo)));
  }
  return el;
}

function campo(id, etiqueta, atributos, ayuda) {
  return h('div', { class: 'campo' },
    h('label', { for: id }, etiqueta),
    h('input', { id, name: id, ...atributos }),
    ayuda ? h('span', { class: 'ayuda' }, ayuda) : null);
}

function fechaISO(d) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
function sumarDias(d, n) { const x = new Date(d); x.setDate(x.getDate() + n); return x; }
function hora(n) { return String(n).padStart(2, '0') + ':00'; }
function fechaLarga(iso) {
  const [y, m, d] = iso.split('-').map(Number);
  return new Date(y, m - 1, d).toLocaleDateString('es-CL', { weekday: 'long', day: 'numeric', month: 'long' });
}

let temporizadorAviso = null;
function aviso(texto, tipo = 'ok') {
  const cont = document.getElementById('aviso');
  cont.replaceChildren(h('div', { class: `msg ${tipo}` }, texto));
  clearTimeout(temporizadorAviso);
  temporizadorAviso = setTimeout(() => cont.replaceChildren(), 6000);
}

async function api(metodo, url, cuerpo) {
  const res = await fetch(url, {
    method: metodo,
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'CanchaYa' },
    credentials: 'same-origin',
    body: cuerpo === undefined ? undefined : JSON.stringify(cuerpo)
  });
  let datos = null;
  try { datos = await res.json(); } catch { /* sin cuerpo */ }
  if (!res.ok) {
    const err = new Error((datos && datos.error) || 'Ocurrió un error inesperado');
    err.status = res.status;
    throw err;
  }
  return datos;
}

// Maneja errores comunes; devuelve true si ya se informó al usuario.
function manejarError(e) {
  if (e.status === 401 && estado.usuario) {
    estado.usuario = null; estado.vista = 'auth';
    render();
    aviso('Su sesión expiró. Ingrese nuevamente.', 'error');
    return;
  }
  aviso(e.message, 'error');
}

// ---------- navegación ----------
function renderNav() {
  const nav = document.getElementById('nav');
  nav.replaceChildren();
  if (!estado.usuario) return;
  const u = estado.usuario;
  nav.append(h('span', { class: 'usuario' }, u.nombre));
  const botones = u.rol === 'ADMIN_RECINTO'
    ? [['panel', 'Panel del recinto']]
    : [['buscar', 'Buscar canchas'], ['mis', 'Mis reservas']];
  for (const [vista, texto] of botones) {
    nav.append(h('button', { type: 'button', class: estado.vista === vista ? 'activo' : '', onclick: () => ir(vista) }, texto));
  }
  nav.append(h('button', { type: 'button', onclick: salir }, 'Salir'));
}

function ir(vista) { estado.vista = vista; estado.cancelando = null; render(); }

async function salir() {
  try { await api('POST', '/api/auth/logout', {}); } catch { /* da igual */ }
  Object.assign(estado, { usuario: null, vista: 'auth', canchas: null, canchaSel: null, bloques: null, bloqueSel: null, pendiente: null });
  render();
}

function render() {
  renderNav();
  const app = document.getElementById('app');
  let contenido;
  if (!estado.usuario) contenido = vistaAuth();
  else if (estado.usuario.rol === 'ADMIN_RECINTO') contenido = vistaPanel();
  else contenido = estado.vista === 'mis' ? vistaMisReservas() : vistaBuscar();
  app.replaceChildren(contenido);
}

// ---------- autenticación ----------
function vistaAuth() {
  const esLogin = estado.tabAuth === 'login';
  const form = esLogin ? formLogin() : formRegistro();
  return h('div', { class: 'auth' },
    h('h1', {}, 'Reserve su cancha en minutos'),
    h('p', { class: 'sub' }, 'Fútbol, pádel y más en Los Ángeles, Región del Biobío.'),
    h('div', { class: 'tarjeta' },
      h('div', { class: 'tabs', role: 'tablist' },
        h('button', { type: 'button', class: esLogin ? 'activo' : '', onclick: () => { estado.tabAuth = 'login'; render(); } }, 'Ingresar'),
        h('button', { type: 'button', class: !esLogin ? 'activo' : '', onclick: () => { estado.tabAuth = 'registro'; render(); } }, 'Crear cuenta')),
      form));
}

function formLogin() {
  return h('form', {
    onsubmit: async (ev) => {
      ev.preventDefault();
      const f = ev.target;
      try {
        const r = await api('POST', '/api/auth/login', { email: f.email.value, password: f.password.value });
        entrar(r.usuario);
      } catch (e) { aviso(e.message, 'error'); }
    }
  },
  campo('email', 'Correo electrónico', { type: 'email', required: true, autocomplete: 'username', maxlength: 254 }),
  campo('password', 'Contraseña', { type: 'password', required: true, autocomplete: 'current-password', maxlength: 200 }),
  h('button', { class: 'btn', type: 'submit' }, 'Ingresar'));
}

function formRegistro() {
  return h('form', {
    onsubmit: async (ev) => {
      ev.preventDefault();
      const f = ev.target;
      try {
        const r = await api('POST', '/api/auth/registro', {
          nombre: f.nombre.value, email: f.email.value, telefono: f.telefono.value,
          password: f.password.value, acepta_privacidad: f.acepta.checked
        });
        entrar(r.usuario);
        aviso('Cuenta creada. ¡Bienvenido a CanchaYa!');
      } catch (e) { aviso(e.message, 'error'); }
    }
  },
  campo('nombre', 'Nombre completo', { type: 'text', required: true, autocomplete: 'name', maxlength: 80 }),
  campo('email', 'Correo electrónico', { type: 'email', required: true, autocomplete: 'email', maxlength: 254 }),
  campo('telefono', 'Teléfono', { type: 'tel', required: true, autocomplete: 'tel', maxlength: 16, placeholder: '+56912345678' }),
  campo('password', 'Contraseña', { type: 'password', required: true, autocomplete: 'new-password', minlength: 10, maxlength: 72 },
    'Mínimo 10 caracteres, con mayúsculas, minúsculas y números.'),
  h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'acepta', required: true }),
    h('span', {}, 'Acepto la política de privacidad y el tratamiento de mis datos personales para gestionar mis reservas (Ley N° 19.628).')),
  h('button', { class: 'btn', type: 'submit' }, 'Crear cuenta'));
}

function entrar(usuario) {
  estado.usuario = usuario;
  estado.vista = usuario.rol === 'ADMIN_RECINTO' ? 'panel' : 'buscar';
  render();
}

// ---------- jugador: buscar y reservar ----------
function vistaBuscar() {
  const hoy = new Date();
  if (!estado.fecha) estado.fecha = fechaISO(hoy);
  const filtros = h('form', {
    class: 'tarjeta',
    onsubmit: (ev) => { ev.preventDefault(); buscar(); }
  },
  h('div', { class: 'fila' },
    h('div', { class: 'campo' }, h('label', { for: 'deporte' }, 'Deporte'),
      h('select', { id: 'deporte', onchange: (e) => { estado.deporte = e.target.value; } },
        ['', 'Fútbol 7', 'Fútbol 5', 'Pádel'].map((d) => h('option', { value: d, selected: estado.deporte === d }, d || 'Todos')))),
    h('div', { class: 'campo' }, h('label', { for: 'fecha' }, 'Fecha'),
      h('input', { id: 'fecha', type: 'date', value: estado.fecha, min: fechaISO(hoy), max: fechaISO(sumarDias(hoy, 60)), required: true,
        onchange: (e) => { estado.fecha = e.target.value; estado.bloques = null; estado.bloqueSel = null; if (estado.canchaSel) cargarBloques(); } })),
    h('button', { class: 'btn', type: 'submit' }, 'Buscar canchas')));

  const cont = h('div', {},
    h('h1', {}, 'Buscar canchas'),
    h('p', { class: 'sub' }, 'Elija deporte y fecha, luego seleccione un horario libre.'),
    filtros,
    h('div', { id: 'resultados' }, listaCanchas()),
    h('div', { id: 'horarios' }, panelHorarios()),
    h('div', { id: 'confirmar' }, panelConfirmar()));
  if (!estado.canchas) buscar();
  return cont;
}

async function buscar() {
  try {
    const q = estado.deporte ? `?deporte=${encodeURIComponent(estado.deporte)}` : '';
    const r = await api('GET', `/api/canchas${q}`);
    estado.canchas = r.canchas;
    estado.canchaSel = null; estado.bloques = null; estado.bloqueSel = null;
    refrescarSeccion();
  } catch (e) { manejarError(e); }
}

function refrescarSeccion() {
  const r = document.getElementById('resultados');
  if (!r) return;
  r.replaceChildren(listaCanchas());
  document.getElementById('horarios').replaceChildren(panelHorarios());
  document.getElementById('confirmar').replaceChildren(panelConfirmar());
}

function listaCanchas() {
  if (!estado.canchas) return h('p', { class: 'vacio' }, 'Cargando canchas…');
  if (!estado.canchas.length) return h('p', { class: 'vacio' }, 'No hay canchas para ese filtro.');
  return h('div', { class: 'grid-canchas' }, estado.canchas.map((c) =>
    h('article', { class: 'tarjeta cancha' },
      h('h3', {}, `${c.nombre} · ${c.deporte}`),
      h('div', { class: 'rec' }, `${c.recinto} — ${c.direccion}, ${c.comuna}`),
      h('div', { class: 'precio' }, `${CLP.format(c.precio_hora)} por hora`),
      h('div', { class: 'rec' }, `Abierto de ${hora(c.hora_apertura)} a ${hora(c.hora_cierre)}`),
      h('button', { class: 'btn mini', type: 'button', onclick: () => { estado.canchaSel = c; estado.bloqueSel = null; cargarBloques(); } }, 'Ver horarios'))));
}

async function cargarBloques() {
  try {
    const r = await api('GET', `/api/canchas/${estado.canchaSel.id}/disponibilidad?fecha=${encodeURIComponent(estado.fecha)}`);
    estado.bloques = r.bloques;
    refrescarSeccion();
    document.getElementById('horarios').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (e) { manejarError(e); }
}

function panelHorarios() {
  if (!estado.canchaSel || !estado.bloques) return h('span');
  const c = estado.canchaSel;
  return h('section', { class: 'tarjeta' },
    h('h2', {}, `${c.nombre} · ${c.recinto}`),
    h('p', { class: 'sub' }, `Horarios del ${fechaLarga(estado.fecha)}. Seleccione un bloque libre (1 hora).`),
    h('div', { class: 'bloques' }, estado.bloques.map((b) =>
      h('button', {
        type: 'button', class: 'bloque' + (estado.bloqueSel === b.hora_inicio ? ' elegido' : ''),
        disabled: b.estado !== 'libre',
        'aria-label': `${hora(b.hora_inicio)} a ${hora(b.hora_fin)}, ${b.estado}`,
        onclick: () => { estado.bloqueSel = b.hora_inicio; estado.pendiente = null; refrescarSeccion(); document.getElementById('confirmar').scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }
      }, `${hora(b.hora_inicio)} – ${hora(b.hora_fin)}`, h('br'), h('small', {}, b.estado === 'libre' ? 'Libre' : b.estado === 'ocupado' ? 'Ocupado' : 'No disponible')))));
}

function panelConfirmar() {
  if (!estado.canchaSel || estado.bloqueSel === null) return h('span');
  const c = estado.canchaSel;
  const conTarjeta = estado.medio === 'webpay_simulado';
  return h('section', { class: 'tarjeta' },
    h('h2', {}, 'Confirmar reserva'),
    h('div', { class: 'resumen' },
      h('div', {}, h('b', {}, `${c.nombre} · ${c.deporte}`), ` — ${c.recinto}`),
      h('div', {}, `${fechaLarga(estado.fecha)}, ${hora(estado.bloqueSel)} a ${hora(estado.bloqueSel + 1)}`),
      h('div', {}, h('b', {}, `Total: ${CLP.format(c.precio_hora)}`))),
    estado.pendiente ? h('p', { class: 'ayuda' }, `Su horario está retenido (código ${estado.pendiente.codigo}). Complete el pago dentro de 10 minutos.`) : null,
    h('form', {
      onsubmit: (ev) => { ev.preventDefault(); confirmarReserva(ev.target); }
    },
    h('div', { class: 'radios', role: 'radiogroup', 'aria-label': 'Medio de pago' },
      h('label', {}, h('input', { type: 'radio', name: 'medio', value: 'webpay_simulado', checked: conTarjeta, onchange: () => { estado.medio = 'webpay_simulado'; refrescarSeccion(); } }), 'Pagar ahora con tarjeta (Webpay simulado)'),
      h('label', {}, h('input', { type: 'radio', name: 'medio', value: 'en_recinto', checked: !conTarjeta, onchange: () => { estado.medio = 'en_recinto'; refrescarSeccion(); } }), 'Pagar en el recinto')),
    conTarjeta ? campo('tarjeta', 'Número de tarjeta', { type: 'text', inputmode: 'numeric', autocomplete: 'off', maxlength: 23, required: true, placeholder: '4242 4242 4242 4242' },
      'Prototipo: use 4242 4242 4242 4242 (aprobada) o 4000 0000 0000 0002 (rechazada). El número no se guarda.') : null,
    h('div', { class: 'fila' }, h('button', { class: 'btn', type: 'submit', id: 'btn-confirmar' }, conTarjeta ? 'Pagar y reservar' : 'Reservar'))));
}

async function confirmarReserva(form) {
  const btn = document.getElementById('btn-confirmar');
  btn.disabled = true;
  const c = estado.canchaSel;
  try {
    if (!estado.pendiente) {
      const r = await api('POST', '/api/reservas', { cancha_id: c.id, fecha: estado.fecha, hora_inicio: estado.bloqueSel });
      estado.pendiente = r.reserva;
    }
    const cuerpo = estado.medio === 'en_recinto' ? { medio: 'en_recinto' } : { medio: 'webpay_simulado', tarjeta: form.tarjeta.value };
    const p = await api('POST', `/api/reservas/${estado.pendiente.id}/pagar`, cuerpo);
    aviso(`¡Reserva lista! Código ${p.reserva.codigo} — ${ETIQUETA[p.reserva.estado]}.`);
    estado.pendiente = null; estado.bloqueSel = null; estado.bloques = null; estado.canchaSel = null;
    ir('mis');
  } catch (e) {
    if (e.status === 409 || e.status === 404) { estado.pendiente = null; estado.bloqueSel = null; await cargarBloques(); }
    manejarError(e);
    const b = document.getElementById('btn-confirmar');
    if (b) b.disabled = false;
  }
}

// ---------- jugador: mis reservas ----------
function vistaMisReservas() {
  const cont = h('div', {}, h('h1', {}, 'Mis reservas'), h('p', { class: 'sub' }, 'Consulte, pague o cancele sus reservas.'),
    h('div', { id: 'lista-mis' }, h('p', { class: 'vacio' }, 'Cargando…')), formEliminarCuenta());
  cargarMisReservas();
  return cont;
}

async function cargarMisReservas() {
  try {
    const r = await api('GET', '/api/reservas/mias');
    const lista = document.getElementById('lista-mis');
    if (!lista) return;
    if (!r.reservas.length) { lista.replaceChildren(h('p', { class: 'vacio' }, 'Aún no tiene reservas.')); return; }
    lista.replaceChildren(...r.reservas.map(tarjetaReserva));
  } catch (e) { manejarError(e); }
}

function tarjetaReserva(r) {
  const activa = ['SOLICITADA', 'CONFIRMADA', 'PAGADA'].includes(r.estado);
  const acciones = h('div', { class: 'acciones' });
  if (r.estado === 'SOLICITADA') {
    acciones.append(h('button', { class: 'btn mini', type: 'button', onclick: () => pagarEnRecinto(r) }, 'Pagar en recinto'));
  }
  if (activa) {
    if (estado.cancelando === r.id) {
      acciones.append(
        h('button', { class: 'btn mini peligro', type: 'button', onclick: () => cancelar(r) }, 'Sí, cancelar'),
        h('button', { class: 'btn mini sec', type: 'button', onclick: () => { estado.cancelando = null; cargarMisReservas(); } }, 'No'));
    } else {
      acciones.append(h('button', { class: 'btn mini peligro', type: 'button', onclick: () => { estado.cancelando = r.id; cargarMisReservas(); } }, 'Cancelar'));
    }
  }
  return h('article', { class: 'tarjeta reserva' },
    h('div', { class: 'datos' },
      h('div', {}, h('b', {}, `${r.cancha} · ${r.deporte}`), ' ', h('span', { class: `insignia i-${r.estado}` }, ETIQUETA[r.estado])),
      h('div', {}, `${r.recinto} — ${fechaLarga(r.fecha)}, ${hora(r.hora_inicio)} a ${hora(r.hora_fin)}`),
      h('div', { class: 'cod' }, `Código ${r.codigo} · ${CLP.format(r.monto)}`)),
    acciones);
}

function formEliminarCuenta() {
  return h('details', { class: 'tarjeta' },
    h('summary', {}, 'Privacidad: eliminar mi cuenta'),
    h('form', {
      onsubmit: async (ev) => {
        ev.preventDefault();
        try {
          await api('POST', '/api/auth/eliminar-cuenta', { password: ev.target.clave.value });
          Object.assign(estado, { usuario: null, vista: 'auth', canchas: null });
          render();
          aviso('Su cuenta fue eliminada y sus datos personales anonimizados.');
        } catch (e) { manejarError(e); }
      }
    },
    h('p', { class: 'ayuda' }, 'Se anonimizan sus datos personales (Ley N° 19.628). Las reservas pasadas se conservan sin sus datos. Debe cancelar antes sus reservas activas.'),
    campo('clave', 'Confirme su contraseña', { type: 'password', required: true, autocomplete: 'current-password', maxlength: 200 }),
    h('button', { class: 'btn peligro', type: 'submit' }, 'Eliminar mi cuenta definitivamente')));
}

async function pagarEnRecinto(r) {
  try { await api('POST', `/api/reservas/${r.id}/pagar`, { medio: 'en_recinto' }); aviso('Reserva confirmada: pagará en el recinto.'); cargarMisReservas(); }
  catch (e) { manejarError(e); cargarMisReservas(); }
}

async function cancelar(r) {
  try {
    const res = await api('POST', `/api/reservas/${r.id}/cancelar`, {});
    estado.cancelando = null;
    aviso(res.devolucion > 0 ? `Reserva cancelada. Se devolverán ${CLP.format(res.devolucion)}.` : 'Reserva cancelada.');
    cargarMisReservas();
  } catch (e) { estado.cancelando = null; manejarError(e); cargarMisReservas(); }
}

// ---------- administrador de recinto ----------
function vistaPanel() {
  if (!estado.panelFecha) estado.panelFecha = fechaISO(new Date());
  const cont = h('div', {},
    h('h1', {}, 'Panel del recinto'),
    h('p', { class: 'sub' }, 'Calendario de reservas, reservas presenciales y estado de la jornada.'),
    h('div', { class: 'tarjeta fila' },
      h('div', { class: 'campo' }, h('label', { for: 'pfecha' }, 'Fecha'),
        h('input', { id: 'pfecha', type: 'date', value: estado.panelFecha, onchange: (e) => { if (e.target.value) { estado.panelFecha = e.target.value; cargarPanel(); } } }))),
    h('div', { id: 'panel-datos' }, h('p', { class: 'vacio' }, 'Cargando…')));
  cargarPanel();
  return cont;
}

async function cargarPanel() {
  try {
    const d = await api('GET', `/api/recinto/reservas?fecha=${encodeURIComponent(estado.panelFecha)}`);
    const cont = document.getElementById('panel-datos');
    if (!cont) return;
    cont.replaceChildren(
      h('h2', {}, `${d.recinto.nombre} — ${fechaLarga(d.fecha)}`),
      h('div', { class: 'kpis' },
        kpi(`${d.resumen.ocupacion_pct} %`, 'Ocupación del día'),
        kpi(`${d.resumen.bloques_ocupados} / ${d.resumen.bloques_totales}`, 'Bloques ocupados'),
        kpi(CLP.format(d.resumen.ingresos), 'Ingresos (pagadas y completadas)')),
      calendario(d),
      listaReservasPanel(d),
      formPresencial(d),
      formCancha());
  } catch (e) { manejarError(e); }
}

function kpi(valor, texto) { return h('div', { class: 'kpi' }, h('b', {}, valor), h('span', {}, texto)); }

function calendario(d) {
  let minH = 24, maxH = 0;
  d.canchas.forEach((c) => { minH = Math.min(minH, c.hora_apertura); maxH = Math.max(maxH, c.hora_cierre); });
  const porCelda = new Map(d.reservas.map((r) => [`${r.cancha_id}-${r.hora_inicio}`, r]));
  const filas = [];
  for (let hh = minH; hh < maxH; hh++) {
    filas.push(h('tr', {},
      h('th', { scope: 'row' }, hora(hh)),
      d.canchas.map((c) => {
        if (hh < c.hora_apertura || hh >= c.hora_cierre) return h('td', { class: 'libre' }, '—');
        const r = porCelda.get(`${c.id}-${hh}`);
        if (!r) return h('td', { class: 'libre' }, 'libre');
        return h('td', { class: 'ocupada' }, h('div', { class: 'quien' }, r.cliente), h('div', { class: 'peq' }, ETIQUETA[r.estado]));
      })));
  }
  return h('div', { class: 'tarjeta' }, h('h2', {}, 'Calendario'),
    h('div', { class: 'tabla-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Hora'), d.canchas.map((c) => h('th', { scope: 'col' }, c.nombre)))),
      h('tbody', {}, filas))));
}

function listaReservasPanel(d) {
  const nombres = new Map(d.canchas.map((c) => [c.id, c.nombre]));
  if (!d.reservas.length) return h('div', { class: 'tarjeta' }, h('h2', {}, 'Reservas del día'), h('p', { class: 'vacio' }, 'No hay reservas para esta fecha.'));
  return h('div', { class: 'tarjeta' }, h('h2', {}, 'Reservas del día'), d.reservas.map((r) => {
    const acciones = h('div', { class: 'acciones' });
    if (['CONFIRMADA', 'PAGADA'].includes(r.estado)) {
      acciones.append(
        h('button', { class: 'btn mini sec', type: 'button', onclick: () => cambiarEstado(r, 'COMPLETADA') }, 'Marcar completada'),
        h('button', { class: 'btn mini sec', type: 'button', onclick: () => cambiarEstado(r, 'NO_PRESENTADA') }, 'No se presentó'));
    }
    if (['SOLICITADA', 'CONFIRMADA', 'PAGADA'].includes(r.estado)) {
      acciones.append(h('button', { class: 'btn mini peligro', type: 'button', onclick: () => cancelarPanel(r) }, 'Cancelar'));
    }
    return h('div', { class: 'reserva', }, h('div', { class: 'datos' },
      h('div', {}, h('b', {}, `${hora(r.hora_inicio)} · ${nombres.get(r.cancha_id)}`), ' ', h('span', { class: `insignia i-${r.estado}` }, ETIQUETA[r.estado])),
      h('div', {}, `${r.cliente}${r.telefono ? ` (tel. ${r.telefono})` : ''} — ${CLP.format(r.monto)}`),
      h('div', { class: 'cod' }, `Código ${r.codigo} · ${r.origen === 'PRESENCIAL' ? 'presencial' : 'app'}`)), acciones);
  }));
}

async function cambiarEstado(r, nuevo) {
  try { await api('POST', `/api/recinto/reservas/${r.id}/estado`, { estado: nuevo }); aviso('Reserva actualizada.'); cargarPanel(); }
  catch (e) { manejarError(e); }
}
async function cancelarPanel(r) {
  try { await api('POST', `/api/recinto/reservas/${r.id}/cancelar`, {}); aviso('Reserva cancelada.'); cargarPanel(); }
  catch (e) { manejarError(e); }
}

function formPresencial(d) {
  return h('form', {
    class: 'tarjeta',
    onsubmit: async (ev) => {
      ev.preventDefault();
      const f = ev.target;
      try {
        await api('POST', '/api/recinto/reservas-presenciales', {
          cancha_id: Number(f.cancha.value), fecha: estado.panelFecha, hora_inicio: Number(f.hora.value), cliente_nombre: f.cliente.value
        });
        aviso('Reserva presencial registrada.');
        cargarPanel();
      } catch (e) { manejarError(e); }
    }
  },
  h('h2', {}, 'Registrar reserva presencial o telefónica'),
  h('div', { class: 'fila' },
    h('div', { class: 'campo' }, h('label', { for: 'pcancha' }, 'Cancha'),
      h('select', { id: 'pcancha', name: 'cancha' }, d.canchas.map((c) => h('option', { value: c.id }, c.nombre)))),
    h('div', { class: 'campo' }, h('label', { for: 'phora' }, 'Hora de inicio'),
      h('select', { id: 'phora', name: 'hora' }, Array.from({ length: 24 }, (_, i) => h('option', { value: i, selected: i === 19 }, hora(i))))),
    campo('pcliente', 'Nombre del cliente', { name: 'cliente', type: 'text', required: true, maxlength: 80 }),
    h('button', { class: 'btn', type: 'submit' }, 'Registrar')));
}

function formCancha() {
  return h('form', {
    class: 'tarjeta',
    onsubmit: async (ev) => {
      ev.preventDefault();
      const f = ev.target;
      try {
        await api('POST', '/api/recinto/canchas', {
          nombre: f.nombre.value, deporte: f.deporte.value, precio_hora: Number(f.precio.value),
          hora_apertura: Number(f.apertura.value), hora_cierre: Number(f.cierre.value)
        });
        aviso('Cancha creada.');
        cargarPanel();
      } catch (e) { manejarError(e); }
    }
  },
  h('h2', {}, 'Agregar una cancha'),
  h('div', { class: 'fila' },
    campo('cnombre', 'Nombre', { name: 'nombre', type: 'text', required: true, maxlength: 80, placeholder: 'Cancha 4' }),
    campo('cdeporte', 'Deporte', { name: 'deporte', type: 'text', required: true, maxlength: 80, placeholder: 'Fútbol 5' }),
    campo('cprecio', 'Precio por hora (CLP)', { name: 'precio', type: 'number', required: true, min: 1000, max: 200000, step: 500, value: 10000 }),
    campo('capertura', 'Apertura (hora)', { name: 'apertura', type: 'number', required: true, min: 0, max: 23, value: 9 }),
    campo('ccierre', 'Cierre (hora)', { name: 'cierre', type: 'number', required: true, min: 1, max: 24, value: 23 }),
    h('button', { class: 'btn', type: 'submit' }, 'Agregar')));
}

// ---------- arranque ----------
(async function iniciar() {
  try {
    const r = await api('GET', '/api/auth/me');
    estado.usuario = r.usuario;
    estado.vista = r.usuario.rol === 'ADMIN_RECINTO' ? 'panel' : 'buscar';
  } catch { /* sin sesión: se muestra el ingreso */ }
  render();
})();
