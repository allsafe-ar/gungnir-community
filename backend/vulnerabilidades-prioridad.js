"use strict";
/**
 * Vulnerabilidades, etapa 2: priorización, plazos y métricas. Lógica pura (sin base ni red), para
 * poder probarla sola. La descarga de KEV y EPSS y la escritura en la base viven en
 * `vulnerabilidades-enriquecimiento.js`.
 *
 * 🔑 **Prioridad.** Es un dato calculado que NO reemplaza a la severidad: la severidad dice cuánto
 * daño haría, la prioridad dice qué conviene arreglar primero según si se está explotando (KEV de
 * CISA) y qué tan probable es que se explote en los próximos 30 días (EPSS de FIRST). La severidad
 * pone un piso y EPSS/KEV solo suben; un dato que falta (sin CVE, sin red) nunca baja la prioridad.
 *
 *   urgente  en KEV (explotada hoy), o crítica con EPSS >= 0,5
 *   alta     crítica; o alta con EPSS >= 0,1; o media/baja con EPSS >= 0,5
 *   media    alta; o media; o baja con EPSS >= 0,1
 *   baja     baja; informativa
 *
 * 🔑 **Plazo (SLA).** `fecha_limite = desde + días de la política según la severidad`, donde `desde`
 * es la primera vez que se vio o la última reapertura. Política por defecto: crítica 7, alta 30,
 * media 90, baja 120 días; informativa sin plazo. Cada cliente puede tener la suya; si no, rige la
 * global. Si la vulnerabilidad está en KEV, el plazo se acorta a 15 días desde que se detectó como
 * máximo, y también al `dueDate` de CISA cuando esa fecha es posterior a la detección.
 *
 *   ⚠️ El `dueDate` de CISA es el plazo que la directiva BOD les fija a las agencias federales de
 *   EE.UU., contado desde que la CVE entró al catálogo. Para una CVE que entró hace años es una fecha
 *   pasada: usarlo siempre dejaría vencida el mismo día de la detección algo que nadie pudo atender.
 *   Por eso solo cuenta si cae después de la detección; si no, rigen los 15 días.
 *
 * Estados del plazo (solo para abiertas, en remediación y reabiertas): `en_plazo`, `por_vencer` (faltan
 * 7 días o menos, incluido el día límite) y `vencida` (pasó el día límite). Remediadas, riesgo
 * aceptado y falso positivo no vencen (`no_aplica`). Sin política para esa severidad: `sin_plazo`.
 *
 * Las fechas de calendario se arman con los componentes locales (nunca con toISOString): la hora de
 * corte depende de la zona del servidor.
 */
const { ABIERTOS, SEVERIDADES } = require("./vulnerabilidades-motor");

const PRIORIDADES = ["urgente", "alta", "media", "baja"];
const ESTADOS_PLAZO = ["vencida", "por_vencer", "en_plazo", "sin_plazo", "no_aplica"];
const POLITICA_DEFECTO = Object.freeze({ critical: 7, high: 30, medium: 90, low: 120, info: null });
/** Tope de días para lo que está en KEV, contado desde la detección (o la reapertura). */
const KEV_DIAS_MAX = 15;
const POR_VENCER_DIAS = 7;
const EPSS_ALTO = 0.5;
const EPSS_MEDIO = 0.1;
const MAX_DIAS_POLITICA = 3650;
const TRAMOS_ANTIGUEDAD = ["0-30", "31-90", "91-180", "180+"];
const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

// ── Fechas de calendario (locales) ─────────────────────────────────────────────────────────────
const dos = (n) => String(n).padStart(2, "0");

/** "YYYY-MM-DD" con la fecha local. Acepta Date, "YYYY-MM-DD" o "YYYY-MM-DD HH:MM:SS". */
function ymd(v) {
  if (v == null || v === "") return null;
  if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}(?:$|[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$)/.test(v)) return v.slice(0, 10);
  const d = v instanceof Date ? v : new Date(v);
  if (Number.isNaN(d.getTime())) return null;
  return `${d.getFullYear()}-${dos(d.getMonth() + 1)}-${dos(d.getDate())}`;
}

function partes(s) { const [y, m, d] = s.split("-").map(Number); return [y, m - 1, d]; }

function sumarDias(fecha, n) {
  const [y, m, d] = partes(ymd(fecha));
  const x = new Date(y, m, d + n);
  return ymd(x);
}

/** Días de calendario de `a` a `b` (b - a). */
function diasEntre(a, b) {
  const [y1, m1, d1] = partes(ymd(a)), [y2, m2, d2] = partes(ymd(b));
  return Math.round((Date.UTC(y2, m2, d2) - Date.UTC(y1, m1, d1)) / 86400000);
}

function hoyLocal(ahora = new Date()) { return ymd(ahora); }

const menor = (a, b) => (a == null ? b : b == null ? a : (a < b ? a : b));

// ── KEV y EPSS ──────────────────────────────────────────────────────────────────────────────────
const fechaValida = (s) => (typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : null);
const recorte = (s, n) => (s == null || s === "" ? null : String(s).slice(0, n));

/**
 * Catálogo KEV de CISA (known_exploited_vulnerabilities.json). Devuelve lo que se guarda en la caché.
 * Falla si el formato no es el esperado: un archivo roto nunca vacía la caché.
 */
function parsearKev(json) {
  const o = typeof json === "string" ? JSON.parse(json) : json;
  if (!o || !Array.isArray(o.vulnerabilities)) throw new Error("el catálogo KEV no tiene el formato esperado");
  const vistos = new Map();
  for (const v of o.vulnerabilities) {
    const cve = String(v?.cveID || "").trim().toUpperCase();
    if (!CVE_RE.test(cve)) continue;
    vistos.set(cve, {
      cve,
      nombre: recorte(v.vulnerabilityName, 300),
      proveedor: recorte(v.vendorProject, 120),
      producto: recorte(v.product, 200),
      alta: fechaValida(v.dateAdded),
      vence: fechaValida(v.dueDate),
      ransomware: String(v.knownRansomwareCampaignUse || "").toLowerCase() === "known" ? 1 : 0,
    });
  }
  if (!vistos.size) throw new Error("el catálogo KEV llegó vacío");
  return { version: recorte(o.catalogVersion, 40), publicado: recorte(o.dateReleased, 40), items: [...vistos.values()] };
}

/** Respuesta de la API de EPSS de FIRST (`/data/v1/epss?cve=...`). */
function parsearEpss(json) {
  const o = typeof json === "string" ? JSON.parse(json) : json;
  if (!o || !Array.isArray(o.data)) throw new Error("la respuesta de EPSS no tiene el formato esperado");
  const out = [];
  for (const f of o.data) {
    const cve = String(f?.cve || "").trim().toUpperCase();
    const epss = Number(f?.epss), percentil = Number(f?.percentile);
    if (!CVE_RE.test(cve) || !Number.isFinite(epss) || epss < 0 || epss > 1) continue;
    out.push({ cve, epss, percentil: Number.isFinite(percentil) && percentil >= 0 && percentil <= 1 ? percentil : null, fecha: fechaValida(f.date) });
  }
  return out;
}

/** Lotes de CVE para la API de EPSS (acepta hasta 100 por pedido). */
function lotes(arr, n = 100) { const o = []; for (let i = 0; i < arr.length; i += n) o.push(arr.slice(i, i + n)); return o; }

/** CVE de la columna `cves` ("CVE-1,CVE-2"). */
function cvesDe(s) {
  return [...new Set(String(s || "").split(/[\s,;]+/).map((c) => c.trim().toUpperCase()).filter((c) => CVE_RE.test(c)))];
}

/**
 * Lo que el hallazgo toma de las cachés. Con varios CVE: el EPSS más alto (y su percentil más alto),
 * KEV si cualquiera está, ransomware si cualquiera de los que están en KEV lo tiene, y el `dueDate`
 * más cercano. `kevCargado` falso (nunca se pudo bajar el catálogo) deja `kev` en null: no se sabe.
 */
function combinar(cves, epssPorCve, kevPorCve, kevCargado = true) {
  let epss = null, percentil = null, kev = kevCargado ? 0 : null, ransomware = kevCargado ? 0 : null, vence = null;
  for (const c of cves) {
    const e = epssPorCve.get(c);
    if (e && e.epss != null) {
      if (epss == null || Number(e.epss) > epss) epss = Number(e.epss);
      if (e.percentil != null && (percentil == null || Number(e.percentil) > percentil)) percentil = Number(e.percentil);
    }
    const k = kevPorCve.get(c);
    if (k) {
      kev = 1;
      if (Number(k.ransomware) === 1) ransomware = 1;
      vence = menor(vence, ymd(k.vence));
    }
  }
  return { epss, epss_percentil: percentil, kev, kev_ransomware: kev ? ransomware : (kevCargado ? 0 : null), kev_vence: kev ? vence : null };
}

// ── Prioridad ───────────────────────────────────────────────────────────────────────────────────
/** La regla de arriba. `epss` null (sin dato) cuenta como 0: no baja nada, tampoco sube. */
function prioridad({ severidad, epss, kev }) {
  const e = epss == null ? 0 : Number(epss);
  if (Number(kev) === 1) return "urgente";
  switch (severidad) {
    case "critical": return e >= EPSS_ALTO ? "urgente" : "alta";
    case "high": return e >= EPSS_MEDIO ? "alta" : "media";
    case "medium": return e >= EPSS_ALTO ? "alta" : "media";
    case "low": return e >= EPSS_ALTO ? "alta" : e >= EPSS_MEDIO ? "media" : "baja";
    default: return "baja";
  }
}

// ── Plazos ──────────────────────────────────────────────────────────────────────────────────────
/** Normaliza una política: días enteros de 1 a 3650 por severidad, o null (sin plazo). */
function validarPolitica(p) {
  if (!p || typeof p !== "object") return { error: "Falta la política de plazos." };
  const out = {};
  for (const s of SEVERIDADES) {
    const v = p[s];
    if (v === null || v === undefined || v === "") { out[s] = null; continue; }
    const n = Number(v);
    if (!Number.isInteger(n) || n < 1 || n > MAX_DIAS_POLITICA) return { error: `El plazo de ${s} tiene que ser un número entero de días entre 1 y ${MAX_DIAS_POLITICA}, o quedar vacío.` };
    out[s] = n;
  }
  return { politica: out };
}

/** Política efectiva: la del cliente si tiene, si no la global, si no la de fábrica. */
function politicaEfectiva(delCliente, global) {
  const base = global ? { ...POLITICA_DEFECTO, ...global } : { ...POLITICA_DEFECTO };
  return delCliente ? { ...base, ...delCliente } : base;
}

/**
 * Día límite (YYYY-MM-DD) o null.
 * @param desde     primera vez que se vio o la última reapertura
 * @param kev       1 si está en KEV; `kev_vence` el dueDate de CISA más cercano de sus CVE
 */
function fechaLimite({ desde, severidad, politica, kev, kev_vence }) {
  const inicio = ymd(desde);
  if (!inicio) return null;
  const dias = (politica || POLITICA_DEFECTO)[severidad];
  let limite = dias == null ? null : sumarDias(inicio, dias);
  if (Number(kev) === 1) {
    let tope = sumarDias(inicio, KEV_DIAS_MAX);
    const cisa = ymd(kev_vence);
    if (cisa && cisa >= inicio) tope = menor(tope, cisa);
    limite = menor(limite, tope);
  }
  return limite;
}

function estadoPlazo({ estado, fecha_limite }, hoy = hoyLocal()) {
  if (!ABIERTOS.includes(estado)) return "no_aplica";
  const lim = ymd(fecha_limite);
  if (!lim) return "sin_plazo";
  const faltan = diasEntre(hoy, lim);
  if (faltan < 0) return "vencida";
  if (faltan <= POR_VENCER_DIAS) return "por_vencer";
  return "en_plazo";
}

/**
 * Todo lo calculado de un hallazgo, a partir de sus datos y de las cachés. Devuelve solo los campos
 * calculados; quien llama compara y escribe lo que cambió.
 */
function calcular(h, { epssPorCve, kevPorCve, kevCargado, politica }) {
  const c = combinar(cvesDe(h.cves), epssPorCve, kevPorCve, kevCargado);
  return {
    ...c,
    prioridad: prioridad({ severidad: h.severidad, epss: c.epss, kev: c.kev }),
    fecha_limite: fechaLimite({ desde: h.plazo_desde || h.primera_vez, severidad: h.severidad, politica, kev: c.kev, kev_vence: c.kev_vence }),
  };
}

// ── Métricas ────────────────────────────────────────────────────────────────────────────────────
function tramoAntiguedad(dias) {
  if (dias <= 30) return "0-30";
  if (dias <= 90) return "31-90";
  if (dias <= 180) return "91-180";
  return "180+";
}

/** Abiertas por prioridad, plazo, KEV y antigüedad (desde la primera vez que se vio). */
function resumenAbiertas(filas, hoy = hoyLocal()) {
  const out = {
    por_prioridad: Object.fromEntries(PRIORIDADES.map((p) => [p, 0])),
    vencidas: 0, por_vencer: 0, en_kev: 0, kev_ransomware: 0,
    antiguedad: Object.fromEntries(TRAMOS_ANTIGUEDAD.map((t) => [t, 0])),
  };
  for (const f of filas) {
    if (!ABIERTOS.includes(f.estado)) continue;
    const p = PRIORIDADES.includes(f.prioridad) ? f.prioridad : "baja";
    out.por_prioridad[p]++;
    const e = estadoPlazo(f, hoy);
    if (e === "vencida") out.vencidas++;
    else if (e === "por_vencer") out.por_vencer++;
    if (Number(f.kev) === 1) { out.en_kev++; if (Number(f.kev_ransomware) === 1) out.kev_ransomware++; }
    const desde = ymd(f.primera_vez);
    if (desde) out.antiguedad[tramoAntiguedad(Math.max(0, diasEntre(desde, hoy)))]++;
  }
  return out;
}

/**
 * Tiempo medio de remediación por severidad: de la primera vez que se vio al cierre, en días con un
 * decimal. Solo lo remediado (riesgo aceptado y falso positivo no son remediación) y cerrado en la
 * ventana (90 días por defecto).
 */
function mttr(filas, ahora = new Date(), ventanaDias = 90) {
  const desde = ahora.getTime() - ventanaDias * 86400000;
  const acc = Object.fromEntries(SEVERIDADES.map((s) => [s, { suma: 0, n: 0 }]));
  for (const f of filas) {
    if (f.estado !== "remediado" || !f.fecha_cierre || !f.primera_vez || !acc[f.severidad]) continue;
    const ini = new Date(f.primera_vez).getTime(), fin = new Date(f.fecha_cierre).getTime();
    if (!Number.isFinite(ini) || !Number.isFinite(fin) || fin < desde || fin > ahora.getTime() || fin < ini) continue;
    acc[f.severidad].suma += (fin - ini) / 86400000;
    acc[f.severidad].n++;
  }
  return Object.fromEntries(SEVERIDADES.map((s) => [s, { dias: acc[s].n ? Math.round((acc[s].suma / acc[s].n) * 10) / 10 : null, cerradas: acc[s].n }]));
}

/**
 * Abiertas al cierre de cada una de las últimas `semanas` semanas (la última termina hoy),
 * reconstruidas con el historial: el estado de un hallazgo en un momento es el `estado_despues` del
 * último evento hasta ese momento.
 *
 * @param eventos  [{ hallazgo_id, estado_despues, created_at }] de un cliente
 */
function tendencia(eventos, ahora = new Date(), semanas = 12) {
  const ordenados = eventos
    .map((e) => ({ ...e, t: new Date(e.created_at).getTime() }))
    .filter((e) => Number.isFinite(e.t) && e.estado_despues)
    .sort((a, b) => a.t - b.t);
  const hoy = hoyLocal(ahora);
  const cortes = [];
  for (let i = semanas - 1; i >= 0; i--) {
    const dia = sumarDias(hoy, -7 * i);
    const [y, m, d] = partes(dia);
    cortes.push({ semana: dia, fin: new Date(y, m, d, 23, 59, 59, 999).getTime() });
  }
  const estado = new Map();
  let abiertas = 0, j = 0;
  const puntos = [];
  for (const c of cortes) {
    while (j < ordenados.length && ordenados[j].t <= c.fin) {
      const e = ordenados[j++];
      const antes = ABIERTOS.includes(estado.get(e.hallazgo_id));
      const despues = ABIERTOS.includes(e.estado_despues);
      estado.set(e.hallazgo_id, e.estado_despues);
      abiertas += (despues ? 1 : 0) - (antes ? 1 : 0);
    }
    puntos.push({ semana: c.semana, abiertas });
  }
  return puntos;
}

module.exports = {
  PRIORIDADES, ESTADOS_PLAZO, POLITICA_DEFECTO, KEV_DIAS_MAX, POR_VENCER_DIAS, EPSS_ALTO, EPSS_MEDIO, TRAMOS_ANTIGUEDAD, CVE_RE,
  ymd, sumarDias, diasEntre, hoyLocal,
  parsearKev, parsearEpss, lotes, cvesDe, combinar, prioridad,
  validarPolitica, politicaEfectiva, fechaLimite, estadoPlazo, calcular,
  resumenAbiertas, mttr, tendencia, tramoAntiguedad,
};
