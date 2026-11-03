"use strict";
/**
 * Vulnerabilidades, etapa 2: enriquecimiento con KEV (CISA) y EPSS (FIRST), cachés propias, plazos
 * por cliente y recálculo de lo derivado (prioridad, plazo) en `vuln_hallazgos`.
 *
 * Las dos fuentes son públicas y gratuitas. En DefectDojo libre estos campos quedan vacíos (el
 * enriquecimiento automático es de su versión paga); acá se bajan solos una vez por día.
 *
 * 🔑 **Qué se baja.**
 *   - KEV: el catálogo entero de CISA (un JSON de ~2 MB y menos de 2.000 entradas) y se guarda
 *     completo en `vuln_kev`. Es chico y así un CVE nuevo que entra en una importación se marca en el
 *     acto, sin esperar a la próxima descarga.
 *   - EPSS: la API de FIRST por lotes de 100 CVE, SOLO para los CVE que hay en `vuln_hallazgos`
 *     (`vuln_epss`). Se descartó el CSV diario (~250.000 filas): para los pocos miles de CVE que
 *     tiene una instalación son unas decenas de pedidos chicos, sin bajar ni descomprimir nada grande
 *     en un servidor con poca memoria.
 *
 * 🔴 **Red.** Las URL son fijas (no las elige nadie desde afuera), con tiempo máximo, sin seguir
 * redirecciones (como notificaciones.js) y con tope de tamaño. Sin internet (on-premise aislado) no
 * se rompe nada: lo que ya estaba en la caché sigue valiendo, lo nuevo queda sin enriquecer y el
 * estado informa el error y la última actualización buena. `VULN_FUENTES_EXTERNAS=0` apaga la
 * descarga del todo (instalaciones sin salida a internet: así no esperan el tiempo máximo cada día).
 *
 * Cómo se usa (server.js):
 *
 *   const enr = enriquecimiento.crear({ qRow, qRows, qRun });
 *   enr.programar();               // diaria, en segundo plano
 */
const P = require("./vulnerabilidades-prioridad");

const URL_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const URL_EPSS = "https://api.first.org/data/v1/epss";
const CLAVE_ESTADO = "vuln_enriquecimiento";
const CLAVE_POLITICA = "vuln_plazos";
const TIEMPO_MAXIMO = 30000;
const MAX_BYTES = 20 * 1024 * 1024;
const PAUSA_EPSS = 300;
const LOTE_RECALCULO = 500;

const habilitada = () => !["0", "no", "off", "false"].includes(String(process.env.VULN_FUENTES_EXTERNAS ?? "").toLowerCase());

/** GET con tiempo máximo, sin redirecciones y con tope de tamaño. Usa el fetch de Node. */
async function descargarTexto(url, { timeout = TIEMPO_MAXIMO, maxBytes = MAX_BYTES, fetchImpl = globalThis.fetch } = {}) {
  const ctrl = new AbortController();
  const reloj = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetchImpl(url, { method: "GET", redirect: "error", signal: ctrl.signal, headers: { Accept: "application/json", "User-Agent": "Gungnir (AllSafe)" } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const largo = Number(r.headers?.get?.("content-length") || 0);
    if (largo > maxBytes) throw new Error("respuesta demasiado grande");
    const texto = await r.text();
    if (texto.length > maxBytes) throw new Error("respuesta demasiado grande");
    return texto;
  } catch (e) {
    throw new Error(e?.name === "AbortError" ? "tiempo de espera agotado" : (e?.cause?.code || e?.message || "error de red"));
  } finally { clearTimeout(reloj); }
}

const esperar = (ms) => new Promise((r) => setTimeout(r, ms));

/** Tablas de la etapa 2 y columnas nuevas en `vuln_hallazgos`. Idempotente; va después de `crearTablas`. */
async function crearTablas({ qRows, qRun }) {
  const cotejo = (await qRows(
    "SELECT CHARACTER_SET_NAME AS cs, COLLATION_NAME AS co FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'clients' AND COLUMN_NAME = 'id'"))[0];
  const deCliente = cotejo?.cs && cotejo?.co ? ` CHARACTER SET ${cotejo.cs} COLLATE ${cotejo.co}` : "";

  const columnas = new Set((await qRows(
    "SELECT COLUMN_NAME AS c FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vuln_hallazgos'")).map((f) => f.c));
  // ⚠️ Sin ADD COLUMN IF NOT EXISTS (no existe en MySQL 8): se mira information_schema.
  const nuevas = {
    prioridad: "VARCHAR(10) NULL",
    kev_ransomware: "TINYINT(1) NULL",
    kev_vence: "DATE NULL",
    kev_desde: "DATETIME NULL",
    plazo_desde: "DATETIME NULL",
  };
  for (const [c, def] of Object.entries(nuevas)) {
    if (!columnas.has(c)) await qRun(`ALTER TABLE vuln_hallazgos ADD COLUMN ${c} ${def}`);
  }
  const indices = new Set((await qRows(
    "SELECT DISTINCT INDEX_NAME AS i FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vuln_hallazgos'")).map((f) => f.i));
  if (!indices.has("idx_vh_prioridad")) await qRun("ALTER TABLE vuln_hallazgos ADD INDEX idx_vh_prioridad (cliente_id, prioridad)");
  if (!indices.has("idx_vh_limite")) await qRun("ALTER TABLE vuln_hallazgos ADD INDEX idx_vh_limite (cliente_id, fecha_limite)");

  await qRun(`CREATE TABLE IF NOT EXISTS vuln_kev (
    cve          VARCHAR(20)  PRIMARY KEY,
    nombre       VARCHAR(300) NULL,
    proveedor    VARCHAR(120) NULL,
    producto     VARCHAR(200) NULL,
    -- dateAdded y dueDate del catálogo de CISA.
    alta         DATE         NULL,
    vence        DATE         NULL,
    ransomware   TINYINT(1)   NOT NULL DEFAULT 0,
    actualizado  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await qRun(`CREATE TABLE IF NOT EXISTS vuln_epss (
    cve          VARCHAR(20)  PRIMARY KEY,
    epss         DECIMAL(6,5) NOT NULL,
    percentil    DECIMAL(6,5) NULL,
    -- Fecha del modelo de FIRST que dio el puntaje.
    fecha        DATE         NULL,
    actualizado  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // Plazos propios de un cliente. Sin fila rige la política global (settings `vuln_plazos`).
  // NULL en una severidad = sin plazo para esa severidad.
  await qRun(`CREATE TABLE IF NOT EXISTS vuln_plazos_cliente (
    cliente_id   VARCHAR(36)${deCliente} PRIMARY KEY,
    critical     INT          NULL,
    high         INT          NULL,
    medium       INT          NULL,
    low          INT          NULL,
    info         INT          NULL,
    usuario      VARCHAR(80)  NULL,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_vpc_cliente FOREIGN KEY (cliente_id) REFERENCES clients(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
}

function crear({ qRow, qRows, qRun, fetchImpl = globalThis.fetch, pausa = PAUSA_EPSS, log = console } = {}) {
  // ── Estado (settings) ─────────────────────────────────────────────────────────────────────────
  async function leerJson(clave) {
    const f = await qRow("SELECT `value` FROM settings WHERE `key` = ?", [clave]).catch(() => null);
    if (!f?.value) return null;
    try { return JSON.parse(f.value); } catch { return null; }
  }
  const guardarJson = (clave, v) => qRun("INSERT INTO settings (`key`,`value`) VALUES (?,?) ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)", [clave, JSON.stringify(v)]);

  async function estado() {
    const e = (await leerJson(CLAVE_ESTADO)) || {};
    const [k, ep] = await Promise.all([
      qRow("SELECT COUNT(*) AS n FROM vuln_kev").catch(() => null),
      qRow("SELECT COUNT(*) AS n, MAX(fecha) AS fecha FROM vuln_epss").catch(() => null),
    ]);
    return {
      habilitada: habilitada(), en_curso: !!corriendo,
      kev: { ...(e.kev || {}), cantidad: Number(k?.n || 0) },
      epss: { ...(e.epss || {}), cantidad: Number(ep?.n || 0), fecha_modelo: P.ymd(ep?.fecha) },
    };
  }
  async function anotarEstado(fuente, cambios) {
    const e = (await leerJson(CLAVE_ESTADO)) || {};
    e[fuente] = { ...(e[fuente] || {}), ...cambios };
    await guardarJson(CLAVE_ESTADO, e);
  }
  const ahoraTexto = () => { const d = new Date(); return `${P.ymd(d)} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`; };

  // ── Políticas de plazos ───────────────────────────────────────────────────────────────────────
  async function politicaGlobal() {
    const g = await leerJson(CLAVE_POLITICA);
    const v = g ? P.validarPolitica(g) : null;
    return v?.politica || { ...P.POLITICA_DEFECTO };
  }
  async function guardarPoliticaGlobal(p) { await guardarJson(CLAVE_POLITICA, p); }
  async function politicaDelCliente(cliente) {
    const f = await qRow("SELECT critical, high, medium, low, info FROM vuln_plazos_cliente WHERE cliente_id = ?", [cliente]).catch(() => null);
    if (!f) return null;
    return Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v == null ? null : Number(v)]));
  }
  async function guardarPoliticaCliente(cliente, p, usuario) {
    await qRun(`INSERT INTO vuln_plazos_cliente (cliente_id, critical, high, medium, low, info, usuario) VALUES (?,?,?,?,?,?,?)
      ON DUPLICATE KEY UPDATE critical=VALUES(critical), high=VALUES(high), medium=VALUES(medium), low=VALUES(low), info=VALUES(info), usuario=VALUES(usuario)`,
    [cliente, p.critical, p.high, p.medium, p.low, p.info, usuario || null]);
  }
  async function borrarPoliticaCliente(cliente) { await qRun("DELETE FROM vuln_plazos_cliente WHERE cliente_id = ?", [cliente]); }

  // ── Recálculo de lo derivado ──────────────────────────────────────────────────────────────────
  /**
   * Recalcula EPSS, KEV, prioridad y plazo de los hallazgos (todos, los de un cliente o unos ids) y
   * escribe solo lo que cambió. Va por lotes (keyset por id) para no cargar todo en memoria.
   *
   * @param db  { qRows, qRun } (puede ser una transacción); por defecto el pool
   */
  async function recalcular({ cliente = null, ids = null, soloSinPrioridad = false, db = null } = {}) {
    const q = db || { qRows, qRun };
    if (ids && ids.length > LOTE_RECALCULO) {
      const total = { revisados: 0, cambiados: 0 };
      for (const t of P.lotes([...new Set(ids)], LOTE_RECALCULO)) {
        const r = await recalcular({ cliente, ids: t, soloSinPrioridad, db });
        total.revisados += r.revisados; total.cambiados += r.cambiados;
      }
      return total;
    }
    const global = await politicaGlobal();
    const politicas = new Map();
    const politicaDe = async (c) => {
      if (!politicas.has(c)) {
        const f = (await q.qRows("SELECT critical, high, medium, low, info FROM vuln_plazos_cliente WHERE cliente_id = ?", [c]).catch(() => []))[0];
        politicas.set(c, P.politicaEfectiva(f ? Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v == null ? null : Number(v)])) : null, global));
      }
      return politicas.get(c);
    };
    const kevCargado = Number((await q.qRows("SELECT COUNT(*) AS n FROM vuln_kev").catch(() => [{ n: 0 }]))[0]?.n || 0) > 0;
    let ultimo = "", cambiados = 0, revisados = 0;
    const listaIds = ids ? [...new Set(ids)] : null;
    for (;;) {
      const w = ["id > ?"], p = [ultimo];
      if (cliente) { w.push("cliente_id = ?"); p.push(cliente); }
      if (soloSinPrioridad) w.push("prioridad IS NULL");
      if (listaIds) {
        if (!listaIds.length) break;
        w.push(`id IN (${listaIds.map(() => "?").join(",")})`); p.push(...listaIds);
      }
      const filas = await q.qRows(
        `SELECT id, cliente_id, cves, severidad, estado, primera_vez, plazo_desde, epss, epss_percentil, kev, kev_ransomware,
                kev_vence, kev_desde, prioridad, fecha_limite
           FROM vuln_hallazgos WHERE ${w.join(" AND ")} ORDER BY id LIMIT ${LOTE_RECALCULO}`, p);
      if (!filas.length) break;
      ultimo = filas[filas.length - 1].id;
      const cves = [...new Set(filas.flatMap((f) => P.cvesDe(f.cves)))];
      const epssPorCve = new Map(), kevPorCve = new Map();
      for (const t of P.lotes(cves, 500)) {
        const marcas = t.map(() => "?").join(",");
        for (const e of await q.qRows(`SELECT cve, epss, percentil FROM vuln_epss WHERE cve IN (${marcas})`, t)) epssPorCve.set(e.cve, e);
        for (const k of await q.qRows(`SELECT cve, vence, ransomware FROM vuln_kev WHERE cve IN (${marcas})`, t)) kevPorCve.set(k.cve, k);
      }
      for (const f of filas) {
        revisados++;
        const c = P.calcular(f, { epssPorCve, kevPorCve, kevCargado, politica: await politicaDe(f.cliente_id) });
        const sets = [], vals = [];
        const num = (v) => (v == null ? null : Math.round(Number(v) * 100000) / 100000);
        const distinto = (a, b) => (a == null ? null : String(a)) !== (b == null ? null : String(b));
        if (distinto(num(f.epss), num(c.epss))) { sets.push("epss = ?"); vals.push(c.epss); }
        if (distinto(num(f.epss_percentil), num(c.epss_percentil))) { sets.push("epss_percentil = ?"); vals.push(c.epss_percentil); }
        if (distinto(f.kev == null ? null : Number(f.kev), c.kev)) {
          sets.push("kev = ?"); vals.push(c.kev);
          // Desde cuándo está en KEV para nosotros: lo usa el resumen semanal ("nuevas en KEV").
          if (c.kev === 1) sets.push("kev_desde = NOW()"); else sets.push("kev_desde = NULL");
        }
        if (distinto(f.kev_ransomware == null ? null : Number(f.kev_ransomware), c.kev_ransomware)) { sets.push("kev_ransomware = ?"); vals.push(c.kev_ransomware); }
        if (distinto(P.ymd(f.kev_vence), c.kev_vence)) { sets.push("kev_vence = ?"); vals.push(c.kev_vence); }
        if (distinto(f.prioridad, c.prioridad)) { sets.push("prioridad = ?"); vals.push(c.prioridad); }
        if (distinto(P.ymd(f.fecha_limite), c.fecha_limite)) { sets.push("fecha_limite = ?"); vals.push(c.fecha_limite); }
        if (sets.length) {
          // updated_at se deja como estaba: un recálculo no es una edición.
          await q.qRun(`UPDATE vuln_hallazgos SET ${sets.join(", ")}, updated_at = updated_at WHERE id = ?`, [...vals, f.id]);
          cambiados++;
        }
      }
      if (listaIds || filas.length < LOTE_RECALCULO) break;
    }
    return { revisados, cambiados };
  }

  // ── Descargas ─────────────────────────────────────────────────────────────────────────────────
  async function actualizarKev() {
    const intento = ahoraTexto();
    try {
      const kev = P.parsearKev(await descargarTexto(URL_KEV, { fetchImpl }));
      // Upsert de todo el catálogo y baja de lo que CISA sacó (pasa muy poco: se corrigen errores).
      for (const t of P.lotes(kev.items, 200)) {
        await qRun(`INSERT INTO vuln_kev (cve, nombre, proveedor, producto, alta, vence, ransomware, actualizado)
          VALUES ${t.map(() => "(?,?,?,?,?,?,?,NOW())").join(",")}
          ON DUPLICATE KEY UPDATE nombre=VALUES(nombre), proveedor=VALUES(proveedor), producto=VALUES(producto), alta=VALUES(alta),
            vence=VALUES(vence), ransomware=VALUES(ransomware), actualizado=VALUES(actualizado)`,
        t.flatMap((k) => [k.cve, k.nombre, k.proveedor, k.producto, k.alta, k.vence, k.ransomware]));
      }
      const enCatalogo = new Set(kev.items.map((k) => k.cve));
      const guardados = await qRows("SELECT cve FROM vuln_kev");
      const sobran = guardados.map((g) => g.cve).filter((c) => !enCatalogo.has(c));
      for (const t of P.lotes(sobran, 200)) await qRun(`DELETE FROM vuln_kev WHERE cve IN (${t.map(() => "?").join(",")})`, t);
      await anotarEstado("kev", { ultimo_intento: intento, ultima_ok: intento, error: null, version: kev.version, publicado: kev.publicado });
      return { ok: true, cantidad: kev.items.length, version: kev.version };
    } catch (e) {
      await anotarEstado("kev", { ultimo_intento: intento, error: e.message }).catch(() => {});
      return { ok: false, error: e.message };
    }
  }

  /** CVE de los hallazgos (todos o de un cliente); con `soloFaltantes`, los que no están en la caché. */
  async function cvesAConsultar({ cliente = null, soloFaltantes = false } = {}) {
    const filas = await qRows(`SELECT DISTINCT cves FROM vuln_hallazgos WHERE cves IS NOT NULL${cliente ? " AND cliente_id = ?" : ""}`, cliente ? [cliente] : []);
    let cves = [...new Set(filas.flatMap((f) => P.cvesDe(f.cves)))].sort();
    if (soloFaltantes && cves.length) {
      const ya = new Set();
      for (const t of P.lotes(cves, 500)) for (const f of await qRows(`SELECT cve FROM vuln_epss WHERE cve IN (${t.map(() => "?").join(",")})`, t)) ya.add(f.cve);
      cves = cves.filter((c) => !ya.has(c));
    }
    return cves;
  }

  async function actualizarEpss(opciones = {}) {
    const intento = ahoraTexto();
    let guardados = 0;
    try {
      const cves = await cvesAConsultar(opciones);
      let fechaModelo = null;
      const grupos = P.lotes(cves, 100);
      for (let i = 0; i < grupos.length; i++) {
        if (i && pausa) await esperar(pausa);
        const url = `${URL_EPSS}?cve=${grupos[i].map(encodeURIComponent).join(",")}`;
        const filas = P.parsearEpss(await descargarTexto(url, { fetchImpl }));
        if (!filas.length) continue;
        await qRun(`INSERT INTO vuln_epss (cve, epss, percentil, fecha, actualizado) VALUES ${filas.map(() => "(?,?,?,?,NOW())").join(",")}
          ON DUPLICATE KEY UPDATE epss=VALUES(epss), percentil=VALUES(percentil), fecha=VALUES(fecha), actualizado=VALUES(actualizado)`,
        filas.flatMap((f) => [f.cve, f.epss, f.percentil, f.fecha]));
        guardados += filas.length;
        fechaModelo = filas.find((f) => f.fecha)?.fecha || fechaModelo;
      }
      if (!opciones.cliente) await anotarEstado("epss", { ultimo_intento: intento, ultima_ok: intento, error: null, consultados: cves.length, ...(fechaModelo ? { fecha_modelo_ultima: fechaModelo } : {}) });
      return { ok: true, consultados: cves.length, guardados };
    } catch (e) {
      if (!opciones.cliente) await anotarEstado("epss", { ultimo_intento: intento, error: e.message }).catch(() => {});
      return { ok: false, error: e.message, guardados };
    }
  }

  let corriendo = null;
  /** Descarga KEV y EPSS y recalcula todo. Una sola corrida a la vez. */
  function actualizarTodo() {
    if (corriendo) return corriendo;
    corriendo = (async () => {
      if (!habilitada()) {
        const r = await recalcular();
        return { kev: { ok: false, error: "deshabilitada" }, epss: { ok: false, error: "deshabilitada" }, recalculo: r };
      }
      const kev = await actualizarKev();
      const epss = await actualizarEpss();
      const recalculo = await recalcular();
      return { kev, epss, recalculo };
    })().finally(() => { corriendo = null; });
    return corriendo;
  }

  /**
   * Después de una importación: los CVE nuevos de ese cliente que la caché de EPSS no tiene se
   * consultan en segundo plano y se recalcula ese cliente. KEV no hace falta: la caché es el catálogo
   * entero y el recálculo dentro de la importación ya lo aplicó.
   */
  function completarCliente(cliente) {
    if (!habilitada()) return Promise.resolve(null);
    return actualizarEpss({ cliente, soloFaltantes: true })
      .then((r) => (r.guardados ? recalcular({ cliente }) : null))
      .catch((e) => { log.error?.("[vulnerabilidades] EPSS del cliente:", e.message); return null; });
  }

  /** Diaria: a los 3 minutos de arrancar (lo pendiente de prioridad) y cada 24 horas la descarga. */
  function programar() {
    const UN_DIA = 24 * 60 * 60 * 1000;
    const correr = () => actualizarTodo()
      .then((r) => log.log?.(`[vulnerabilidades] KEV ${r.kev.ok ? "ok" : r.kev.error}, EPSS ${r.epss.ok ? "ok" : r.epss.error}, ${r.recalculo.cambiados} recalculadas`))
      .catch((e) => log.error?.("[vulnerabilidades] enriquecimiento:", e.message));
    // Al arrancar solo se completa lo que no tiene prioridad (instalaciones que vienen de la 1.7.0);
    // la descarga va más tarde: un reinicio en loop no golpea a CISA ni a FIRST.
    setTimeout(() => recalcular({ soloSinPrioridad: true }).catch((e) => log.error?.("[vulnerabilidades] recálculo inicial:", e.message)), 60 * 1000).unref?.();
    setTimeout(correr, 10 * 60 * 1000).unref?.();
    return setInterval(correr, UN_DIA).unref?.();
  }

  const enCurso = () => !!corriendo;

  return {
    estado, recalcular, enCurso, actualizarKev, actualizarEpss, actualizarTodo, completarCliente, programar,
    politicaGlobal, guardarPoliticaGlobal, politicaDelCliente, guardarPoliticaCliente, borrarPoliticaCliente, cvesAConsultar,
  };
}

module.exports = { crear, crearTablas, descargarTexto, URL_KEV, URL_EPSS, CLAVE_ESTADO, CLAVE_POLITICA, habilitada };
