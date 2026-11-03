"use strict";
/**
 * Vulnerabilidades: motor del seguimiento continuo por cliente (deduplicación, cierre y reapertura).
 *
 * Es lo que hace útil reimportar el mismo escaneo cada semana: no se cargan los mismos hallazgos de
 * nuevo, se sabe qué es nuevo, qué se arregló y qué volvió. Las rutas viven en `vulnerabilidades.js`;
 * acá no hay Express, para poder probarlo solo.
 *
 * 🔑 **Clave de deduplicación (v1).** Un hallazgo es el mismo entre importaciones, y entre
 * herramientas, si coinciden el activo, el puerto y lo que lo identifica:
 *
 *   clave = sha256("v1|" + activo_id + "|" + puerto/protocolo + "|" + identificador)
 *
 *   identificador = "cve:"    + CVE ordenados y separados por coma, si el hallazgo trae alguno;
 *                   si no,  "regla:" + id de la regla de la herramienta (nessus:<plugin>,
 *                                     openvas:<oid>, zap:<pluginid>, burp:<type>, nmap:puerto-abierto);
 *                   si no,  "titulo:" + título normalizado (minúsculas, sin acentos, solo letras y
 *                                     números separados por un espacio).
 *
 *   puerto/protocolo = "443/tcp", o vacío si el hallazgo no es de un puerto.
 *
 * La fuente NO entra en la clave: el mismo CVE en el mismo puerto del mismo equipo, visto por
 * OpenVAS y por Nessus, es una sola vulnerabilidad. La regla sí lleva el nombre de la herramienta
 * adelante, porque los números de plugin de dos herramientas pueden coincidir sin ser lo mismo.
 * Cambiar la fórmula obliga a recalcular todas las claves: por eso lleva versión ("v1").
 *
 * 🔑 **El cierre por ausencia vale solo dentro del mismo alcance.** Un hallazgo abierto se cierra
 * solo (pasa a `remediado`) si es de la MISMA fuente que la importación, su activo estaba entre los
 * equipos que ese escaneo cubrió y no apareció. Un escaneo de la red A no puede cerrar lo de la red B,
 * ni un Nmap cerrar lo que encontró un Nessus.
 *
 * ⚠️ `riesgo_aceptado` y `falso_positivo` son decisiones de una persona: ninguna importación las
 * cierra ni las reabre. Solo se anota que se volvió a ver.
 */
const crypto = require("crypto");

const ESTADOS = ["abierto", "en_remediacion", "remediado", "reabierto", "riesgo_aceptado", "falso_positivo"];
/** Los que cuentan como abiertos: los únicos que el cierre automático puede tocar. */
const ABIERTOS = ["abierto", "en_remediacion", "reabierto"];
/** Decisiones de una persona: la importación no las cambia. */
const DECISIONES = ["riesgo_aceptado", "falso_positivo"];
/** A los que se puede pasar a mano. `reabierto` lo pone solo una importación. */
const MANUALES = ["abierto", "en_remediacion", "remediado", "riesgo_aceptado", "falso_positivo"];
const CERRADOS = ["remediado", "riesgo_aceptado", "falso_positivo"];

const SEVERIDADES = ["critical", "high", "medium", "low", "info"];
const RANGO = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

/**
 * Fuentes del hallazgo. Las importables tienen parser hoy; el resto queda previsto para los
 * conectores programados y la API (etapa 3).
 */
const FUENTES = ["openvas", "nessus", "nmap", "zap", "burp", "wazuh", "manual"];
const NOMBRE_FUENTE = { openvas: "OpenVAS", nessus: "Nessus", nmap: "Nmap", zap: "ZAP", burp: "Burp", wazuh: "Wazuh", manual: "carga manual" };
const IMPORTABLES = ["openvas", "nessus", "nmap", "zap", "burp"];

/** Fuente con la que el inventario registra lo que encontró un escáner (ver vulnerabilidades.js). */
const FUENTE_INVENTARIO = "escaneo";

function normalizarTitulo(t) {
  return String(t || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase()
    .replace(/[^a-z0-9]+/g, " ").trim();
}

function normalizarCves(lista) {
  const arr = Array.isArray(lista) ? lista : String(lista || "").split(/[\s,;]+/);
  return [...new Set(arr.map((c) => String(c || "").trim().toUpperCase()).filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c)))].sort();
}

function puertoProtocolo(puerto, protocolo) {
  const p = String(puerto ?? "").trim();
  if (!p || p === "0") return "";
  return `${p}/${String(protocolo || "tcp").trim().toLowerCase()}`;
}

/** Lo que identifica al hallazgo dentro del activo y el puerto (ver la fórmula arriba). */
function identificador({ cves, regla, titulo }) {
  const c = normalizarCves(cves);
  if (c.length) return `cve:${c.join(",")}`;
  const r = String(regla || "").trim().toLowerCase();
  if (r) return `regla:${r}`;
  return `titulo:${normalizarTitulo(titulo)}`;
}

function claveDedup({ activo_id, puerto, protocolo, cves, regla, titulo }) {
  if (!activo_id) throw new Error("claveDedup: falta el activo");
  const base = `v1|${activo_id}|${puertoProtocolo(puerto, protocolo)}|${identificador({ cves, regla, titulo })}`;
  return crypto.createHash("sha256").update(base, "utf8").digest("hex");
}

function severidadValida(s) {
  const v = String(s || "").toLowerCase();
  return SEVERIDADES.includes(v) ? v : "medium";
}

const corto = (s, n) => (s == null || s === "" ? null : String(s).slice(0, n));

/** Un hallazgo de cualquier parser de `importacion-escaneres.js`, en el formato del seguimiento continuo. */
function desdeParser(f) {
  const cves = normalizarCves(f._cves);
  const pp = String(f._puerto || "").trim();
  return {
    titulo: corto(String(f.title || "").trim(), 500),
    severidad: severidadValida(f.severity),
    cvss: Number.isFinite(Number(f._cvss ?? f.cvss_score_31)) && (f._cvss ?? f.cvss_score_31) != null ? Math.min(10, Math.max(0, Number(f._cvss ?? f.cvss_score_31))) : null,
    cvss_vector: corto(f.cvss_vector_31, 200),
    cves,
    cwe: corto(String(f.cwe_id || "").trim(), 40),
    puerto: pp && pp !== "0" ? corto(pp, 10) : null,
    protocolo: pp && pp !== "0" ? corto(String(f._protocolo || "tcp").toLowerCase(), 10) : null,
    servicio: corto(f._servicio, 80),
    regla: corto(f._regla, 200),
    descripcion: corto(f.description, 60000),
    solucion: corto(f.recommendation, 60000),
    evidencia: corto(f.steps_to_reproduce, 20000),
    host: { ip: String(f._ip || "").trim(), hostname: String(f._hostname || "").trim() },
  };
}

/** Texto legible para el historial. La pantalla arma el suyo por idioma con `evento`. */
function motivoAutomatico(evento, { fuente, codigo }) {
  const de = `la importación ${codigo} de ${NOMBRE_FUENTE[fuente] || fuente}`;
  if (evento === "alta") return `Alta: apareció en ${de}`;
  if (evento === "cierre_auto") return `Cerrado: no apareció en ${de}`;
  if (evento === "reapertura") return `Reabierto: volvió a aparecer en ${de}`;
  if (evento === "visto") return `Visto otra vez en ${de}; se mantiene la decisión`;
  return "";
}

/**
 * Huella de lo que describe al hallazgo (lo que una importación actualiza). Si la que está guardada
 * es igual, el hallazgo solo se "toca" (última vez visto) en un UPDATE por lote: un conector que
 * corre cada hora sobre miles de vulnerabilidades no reescribe miles de textos que no cambiaron.
 */
function huella(d) {
  const orden = ["titulo", "severidad", "cvss", "cvss_vector", "cves", "cwe", "servicio", "regla", "descripcion", "solucion", "evidencia", "externo_id"];
  const base = orden.map((k) => (d[k] == null ? "" : String(d[k]))).join("\u0001");
  return crypto.createHash("sha1").update(base, "utf8").digest("hex");
}

/**
 * Aplica una importación sobre lo que ya había. Devuelve el delta.
 *
 * @param repo      ver `repoSQL`: porClaves, abiertosEnAlcance, insertar, actualizar, anotar, y si
 *                  los tiene, insertarLote, anotarLote y tocar (lotes: los usa si están).
 * @param opciones  { cliente, tenant, fuente, items (con activo_id), alcance (ids de activos que
 *                    cubrió el escaneo), importacion: { id, codigo }, usuario, nuevoId(),
 *                    cierreMinimo? (severidad: lo que está por debajo no se cierra por ausencia,
 *                    porque la fuente lo filtró y no lo trae) }
 */
async function aplicar(repo, { cliente, tenant = null, fuente, items, alcance, importacion, usuario = null, nuevoId, cierreMinimo = null }) {
  if (!IMPORTABLES.includes(fuente) && !FUENTES.includes(fuente)) throw new Error(`fuente desconocida: ${fuente}`);
  const ref = { fuente, codigo: importacion.codigo };

  // 1. Dentro del mismo archivo, lo repetido es uno solo (con la severidad más alta que se vio).
  const porClave = new Map();
  for (const it of items) {
    if (!it.activo_id || !it.titulo) continue;
    const clave = claveDedup(it);
    const ya = porClave.get(clave);
    if (!ya) porClave.set(clave, { ...it, clave });
    else if (RANGO[it.severidad] > RANGO[ya.severidad]) ya.severidad = it.severidad;
  }

  const delta = { nuevos: 0, cerrados: 0, reabiertos: 0, sin_cambios: 0, decisiones_mantenidas: 0 };
  // Nuevas y reabiertas por severidad: lo que mira un pipeline para decidir si corta.
  const aparecidas = Object.fromEntries(SEVERIDADES.map((x) => [x, 0]));
  const existentes = await repo.porClaves(cliente, [...porClave.keys()]);
  const descriptivos = (it) => {
    const d = {
      titulo: it.titulo, severidad: it.severidad, cvss: it.cvss, cvss_vector: it.cvss_vector,
      cves: it.cves.length ? it.cves.join(",") : null, cwe: it.cwe, servicio: it.servicio, regla: it.regla,
      descripcion: it.descripcion, solucion: it.solucion, evidencia: it.evidencia,
    };
    // El id con que la herramienta conoce al hallazgo (conectores). Sin él no se pisa el que había.
    if (it.externo_id) d.externo_id = String(it.externo_id).slice(0, 191);
    d.huella = huella(d);
    return d;
  };

  // Lo que se escribe va juntándose y sale por lotes al final (si el repositorio los tiene).
  const altas = [], notas = [], tocados = [];
  const anotar = (e) => notas.push(e);

  // 2. Lo que vino en el archivo: nuevo, reabierto o visto otra vez.
  for (const [clave, it] of porClave) {
    const ex = existentes.get(clave);
    if (!ex) {
      const id = nuevoId();
      altas.push({
        id, tenant_id: tenant, cliente_id: cliente, activo_id: it.activo_id, fuente, fuente_ultima: fuente,
        ...descriptivos(it), puerto: it.puerto, protocolo: it.protocolo, clave_dedup: clave,
        estado: "abierto", ultima_importacion_id: importacion.id, created_by: usuario,
      });
      anotar({ id: nuevoId(), cliente_id: cliente, hallazgo_id: id, estado_antes: null, estado_despues: "abierto",
        evento: "alta", motivo: motivoAutomatico("alta", ref), automatico: 1, importacion_id: importacion.id, fuente, usuario });
      delta.nuevos++;
      aparecidas[it.severidad] = (aparecidas[it.severidad] || 0) + 1;
    } else if (ex.estado === "remediado") {
      await repo.actualizar(ex.id, { ...descriptivos(it), estado: "reabierto", reaperturas: "+1", fecha_cierre: null,
        plazo_desde: "ahora", ultima_vez: "ahora", fuente_ultima: fuente, ultima_importacion_id: importacion.id });
      anotar({ id: nuevoId(), cliente_id: cliente, hallazgo_id: ex.id, estado_antes: "remediado", estado_despues: "reabierto",
        evento: "reapertura", motivo: motivoAutomatico("reapertura", ref), automatico: 1, importacion_id: importacion.id, fuente, usuario });
      delta.reabiertos++;
      aparecidas[it.severidad] = (aparecidas[it.severidad] || 0) + 1;
    } else if (DECISIONES.includes(ex.estado)) {
      // La decisión de una persona no la cambia un escáner: solo se anota que se volvió a ver.
      tocados.push(ex.id);
      delta.sin_cambios++;
      delta.decisiones_mantenidas++;
    } else {
      const d = descriptivos(it);
      if (ex.huella && ex.huella === d.huella) tocados.push(ex.id);
      else await repo.actualizar(ex.id, { ...d, ultima_vez: "ahora", fuente_ultima: fuente, ultima_importacion_id: importacion.id });
      delta.sin_cambios++;
    }
  }
  if (altas.length) {
    if (repo.insertarLote) await repo.insertarLote(altas);
    else for (const h of altas) await repo.insertar(h);
  }
  if (tocados.length) {
    const visto = { ultima_vez: "ahora", fuente_ultima: fuente, ultima_importacion_id: importacion.id };
    if (repo.tocar) await repo.tocar(tocados, visto);
    else for (const id of tocados) await repo.actualizar(id, visto);
  }

  // 3. Lo que no vino: se cierra solo si es de la misma fuente y su activo estaba en el alcance.
  // Con `cierreMinimo`, lo que está por debajo de esa severidad tampoco: la fuente no lo trajo
  // porque se filtró, no porque se haya arreglado.
  const candidatos = await repo.abiertosEnAlcance(cliente, fuente, [...new Set(alcance)]);
  const piso = cierreMinimo && RANGO[cierreMinimo] ? RANGO[cierreMinimo] : 0;
  for (const c of candidatos) {
    if (porClave.has(c.clave_dedup)) continue;
    if (piso && c.severidad && (RANGO[c.severidad] || 0) < piso) continue;
    await repo.actualizar(c.id, { estado: "remediado", fecha_cierre: "ahora" });
    anotar({ id: nuevoId(), cliente_id: cliente, hallazgo_id: c.id, estado_antes: c.estado, estado_despues: "remediado",
      evento: "cierre_auto", motivo: motivoAutomatico("cierre_auto", ref), automatico: 1, importacion_id: importacion.id, fuente, usuario });
    delta.cerrados++;
  }
  if (notas.length) {
    if (repo.anotarLote) await repo.anotarLote(notas);
    else for (const e of notas) await repo.anotar(e);
  }
  delta.total = porClave.size;
  delta.nuevas_por_severidad = aparecidas;
  return delta;
}

/**
 * Cambio de estado a mano. Devuelve los cambios a aplicar o `{ error }`.
 * Reabrir algo remediado cuenta como reapertura; cerrar (por cualquier motivo) fecha el cierre.
 */
function transicionManual(actual, nuevo) {
  if (!MANUALES.includes(nuevo)) return { error: "Estado inválido." };
  if (actual === nuevo) return { error: "La vulnerabilidad ya está en ese estado." };
  const cambios = { estado: nuevo };
  if (CERRADOS.includes(nuevo)) cambios.fecha_cierre = "ahora";
  else {
    cambios.fecha_cierre = null;
    // Reabrir algo remediado es una reapertura: suma una y el plazo corre de nuevo desde hoy.
    if (actual === "remediado") { cambios.reaperturas = "+1"; cambios.plazo_desde = "ahora"; }
  }
  return { cambios };
}

// ── Acceso a la base ────────────────────────────────────────────────────────────────────────────
const TROZO = 500;
function trozos(arr, n = TROZO) { const o = []; for (let i = 0; i < arr.length; i += n) o.push(arr.slice(i, i + n)); return o; }

const COLUMNAS_INSERT = ["id", "tenant_id", "cliente_id", "activo_id", "fuente", "fuente_ultima", "titulo", "severidad", "cvss",
  "cvss_vector", "cves", "cwe", "puerto", "protocolo", "servicio", "regla", "descripcion", "solucion", "evidencia",
  "clave_dedup", "estado", "ultima_importacion_id", "created_by", "externo_id", "huella"];
const ACTUALIZABLES = new Set(["titulo", "severidad", "cvss", "cvss_vector", "cves", "cwe", "servicio", "regla", "descripcion",
  "solucion", "evidencia", "estado", "fecha_cierre", "ultima_vez", "fuente_ultima", "ultima_importacion_id", "reaperturas",
  "responsable", "notas", "activo_id", "clave_dedup", "primera_vez", "plazo_desde", "externo_id", "huella"]);
const COLUMNAS_HISTORIAL = ["id", "cliente_id", "hallazgo_id", "estado_antes", "estado_despues", "evento", "motivo", "automatico",
  "importacion_id", "fuente", "usuario"];
/** Filas por INSERT de lote, y tope aproximado de bytes (los textos de un escáner pueden ser largos). */
const LOTE_FILAS = 100;
const LOTE_BYTES = 4 * 1024 * 1024;

function filaHistorial(e) {
  return [e.id, e.cliente_id, e.hallazgo_id, e.estado_antes ?? null, e.estado_despues ?? null, e.evento,
    e.motivo ? String(e.motivo).slice(0, 1000) : null, e.automatico ? 1 : 0, e.importacion_id ?? null, e.fuente ?? null, e.usuario ?? null];
}

/** Parte una lista de filas en lotes por cantidad y por tamaño aproximado. */
function lotesPorTamano(filas, medir, maxFilas = LOTE_FILAS, maxBytes = LOTE_BYTES) {
  const o = [];
  let actual = [], bytes = 0;
  for (const f of filas) {
    const b = medir(f);
    if (actual.length && (actual.length >= maxFilas || bytes + b > maxBytes)) { o.push(actual); actual = []; bytes = 0; }
    actual.push(f); bytes += b;
  }
  if (actual.length) o.push(actual);
  return o;
}
const largo = (h) => ["descripcion", "solucion", "evidencia", "titulo"].reduce((n, k) => n + (h[k] ? Buffer.byteLength(String(h[k])) : 0), 512);

/** El repositorio del motor sobre `{ qRow, qRows, qRun }` (dentro de una transacción). */
function repoSQL({ qRows, qRun }) {
  return {
    async porClaves(cliente, claves) {
      const m = new Map();
      for (const t of trozos(claves)) {
        const filas = await qRows(
          `SELECT id, clave_dedup, estado, huella FROM vuln_hallazgos WHERE cliente_id = ? AND clave_dedup IN (${t.map(() => "?").join(",")})`,
          [cliente, ...t]);
        for (const f of filas) m.set(f.clave_dedup, f);
      }
      return m;
    },
    async abiertosEnAlcance(cliente, fuente, activos) {
      const o = [];
      for (const t of trozos(activos)) {
        o.push(...await qRows(
          `SELECT id, clave_dedup, estado, activo_id, severidad FROM vuln_hallazgos
            WHERE cliente_id = ? AND fuente = ? AND estado IN (${ABIERTOS.map(() => "?").join(",")})
              AND activo_id IN (${t.map(() => "?").join(",")})`,
          [cliente, fuente, ...ABIERTOS, ...t]));
      }
      return o;
    },
    async insertar(h) {
      await qRun(
        `INSERT INTO vuln_hallazgos (${COLUMNAS_INSERT.join(", ")}, primera_vez, ultima_vez)
         VALUES (${COLUMNAS_INSERT.map(() => "?").join(",")}, NOW(), NOW())`,
        COLUMNAS_INSERT.map((k) => h[k] ?? null));
    },
    /** Varias altas en un INSERT por lote (dentro de la misma transacción que el resto). */
    async insertarLote(lista) {
      for (const lote of lotesPorTamano(lista, largo)) {
        const fila = `(${COLUMNAS_INSERT.map(() => "?").join(",")}, NOW(), NOW())`;
        await qRun(
          `INSERT INTO vuln_hallazgos (${COLUMNAS_INSERT.join(", ")}, primera_vez, ultima_vez) VALUES ${lote.map(() => fila).join(", ")}`,
          lote.flatMap((h) => COLUMNAS_INSERT.map((k) => h[k] ?? null)));
      }
    },
    /** "Visto otra vez" sin cambios en lo que describe al hallazgo: un UPDATE por cada 500. */
    async tocar(ids, { fuente_ultima, ultima_importacion_id }) {
      for (const t of trozos(ids)) {
        await qRun(`UPDATE vuln_hallazgos SET ultima_vez = NOW(), fuente_ultima = ?, ultima_importacion_id = ? WHERE id IN (${t.map(() => "?").join(",")})`,
          [fuente_ultima, ultima_importacion_id, ...t]);
      }
    },
    async anotarLote(lista) {
      for (const lote of trozos(lista, 300)) {
        const fila = `(${COLUMNAS_HISTORIAL.map(() => "?").join(",")})`;
        await qRun(`INSERT INTO vuln_historial (${COLUMNAS_HISTORIAL.join(", ")}) VALUES ${lote.map(() => fila).join(", ")}`,
          lote.flatMap(filaHistorial));
      }
    },
    async actualizar(id, cambios) {
      const sets = [], params = [];
      for (const [k, v] of Object.entries(cambios)) {
        if (!ACTUALIZABLES.has(k)) throw new Error(`columna no actualizable: ${k}`);
        if (v === "ahora") sets.push(`${k} = NOW()`);
        else if (v === "+1") sets.push(`${k} = ${k} + 1`);
        else { sets.push(`${k} = ?`); params.push(v); }
      }
      if (sets.length) await qRun(`UPDATE vuln_hallazgos SET ${sets.join(", ")} WHERE id = ?`, [...params, id]);
    },
    async anotar(e) {
      await qRun(
        `INSERT INTO vuln_historial (${COLUMNAS_HISTORIAL.join(", ")}) VALUES (${COLUMNAS_HISTORIAL.map(() => "?").join(",")})`,
        filaHistorial(e));
    },
  };
}

/**
 * Al fusionar dos activos del inventario, sus vulnerabilidades pasan al que queda. Como el activo
 * es parte de la clave, se recalcula; si el que queda ya tenía la misma vulnerabilidad, se conserva
 * esa (con la primera y la última vez más amplias) y el historial de la absorbida pasa a ella.
 */
async function moverDeActivo({ qRow, qRows, qRun }, principalId, absorbidoId) {
  const filas = await qRows("SELECT * FROM vuln_hallazgos WHERE activo_id = ?", [absorbidoId]);
  let movidas = 0, unidas = 0;
  for (const h of filas) {
    const clave = claveDedup({ activo_id: principalId, puerto: h.puerto, protocolo: h.protocolo, cves: h.cves, regla: h.regla, titulo: h.titulo });
    const ya = await qRow("SELECT id FROM vuln_hallazgos WHERE cliente_id = ? AND clave_dedup = ? AND id <> ?", [h.cliente_id, clave, h.id]);
    if (ya) {
      await qRun(`UPDATE vuln_hallazgos SET primera_vez = LEAST(primera_vez, ?), ultima_vez = GREATEST(ultima_vez, ?) WHERE id = ?`,
        [h.primera_vez, h.ultima_vez, ya.id]);
      await qRun("UPDATE vuln_historial SET hallazgo_id = ? WHERE hallazgo_id = ?", [ya.id, h.id]);
      await qRun("DELETE FROM vuln_hallazgos WHERE id = ?", [h.id]);
      unidas++;
    } else {
      await qRun("UPDATE vuln_hallazgos SET activo_id = ?, clave_dedup = ? WHERE id = ?", [principalId, clave, h.id]);
      movidas++;
    }
  }
  return { vulnerabilidades: movidas, vulnerabilidades_unidas: unidas };
}

module.exports = {
  ESTADOS, ABIERTOS, DECISIONES, MANUALES, CERRADOS, SEVERIDADES, RANGO, FUENTES, IMPORTABLES, FUENTE_INVENTARIO,
  normalizarTitulo, normalizarCves, puertoProtocolo, identificador, claveDedup, desdeParser, motivoAutomatico,
  aplicar, transicionManual, repoSQL, moverDeActivo, trozos, huella, lotesPorTamano,
};
