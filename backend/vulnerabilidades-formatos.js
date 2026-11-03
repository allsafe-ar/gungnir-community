"use strict";
/**
 * Vulnerabilidades, etapa 4: importadores de SARIF 2.1.0, Trivy JSON y Nuclei JSONL.
 *
 * Abren la capa AppSec: SARIF cubre con un solo formato a Semgrep, CodeQL, Trivy en modo SARIF y la
 * mayoría de los SAST; Trivy JSON trae las vulnerabilidades de una imagen o de un repositorio, y
 * Nuclei las de un sitio. Devuelven hallazgos con la misma forma que los parsers de
 * `importacion-escaneres.js` (los campos con guion bajo), así que el motor no sabe de dónde vienen.
 * Sin Express ni base: se prueba solo. Idéntico en Gungnir Pro y Community.
 *
 * 🔑 **El activo.** Un hallazgo de código o de una imagen no tiene IP. El activo es el repositorio o la
 * imagen y entra al inventario único como software, con un identificador estable que no depende de la
 * corrida (`_activo.clave`, que es el identificador externo del inventario):
 *
 *   repo:<servidor>/<org>/<nombre>   SARIF (versionControlProvenance) y Trivy de repositorio.
 *                                    Sin esquema, sin credenciales, sin ".git", en minúsculas.
 *   imagen:<registro>/<nombre>       Trivy de imagen. SIN la etiqueta ni el digest: la imagen
 *                                    `app:1.4` y la `app:1.5` son el mismo activo a lo largo del
 *                                    tiempo, y actualizar la etiqueta es lo que cierra lo corregido.
 *
 * Si el archivo no lo dice (un SARIF sin versionControlProvenance, un Trivy de un directorio "."), quien
 * importa lo completa con el campo `activo` ("github.com/org/app", o con el prefijo repo: o imagen:).
 * Lo que se escribe a mano también gana sobre lo que dice el archivo. Nuclei usa el host de la URL,
 * como ZAP: un sitio es un servicio expuesto.
 *
 * 🔑 **La deduplicación** es la fórmula v1 del motor, con la ubicación en el lugar del puerto:
 *   SARIF   regla sarif:<ruleId>          ubicación "archivo:línea"
 *   Trivy   regla trivy:<VulnerabilityID> ubicación el paquete (con el archivo de dependencias
 *                                         adelante si es de un lenguaje: "package-lock.json:lodash")
 *   Nuclei  regla nuclei:<template-id>    ubicación el matched-at
 * Como en todo el motor, si el hallazgo trae CVE el identificador es el CVE (la regla queda guardada).
 * La versión instalada NO entra: si una actualización no corrige el CVE, sigue siendo la misma
 * vulnerabilidad. En SARIF la línea sí entra (es la ubicación que pide la fórmula): si el código se
 * corre de línea, se cierra la vieja y aparece una nueva.
 *
 * 🔑 **El alcance del cierre** es lo que el archivo dice que analizó:
 *   SARIF   el repositorio de cada run, y dentro de él solo lo de la MISMA herramienta (driver) y, si
 *           el run declara su juego de reglas, solo esas reglas. Un CodeQL no cierra lo de Semgrep y
 *           un Semgrep corrido con otra configuración no cierra lo de reglas que no corrió. Los archivos
 *           NO acotan: las herramientas suelen listar solo los que tienen resultados, y acotar por
 *           ahí haría que lo corregido nunca se cierre (ver `reglasDeclaradas`).
 *   Trivy   el artefacto (la imagen o el repositorio), aunque no traiga vulnerabilidades: una imagen
 *           limpia cierra lo que tenía abierto. ⚠️ Si se corrió con --severity, usar `cierre_minimo`
 *           en la API, porque el archivo no dice qué severidades se filtraron.
 *   Nuclei  los hosts que tienen algún resultado, más los que se declaren en el campo de alcance:
 *           el JSONL solo trae coincidencias, así que un sitio limpio no aparece.
 */

const SEVERIDADES = ["critical", "high", "medium", "low", "info"];
const FORMATOS = ["sarif", "trivy", "nuclei"];
const ES_IP = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*$/i;

/** Error de lectura con un mensaje para quien importa (sale como 400). */
function errorLectura(msg) { return Object.assign(new Error(msg), { lectura: true }); }

function json(texto) {
  const t = String(texto ?? "").replace(/^﻿/, "").trim();
  if (!t) throw errorLectura("el archivo está vacío.");
  try { return JSON.parse(t); } catch { throw errorLectura("no es un JSON válido."); }
}

const txt = (v) => (v == null ? "" : String(v)).trim();
const corto = (v, n) => { const s = txt(v); return s.length > n ? s.slice(0, n) : s; };
const unir = (...partes) => partes.map(txt).filter(Boolean).join("\n\n");

function cvesDe(...valores) {
  const s = new Set();
  for (const v of valores.flat(Infinity)) for (const m of String(v ?? "").match(/CVE-\d{4}-\d{4,}/gi) || []) s.add(m.toUpperCase());
  return [...s];
}
function cweDe(...valores) {
  for (const v of valores.flat(Infinity)) {
    const m = /CWE[-_ ]?(\d{1,5})/i.exec(String(v ?? ""));
    if (m) return `CWE-${Number(m[1])}`;
  }
  return "";
}
/** Severidad desde un puntaje tipo CVSS (security-severity de CodeQL y Trivy SARIF). */
function sevPorPuntaje(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return null;
  if (x >= 9) return "critical"; if (x >= 7) return "high"; if (x >= 4) return "medium"; if (x > 0) return "low";
  return "info";
}
function sevTexto(s) {
  const v = txt(s).toLowerCase();
  if (SEVERIDADES.includes(v)) return v;
  return { moderate: "medium", informational: "info", information: "info", unknown: "info", negligible: "info" }[v] || null;
}

// ── Identidad del activo ──────────────────────────────────────────────────────────────────────

/**
 * "https://x-access-token:abc@github.com/Org/App.git" -> "github.com/org/app". Saca el esquema, las
 * credenciales (un pipeline las pone en la URL del clon), ".git" y las barras del final.
 */
function normalizarRepo(uri) {
  let s = txt(uri);
  if (!s) return "";
  const scp = /^[\w.-]+@([^:/\s]+):(.+)$/.exec(s);          // git@github.com:org/app.git
  if (scp) s = `${scp[1]}/${scp[2]}`;
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^[^@/]*@/, "");
  s = s.split(/[?#]/)[0].replace(/\/+$/, "").replace(/\.git$/i, "").replace(/\/+$/, "");
  return s.toLowerCase().slice(0, 300);
}

/** "ghcr.io/org/app:1.4@sha256:..." -> "ghcr.io/org/app". La etiqueta y el digest no son el activo. */
function normalizarImagen(nombre) {
  let s = txt(nombre).split("@")[0];
  const barra = s.lastIndexOf("/");
  const dosPuntos = s.lastIndexOf(":");
  if (dosPuntos > barra) s = s.slice(0, dosPuntos);
  return s.toLowerCase().slice(0, 300);
}

function refRepo(nombre) {
  const n = normalizarRepo(nombre);
  return n ? { clave: `repo:${n}`, nombre: n, tipo: "desarrollo_propio" } : null;
}
function refImagen(nombre) {
  const n = normalizarImagen(nombre);
  return n ? { clave: `imagen:${n}`, nombre: n, tipo: "aplicacion" } : null;
}

/** El activo que escribió quien importa: "repo:..." o "imagen:..." explícitos, o el tipo por defecto. */
function refManual(valor, porDefecto) {
  const v = txt(valor);
  if (!v) return null;
  const m = /^(repo|imagen|image):(.+)$/i.exec(v);
  if (m) return m[1].toLowerCase() === "repo" ? refRepo(m[2]) : refImagen(m[2]);
  return porDefecto === "imagen" ? refImagen(v) : refRepo(v);
}

/** Un directorio local ("." o "./src") no identifica nada fuera de la máquina donde corrió. */
const esRutaLocal = (s) => { const v = txt(s); return !v || v === "." || v.startsWith("./") || v.startsWith("../"); };

function partesDeUrl(u) {
  try {
    const x = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(u) ? u : `tcp://${u}`);
    const host = x.hostname.replace(/^\[|\]$/g, "");
    const puerto = x.port || (x.protocol === "https:" ? "443" : x.protocol === "http:" ? "80" : "");
    return { ...(ES_IP.test(host) ? { ip: host, hostname: "" } : { ip: "", hostname: host.toLowerCase() }), puerto, protocolo: puerto ? "tcp" : "" };
  } catch { return { ip: "", hostname: "", puerto: "", protocolo: "" }; }
}

// ── SARIF 2.1.0 ───────────────────────────────────────────────────────────────────────────────

function rutaArtefacto(loc) {
  const a = loc?.physicalLocation?.artifactLocation;
  let uri = txt(a?.uri);
  if (!uri) return "";
  try { uri = decodeURIComponent(uri); } catch { /* se deja como vino */ }
  return uri.replace(/^file:\/\//i, "").replace(/^\.\//, "");
}

/**
 * El título de la regla. Semgrep pone "Semgrep Finding: <id>" como descripción corta: ahí se usa la
 * primera oración de la descripción larga, que dice qué es. El título sale de la regla, no del
 * mensaje del resultado, para que sea el mismo en cada corrida.
 */
function tituloRegla(regla, ruleId) {
  const corta = txt(regla.shortDescription?.text);
  if (corta && !/^semgrep finding:/i.test(corta)) return corta;
  const larga = txt(regla.fullDescription?.text);
  if (larga) { const o = larga.split(/(?<=\.)\s/)[0]; return o.length > 160 ? `${o.slice(0, 157)}...` : o; }
  return txt(regla.name) || ruleId;
}

/**
 * Las reglas que corrieron, si el run las declara. 🔑 Un run que lista reglas SIN resultados está
 * declarando su juego completo (Semgrep y CodeQL lo hacen): eso acota el cierre. Si todas las reglas
 * listadas tienen resultados, la lista es solo la de lo encontrado (Trivy en SARIF lo hace así) y
 * acotar por ella impediría cerrar lo corregido: entonces no se acota (null).
 */
function reglasDeclaradas(run, conResultados) {
  const ids = new Set();
  for (const r of run?.tool?.driver?.rules || []) if (r?.id) ids.add(String(r.id));
  for (const ext of run?.tool?.extensions || []) for (const r of ext?.rules || []) if (r?.id) ids.add(String(r.id));
  if (!ids.size) return null;
  const sinResultados = [...ids].some((id) => !conResultados.has(id));
  if (!sinResultados) return null;
  for (const id of conResultados) ids.add(id);
  return [...ids].map((id) => `sarif:${id}`.slice(0, 200));
}

function leerSarif(texto, { activo } = {}) {
  const doc = json(texto);
  if (!Array.isArray(doc?.runs)) throw errorLectura("no es un SARIF: falta el arreglo runs.");
  if (doc.version && String(doc.version) !== "2.1.0") throw errorLectura(`la versión de SARIF es ${doc.version}; se lee la 2.1.0.`);
  const crudos = [], hosts = [], cierre = [];
  for (const run of doc.runs) {
    const driver = run?.tool?.driver || {};
    const herramienta = corto(driver.name || "SARIF", 80);
    const reglas = new Map();
    const porIndice = [];
    for (const r of [...(driver.rules || []), ...(run?.tool?.extensions || []).flatMap((e) => e?.rules || [])]) {
      if (r?.id) reglas.set(String(r.id), r);
    }
    (driver.rules || []).forEach((r, i) => { porIndice[i] = r; });
    const ref = refManual(activo, "repo")
      || refRepo((run.versionControlProvenance || []).map((v) => v?.repositoryUri).find(Boolean));
    if (!ref) throw errorLectura(`el SARIF de ${herramienta} no dice qué repositorio analizó (falta versionControlProvenance): completá el activo (por ejemplo github.com/org/app).`);
    hosts.push({ ip: "", hostname: "", ref });

    const conResultados = new Set();
    for (const res of run.results || []) {
      if (res?.suppressions?.length) continue;                       // suprimido en el código: no es un hallazgo
      if (res?.baselineState === "absent") continue;                 // el SARIF dice que ya no está
      const regla = (res?.ruleIndex != null && porIndice[res.ruleIndex]) || reglas.get(String(res?.ruleId || res?.rule?.id || "")) || {};
      const ruleId = txt(res?.ruleId || res?.rule?.id || regla.id);
      if (!ruleId) continue;
      conResultados.add(ruleId);
      const props = { ...(regla.properties || {}), ...(res.properties || {}) };
      const nivel = txt(res.level || regla.defaultConfiguration?.level || "warning").toLowerCase();
      const severidad = sevPorPuntaje(props["security-severity"])
        || sevTexto(props.severity) || { error: "high", warning: "medium", note: "low", none: "info" }[nivel] || "medium";
      const loc = (res.locations || [])[0];
      const ruta = rutaArtefacto(loc);
      const linea = loc?.physicalLocation?.region?.startLine;
      const ubicacion = ruta ? `${ruta}${linea ? `:${linea}` : ""}` : "";
      const mensaje = txt(res.message?.text || res.message?.markdown);
      const titulo = tituloRegla(regla, ruleId);
      const cves = cvesDe(ruleId);
      const fragmento = txt(loc?.physicalLocation?.region?.snippet?.text);
      crudos.push({
        title: corto(titulo, 500),
        severity: severidad,
        description: unir(regla.fullDescription?.text, mensaje && mensaje !== titulo ? mensaje : ""),
        recommendation: unir(regla.help?.text || regla.help?.markdown),
        steps_to_reproduce: unir(ubicacion ? `${ubicacion}` : "", fragmento ? fragmento.slice(0, 4000) : ""),
        cvss_score_31: sevPorPuntaje(props["security-severity"]) ? Number(props["security-severity"]) : null,
        cvss_vector_31: null,
        cwe_id: cweDe(props.tags, props.cwe, regla.relationships?.map((x) => x?.target?.id)),
        _cves: cves,
        _regla: `sarif:${ruleId}`,
        _servicio: herramienta,
        _ubicacion: ubicacion,
        _activo: ref,
      });
    }
    cierre.push({ activo: ref.clave, herramienta, reglas: reglasDeclaradas(run, conResultados) });
  }
  return { crudos, hosts, cierre };
}

// ── Trivy JSON ────────────────────────────────────────────────────────────────────────────────

function cvssTrivy(v) {
  const fuentes = v?.CVSS && typeof v.CVSS === "object" ? v.CVSS : {};
  const orden = ["nvd", v?.SeveritySource, ...Object.keys(fuentes)].filter(Boolean);
  for (const k of orden) {
    const c = fuentes[k];
    if (c && Number.isFinite(Number(c.V3Score))) return { puntaje: Number(c.V3Score), vector: txt(c.V3Vector) || null };
  }
  return { puntaje: null, vector: null };
}

function refTrivy(doc, activo) {
  const tipo = txt(doc.ArtifactType).toLowerCase();
  const esImagen = tipo === "container_image";
  const manual = refManual(activo, esImagen ? "imagen" : "repo");
  if (manual) return manual;
  if (esImagen) return refImagen(doc.ArtifactName || doc.Metadata?.RepoTags?.[0]);
  if (tipo === "repository") return refRepo(doc.ArtifactName);
  if (!esRutaLocal(doc.ArtifactName)) return refRepo(doc.ArtifactName);
  return null;
}

function leerTrivy(texto, { activo } = {}) {
  const doc = json(texto);
  if (!doc || typeof doc !== "object" || Array.isArray(doc) || !("Results" in doc || "ArtifactName" in doc))
    throw errorLectura("no es un informe JSON de Trivy (trivy ... --format json): faltan ArtifactName y Results.");
  const ref = refTrivy(doc, activo);
  if (!ref) throw errorLectura(`Trivy analizó "${txt(doc.ArtifactName) || "un directorio"}", que no identifica al activo: completá el activo (repositorio o imagen).`);
  const crudos = [];
  for (const r of doc.Results || []) {
    const deLenguaje = txt(r.Class) !== "os-pkgs";
    for (const v of r.Vulnerabilities || []) {
      const id = txt(v.VulnerabilityID);
      const pkg = txt(v.PkgName || v.PkgID);
      if (!id || !pkg) continue;
      const { puntaje, vector } = cvssTrivy(v);
      const fija = txt(v.FixedVersion);
      crudos.push({
        title: corto(`${pkg}: ${txt(v.Title) || id}`, 500),
        severity: sevTexto(v.Severity) || "medium",
        description: unir(v.Description, `${id} en ${pkg} ${txt(v.InstalledVersion)}`.trim(), v.PrimaryURL),
        recommendation: fija ? `Actualizar ${pkg} a ${fija} o posterior.` : `Sin versión corregida publicada (estado: ${txt(v.Status) || "sin dato"}).`,
        steps_to_reproduce: unir(`Objetivo: ${txt(r.Target)}`, `Paquete: ${pkg} ${txt(v.InstalledVersion)}`.trim(),
          fija ? `Corregido en: ${fija}` : ""),
        cvss_score_31: puntaje,
        cvss_vector_31: vector,
        cwe_id: cweDe(v.CweIDs),
        _cves: cvesDe(id),
        _regla: `trivy:${id}`,
        _servicio: corto(pkg, 80),
        // El paquete; si es de un lenguaje, con el archivo de dependencias adelante (dos lockfiles con
        // el mismo paquete son dos lugares). En los del sistema, el objetivo lleva la etiqueta de la
        // imagen y cambiaría con cada versión: va solo el paquete.
        _ubicacion: deLenguaje && txt(r.Target) ? `${txt(r.Target)}:${pkg}` : pkg,
        _activo: ref,
      });
    }
  }
  return { crudos, hosts: [{ ip: "", hostname: "", ref }], cierre: null };
}

// ── Nuclei JSONL ──────────────────────────────────────────────────────────────────────────────

function lineasNuclei(texto) {
  const t = String(texto ?? "").replace(/^﻿/, "").trim();
  if (!t) throw errorLectura("el archivo está vacío.");
  if (t.startsWith("[")) {                                         // -json-export: un arreglo
    const a = json(t);
    if (!Array.isArray(a)) throw errorLectura("no es un resultado de Nuclei.");
    return a;
  }
  const o = [];
  for (const [i, l] of t.split(/\r?\n/).entries()) {
    if (!l.trim()) continue;
    try { o.push(JSON.parse(l)); } catch { throw errorLectura(`la línea ${i + 1} no es JSON (se espera la salida de nuclei -jsonl).`); }
  }
  return o;
}

function leerNuclei(texto, _opciones = {}) {
  const filas = lineasNuclei(texto);
  if (filas.length && !filas.some((f) => f && (f["template-id"] || f.templateID))) throw errorLectura("no es un resultado de Nuclei: falta template-id.");
  const crudos = [], hosts = [];
  for (const f of filas) {
    if (!f || f["matcher-status"] === false) continue;
    const tpl = txt(f["template-id"] || f.templateID);
    const donde = txt(f["matched-at"] || f.matched || f.url || f.host);
    if (!tpl || !donde) continue;
    const u = partesDeUrl(txt(f.host) || donde);
    if (!u.ip && !u.hostname) continue;
    const info = f.info || {};
    const cls = info.classification || {};
    const extraidos = Array.isArray(f["extracted-results"]) ? f["extracted-results"].join(", ") : txt(f["extracted-results"]);
    const puntaje = Number(cls["cvss-score"]);
    const refs = Array.isArray(info.reference) ? info.reference.join("\n") : txt(info.reference);
    crudos.push({
      title: corto(txt(info.name) || tpl, 500),
      severity: sevTexto(info.severity) || "info",
      description: unir(info.description, refs),
      recommendation: unir(info.remediation),
      steps_to_reproduce: unir(`Coincidencia en: ${donde}`, f["matcher-name"] ? `Matcher: ${txt(f["matcher-name"])}` : "",
        extraidos ? `Extraído: ${extraidos.slice(0, 500)}` : ""),
      cvss_score_31: Number.isFinite(puntaje) ? puntaje : null,
      cvss_vector_31: txt(cls["cvss-metrics"]) || null,
      cwe_id: cweDe(cls["cwe-id"]),
      _cves: cvesDe(cls["cve-id"]),
      _regla: `nuclei:${tpl}`,
      _ip: u.ip, _hostname: u.hostname, _puerto: txt(f.port) || u.puerto, _protocolo: u.puerto || f.port ? "tcp" : "",
      _servicio: corto(f.type, 80),
      _ubicacion: donde,
    });
    hosts.push({ ip: u.ip, hostname: u.hostname });
  }
  return { crudos, hosts, cierre: null };
}

const LECTORES = { sarif: leerSarif, trivy: leerTrivy, nuclei: leerNuclei };

/**
 * Lee un archivo de uno de los formatos. Devuelve { crudos, hosts, cierre } o tira un error con
 * `lectura: true` y un mensaje para quien importa.
 *   crudos  hallazgos con la forma de los parsers (para M.desdeParser).
 *   hosts   el alcance: equipos, sitios o activos de código (`ref`) que el archivo cubrió.
 *   cierre  null, o una lista { activo (clave de ref), herramienta, reglas } que acota el cierre (SARIF).
 */
function leer(fuente, texto, opciones = {}) {
  const f = LECTORES[fuente];
  if (!f) throw errorLectura("formato desconocido.");
  return f(texto, opciones);
}

module.exports = { FORMATOS, leer, leerSarif, leerTrivy, leerNuclei, normalizarRepo, normalizarImagen, refManual, reglasDeclaradas };
