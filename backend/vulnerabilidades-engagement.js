"use strict";
/**
 * Vulnerabilidades, etapa 4: pase a engagement. Idéntico en Gungnir Pro y Community.
 *
 * Una vulnerabilidad del seguimiento continuo se lleva a un engagement del MISMO cliente cuando hay
 * que tratarla como trabajo de pentest: verificarla a mano, explotarla, ponerla en un informe o hacer
 * el retest de la remediación. Se crea un hallazgo (`findings`) con lo que ya se sabe (título,
 * descripción, CVE, CVSS, severidad, activo afectado, solución y evidencia) y quedan enlazados por
 * `vuln_hallazgos.engagement_id` y `finding_id`. Queda historial en los dos lados: un evento
 * `a_engagement` en la vulnerabilidad y un `finding_create` en la actividad del engagement.
 *
 * 🔑 **No se duplica.** Si la vulnerabilidad ya tiene un hallazgo que existe, no se crea otro (en lote
 * se informa como "ya llevada"). Si el hallazgo o el engagement se borraron, el enlace está muerto y se
 * puede volver a llevar. La fila de la vulnerabilidad se bloquea (FOR UPDATE) mientras tanto: dos
 * pedidos a la vez no crean dos hallazgos.
 *
 * 🔑 **El retest NO cierra la vulnerabilidad continua (decisión del 03/11/2026).** La regla del motor
 * es que solo la fuente que la creó la cierra sola, cuando un escaneo que cubrió el activo ya no la
 * ve. Un retest aprobado prueba un caso puntual; si el escáner la sigue viendo, cerrarla haría que la
 * próxima importación la reabra (cierre y reapertura en loop, y el contador de reaperturas mentiría).
 * Lo que hace el retest:
 *   1. queda en el historial de la vulnerabilidad (evento `retest`, sin cambio de estado), y
 *   2. la ficha muestra el estado del hallazgo y del retest, con un atajo para cerrarla a mano con el
 *      motivo ya escrito (el cambio de estado con motivo de siempre: queda quién y por qué).
 *
 * Cómo se monta (lo llama `vulnerabilidades.montar`):
 *   VE.montar(app, { mw, clienteO403, qRow, qRows, qRun, transaccion, auditLog, notificarActividad?,
 *                    engagementVisible?, tenantEnFinding?, fallo });
 * y en la ruta de retest del engagement: `VE.registrarRetest({ qRows, qRun }, findingId, resultado, usuario)`.
 */
const { v4: uuidv4 } = require("uuid");
const M = require("./vulnerabilidades-motor");
const P = require("./vulnerabilidades-prioridad");

const MAX_LOTE = 200;
const NVD = "https://nvd.nist.gov/vuln/detail/";

/** Lo que un engagement archivado no recibe: ya se cerró. */
const ESTADOS_CERRADOS = ["archived"];

function cweCorto(c) {
  const s = String(c || "").trim();
  if (!s) return null;
  if (/^\d+$/.test(s)) return `CWE-${s}`;
  return s.slice(0, 20);
}

/** El activo como lo lee un informe: "srv-web (10.0.0.5) 443/tcp" o "github.com/org/app src/db.js:42". */
function activoAfectado(v, a) {
  const nombre = a?.nombre || a?.ip || a?.hostname || "";
  const ip = a?.ip && a.ip !== nombre ? ` (${a.ip})` : "";
  const lugar = v.ubicacion ? ` ${v.ubicacion}` : v.puerto ? ` ${v.puerto}/${v.protocolo || "tcp"}` : "";
  return `${nombre}${ip}${lugar}`.trim().slice(0, 500) || null;
}

/** Las columnas del hallazgo del informe, armadas con lo que sabe el seguimiento continuo. */
function hallazgoDesde(v, a) {
  const cves = M.normalizarCves(v.cves);
  const vector = v.cvss_vector ? String(v.cvss_vector) : null;
  const es40 = !!vector && /^CVSS:4/i.test(vector);
  const puntaje = v.cvss == null || v.cvss === "" ? null : Number(v.cvss);
  return {
    title: String(v.titulo || "").slice(0, 500),
    description: [v.descripcion, cves.length ? `CVE: ${cves.join(", ")}` : ""].filter((x) => x && String(x).trim()).join("\n\n") || null,
    steps_to_reproduce: v.evidencia || null,
    affected_asset: activoAfectado(v, a),
    cvss_vector_31: !es40 && vector && /^CVSS:3/i.test(vector) ? vector.slice(0, 100) : null,
    cvss_score_31: !es40 && Number.isFinite(puntaje) ? puntaje : null,
    cvss_vector_40: es40 ? vector.slice(0, 200) : null,
    cvss_score_40: es40 && Number.isFinite(puntaje) ? puntaje : null,
    severity: M.SEVERIDADES.includes(v.severidad) ? v.severidad : "medium",
    cwe_id: cweCorto(v.cwe),
    recommendation: v.solucion || null,
    references_list: cves.length ? JSON.stringify(cves.map((c) => `${NVD}${c}`)) : null,
    remediation_due_date: P.ymd(v.fecha_limite) || null,
  };
}

const COLS_FINDING = ["id", "engagement_id", "phase_type", "title", "description", "steps_to_reproduce", "affected_asset",
  "cvss_vector_31", "cvss_score_31", "cvss_vector_40", "cvss_score_40", "severity", "initial_severity", "cwe_id",
  "recommendation", "references_list", "remediation_due_date", "status", "created_by"];

/**
 * Lleva una vulnerabilidad a un engagement dentro de una transacción. Devuelve { creado } o { ya }.
 * `eng` ya validado (mismo cliente, visible). `usuario`: { id, username }.
 */
async function llevarUna(tx, { vulnId, cliente, eng, usuario, tenantEnFinding = false }) {
  const v = await tx.qRow("SELECT * FROM vuln_hallazgos WHERE id = ? AND cliente_id = ? FOR UPDATE", [vulnId, cliente]);
  if (!v) return { noEncontrada: true };
  if (v.finding_id) {
    const f = await tx.qRow("SELECT f.id, f.engagement_id FROM findings f JOIN engagements e ON e.id = f.engagement_id WHERE f.id = ?", [v.finding_id]);
    if (f) return { ya: { id: v.id, finding_id: f.id, engagement_id: f.engagement_id } };
  }
  const a = await tx.qRow("SELECT id, nombre, ip, hostname FROM activos WHERE id = ?", [v.activo_id]);
  const h = hallazgoDesde(v, a);
  const fid = uuidv4();
  const fila = { ...h, id: fid, engagement_id: eng.id, phase_type: "scanning", initial_severity: h.severity, status: "open", created_by: usuario.id };
  const cols = [...COLS_FINDING];
  if (tenantEnFinding) { cols.push("tenant_id"); fila.tenant_id = eng.tenant_id ?? null; }
  await tx.qRun(`INSERT INTO findings (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(",")})`, cols.map((k) => fila[k] ?? null));
  await tx.qRun("UPDATE vuln_hallazgos SET engagement_id = ?, finding_id = ? WHERE id = ?", [eng.id, fid, v.id]);
  await M.repoSQL(tx).anotar({
    id: uuidv4(), cliente_id: cliente, hallazgo_id: v.id, estado_antes: null, estado_despues: null, evento: "a_engagement",
    motivo: `Llevada al engagement "${String(eng.title || "").slice(0, 200)}" (hallazgo ${fid.slice(0, 8).toUpperCase()})`,
    automatico: 0, usuario: usuario.username,
  });
  return { creado: { id: v.id, finding_id: fid, engagement_id: eng.id, titulo: h.title } };
}

/**
 * El retest de un hallazgo queda en el historial de la vulnerabilidad de la que nació (si nació de una).
 * No cambia su estado: ver la decisión arriba. Nunca hace fallar el retest.
 */
async function registrarRetest({ qRows, qRun }, findingId, resultado, usuario) {
  try {
    const vs = await qRows("SELECT id, cliente_id FROM vuln_hallazgos WHERE finding_id = ?", [findingId]);
    for (const v of vs) {
      await M.repoSQL({ qRows, qRun }).anotar({
        id: uuidv4(), cliente_id: v.cliente_id, hallazgo_id: v.id, estado_antes: null, estado_despues: null, evento: "retest",
        motivo: `Retest en el engagement: ${resultado}`, automatico: 0, usuario: usuario || null,
      });
    }
    return vs.length;
  } catch (e) {
    console.error("[vulnerabilidades] retest:", e.message);
    return 0;
  }
}

/** Lo que muestra la ficha del enlace con el engagement (solo si quien mira ve el engagement). */
async function enlaceDe({ qRow }, h, req, engagementVisible) {
  if (!h.finding_id) return null;
  const f = await qRow(
    `SELECT f.id, f.status, f.retest_status, f.retested_at, f.severity, e.id AS engagement_id, e.title AS engagement_titulo, e.status AS engagement_estado
       FROM findings f JOIN engagements e ON e.id = f.engagement_id WHERE f.id = ?`, [h.finding_id]);
  if (!f) return { roto: true };
  if (engagementVisible && !(await engagementVisible(req, { id: f.engagement_id }))) return { sin_acceso: true };
  return {
    finding_id: f.id, estado: f.status, retest: f.retest_status || "not_retested", retest_fecha: f.retested_at || null,
    engagement_id: f.engagement_id, engagement_titulo: f.engagement_titulo, engagement_estado: f.engagement_estado,
  };
}

function montar(app, deps) {
  const faltan = ["mw", "clienteO403", "qRow", "qRows", "qRun", "transaccion", "auditLog", "fallo"].filter((k) => !deps[k]);
  if (faltan.length) throw new Error(`vulnerabilidades-engagement.montar: faltan dependencias: ${faltan.join(", ")}`);
  const { mw, clienteO403, qRows, transaccion, auditLog, fallo } = deps;
  const visible = deps.engagementVisible || (async () => true);

  /** Engagements del cliente que la persona ve y que todavía reciben hallazgos. */
  async function engagementsDelCliente(req, cliente) {
    const filas = await qRows(
      `SELECT * FROM engagements WHERE client_id = ? AND status NOT IN (${ESTADOS_CERRADOS.map(() => "?").join(",")})
        ORDER BY updated_at DESC LIMIT 300`, [cliente, ...ESTADOS_CERRADOS]);
    const o = [];
    for (const e of filas) if (await visible(req, e)) o.push(e);
    return o;
  }

  app.get("/api/vulnerabilidades/engagements", ...mw.editar, async (req, res) => {
    const cliente = clienteO403(req, res); if (!cliente) return;
    try {
      res.json((await engagementsDelCliente(req, cliente)).map((e) => ({
        id: e.id, titulo: e.title, codigo: e.codename || null, estado: e.status, inicio: e.start_date || null, fin: e.end_date || null,
      })));
    } catch (e) { fallo(res, e, "engagements del cliente"); }
  });

  /**
   * Lleva una o varias vulnerabilidades (ids) al engagement elegido. Todas del cliente del pedido; el
   * engagement también. Las que ya tienen hallazgo no se duplican: vuelven en `ya_llevadas`.
   */
  app.post("/api/vulnerabilidades/a-engagement", ...mw.editar, async (req, res) => {
    const cliente = clienteO403(req, res); if (!cliente) return;
    const ids = [...new Set((Array.isArray(req.body?.ids) ? req.body.ids : []).map((x) => String(x || "").trim()).filter(Boolean))];
    if (!ids.length) return res.status(400).json({ error: "Elegí al menos una vulnerabilidad." });
    if (ids.length > MAX_LOTE) return res.status(400).json({ error: `Se llevan hasta ${MAX_LOTE} vulnerabilidades por vez.` });
    const engId = String(req.body?.engagement_id || "").trim();
    try {
      const eng = engId ? (await qRows("SELECT * FROM engagements WHERE id = ?", [engId]))[0] : null;
      // Otro cliente, archivado o no visible: la misma respuesta (no se confirma que exista).
      if (!eng || eng.client_id !== cliente || ESTADOS_CERRADOS.includes(eng.status) || !(await visible(req, eng))) {
        return res.status(404).json({ error: "Elegí un engagement abierto del mismo cliente." });
      }
      const usuario = { id: req.user.id, username: req.user.username };
      const r = await transaccion(async (tx) => {
        const out = { creados: [], ya_llevadas: [], no_encontradas: [] };
        for (const id of ids) {
          const x = await llevarUna(tx, { vulnId: id, cliente, eng, usuario, tenantEnFinding: !!deps.tenantEnFinding });
          if (x.creado) out.creados.push(x.creado);
          else if (x.ya) out.ya_llevadas.push(x.ya);
          else out.no_encontradas.push(id);
        }
        return out;
      });
      for (const c of r.creados) {
        // Del lado del engagement, la actividad de siempre: el feed lo muestra como un hallazgo nuevo.
        auditLog(req.user.id, req.user.username, "finding_create", "engagements", eng.id, `${String(c.titulo).slice(0, 70)} (desde Vulnerabilidades)`, req.ip);
        if (deps.notificarActividad) deps.notificarActividad(eng.id, "finding_create", String(c.titulo).slice(0, 80));
      }
      if (r.creados.length) {
        auditLog(req.user.id, req.user.username, "vuln_a_engagement", "vulnerabilidades", eng.id,
          `${r.creados.length} llevadas a ${String(eng.title || "").slice(0, 80)}${r.ya_llevadas.length ? `, ${r.ya_llevadas.length} ya estaban` : ""}`, req.ip);
      }
      res.status(r.creados.length ? 201 : 200).json({ engagement_id: eng.id, ...r });
    } catch (e) { fallo(res, e, "pase a engagement"); }
  });

  return { enlace: (h, req) => enlaceDe(deps, h, req, deps.engagementVisible) };
}

module.exports = { montar, registrarRetest, hallazgoDesde, activoAfectado, llevarUna, MAX_LOTE };
