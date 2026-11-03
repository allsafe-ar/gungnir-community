"use strict";
/**
 * Vulnerabilidades: seguimiento continuo por cliente, separado de los engagements.
 *
 * Un engagement es un trabajo con principio y fin, y sus hallazgos son parte del informe. Lo que
 * llega de los escaneos periódicos (OpenVAS, Nessus, Nmap, ZAP, Burp) es otra cosa: el estado de
 * la infraestructura del cliente a lo largo del tiempo. Cada vulnerabilidad cuelga de un activo del
 * inventario único y se sigue entre importaciones: aparece, se cierra cuando deja de aparecer en un
 * escaneo que cubrió ese equipo y se reabre si vuelve. La lógica está en `vulnerabilidades-motor.js`.
 *
 * 🔑 El alcance es el del inventario: el cliente va en `?cliente=` (o en el cuerpo) y tiene que ser
 * uno de los clientes de la instalación (`cargarClientes` en `inventario-community.js`).
 *
 * Gungnir Community: copia del módulo de Gungnir Pro con la misma fórmula de deduplicación, las
 * mismas reglas de cierre y reapertura y las mismas tablas, para que una instalación pase a Pro sin
 * perder la historia. La edición libre tiene una sola organización: no hay inquilinos ni staff, y el
 * administrador de la instalación hace lo que en Pro hace el staff (política global de plazos y
 * "Actualizar ahora" de KEV y EPSS).
 *
 * Etapa 2 (priorización, plazos y métricas): EPSS y KEV con cachés propias, prioridad calculada,
 * plazo por severidad con política por cliente y métricas. La lógica está en
 * `vulnerabilidades-prioridad.js` y la descarga y el recálculo en `vulnerabilidades-enriquecimiento.js`.
 *
 * Solo en Pro (no están en esta copia): los conectores programados por cliente (Wazuh Indexer y
 * OpenVAS) y la API de importación para CI/CD. Las columnas que usan (`origen`, `conector_id`,
 * `externo_id`, `huella`) se crean igual, para que el esquema sea el mismo.
 *
 * Preparado y sin implementar: el pase a engagement (`engagement_id`, `finding_id`).
 *
 * Cómo se monta en el server.js:
 *
 *   const v = vulnerabilidades.montar(app, { auth, auditLog, qRow, qRows, qRun, transaccion });
 *   v.enriquecimiento.programar();
 */
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const escaneres = require("./importacion-escaneres");
const ingreso = require("./inventario/ingreso");
const { norm } = require("./inventario/identidad");
const M = require("./vulnerabilidades-motor");
const P = require("./vulnerabilidades-prioridad");
const E = require("./vulnerabilidades-enriquecimiento");
const { middlewares, clienteDelPedido, ROLES_ADMINISTRAR } = require("./inventario-community");

const MAX_LISTA = 500;
const MAX_ALCANCE_EXTRA = 2000;
/** Escáneres web: el host es un sitio, no un equipo de la red (ver `resolverActivos`). */
const WEB = ["zap", "burp"];

const codigoDe = (id) => String(id).slice(0, 8).toUpperCase();

/**
 * Reconoce o crea el activo de cada host por la ingesta canónica del inventario.
 *
 * 🔑 Todos los escáneres entran con la misma fuente de inventario (`escaneo`) y la IP (o el nombre)
 * como identificador externo: así OpenVAS y Nessus, que casi siempre ven solo la IP, reconocen el
 * mismo equipo en vez de crear uno cada uno. Si el equipo ya estaba en el inventario por otra fuente
 * con nombre o serie, la ingesta lo vincula; si solo coincide la IP, lo crea y deja la duda para que
 * la resuelva una persona (regla del inventario: la IP sola nunca une).
 *
 * ⚠️ En ZAP y Burp el host es un sitio (`www.cliente.com`). El inventario compara nombres de host sin
 * dominio (`www`), así que dos sitios distintos se unirían: por eso el sitio entra como nombre, no
 * como nombre de host, y se reconoce por el identificador externo.
 */
async function resolverActivos(dep, { cliente, fuente, hosts, usuario }) {
  const mapa = new Map();
  let nuevos = 0;
  for (const h of hosts) {
    const k = claveHost(h);
    if (!k || mapa.has(k)) continue;
    const web = WEB.includes(fuente);
    const entrante = web
      ? { nombre: h.hostname || h.ip, ip: h.ip || null, tipo: "expuesto" }
      : { nombre: h.hostname || h.ip, ip: h.ip || null, hostname: h.hostname || null };
    const externoId = h.ip ? `ip:${h.ip}` : `host:${String(h.hostname).toLowerCase()}`;
    const r = await ingreso.ingresar(dep, { tenant: cliente, fuente: M.FUENTE_INVENTARIO, externoId, entrante: { ...entrante, herramienta: fuente }, usuario });
    if (r.id) mapa.set(k, r.id);
    if (r.accion === "nuevo" || r.accion === "nuevo_con_duda") nuevos++;
  }
  return { mapa, nuevos };
}

function claveHost(h) {
  const ip = norm("ip", h?.ip), hn = h?.hostname ? String(h.hostname).trim().toLowerCase() : null;
  return ip || hn ? `${ip || ""}|${hn || ""}` : null;
}

/**
 * El alcance que agrega quien importa (equipos que el escaneo cubrió aunque el archivo no los nombre).
 * Solo se reconocen activos que ya existen: un nombre mal tipeado no crea un equipo.
 */
async function alcanceExtra({ qRows }, cliente, lineas) {
  const pedidos = [...new Set(lineas.map((l) => String(l).trim()).filter(Boolean))].slice(0, MAX_ALCANCE_EXTRA);
  if (!pedidos.length) return { ids: [], sinActivo: [] };
  const activos = await qRows("SELECT id, nombre, ip, hostname FROM activos WHERE tenant_id = ? AND eliminado_at IS NULL", [cliente]);
  const ids = [], sinActivo = [];
  for (const p of pedidos) {
    const v = p.toLowerCase();
    const a = activos.filter((x) => norm("ip", x.ip) === v || (x.hostname && x.hostname.toLowerCase() === v)
      || norm("hostname", x.hostname) === v || (x.nombre && x.nombre.toLowerCase() === v));
    if (a.length) ids.push(...a.map((x) => x.id)); else sinActivo.push(p);
  }
  return { ids, sinActivo };
}

/**
 * Importa un archivo de escáner para un cliente. Todo en una transacción: si algo falla, no queda
 * ni un activo ni una vulnerabilidad a medias.
 *
 * `origen`: manual (archivo subido en la pantalla), api (CI/CD con clave de API) o conector.
 */
async function importar(deps, { cliente, fuente, xml, extra = [], usuario, usuarioId = null, archivo = null, origen = "manual", conectorId = null }) {
  const parser = escaneres.PARSERS[fuente];
  if (!parser) return { error: "Fuente no importable.", status: 400 };
  let crudos;
  try { crudos = parser(xml); } catch (e) { return { error: `No se pudo leer el archivo: ${e.message}`, status: 400 }; }
  const items = crudos.map(M.desdeParser).filter((i) => i.titulo && (i.host.ip || i.host.hostname));
  const hosts = escaneres.hostsEscaneados(fuente, xml, crudos);
  if (!items.length && !hosts.length) return { error: "El archivo no tiene vulnerabilidades ni equipos escaneados. Revisá que la fuente elegida sea la correcta.", status: 400 };
  return importarItems(deps, { cliente, fuente, items, hosts, extra, usuario, usuarioId, archivo, origen, conectorId });
}

/**
 * Lo común a un archivo, a la API y al conector de OpenVAS: hallazgos ya en el formato del motor
 * (con `host`) y los equipos que cubrió el escaneo. Una transacción.
 */
async function importarItems(deps, { cliente, fuente, items, hosts, extra = [], usuario, usuarioId = null, archivo = null,
  origen = "manual", conectorId = null, cierreMinimo = null }) {
  return deps.transaccion(async (tx) => {
    // Dos importaciones del mismo cliente a la vez se pisarían el cierre: se hacen de a una.
    // En Community `clients` no tiene inquilino: `tenant_id` va nulo, como en una instalación de Pro
    // sin inquilinos (el script de migración a la nube de Pro lo completa).
    const cli = await tx.qRow("SELECT id, NULL AS tenant_id FROM clients WHERE id = ? FOR UPDATE", [cliente]);
    if (!cli) return { error: "Cliente no encontrado.", status: 404 };
    const dep = { ...tx, uuidv4 };
    const { mapa, nuevos: activosNuevos } = await resolverActivos(dep, { cliente, fuente, hosts: [...hosts, ...items.map((i) => i.host)], usuario });
    const conActivo = items.map((i) => ({ ...i, activo_id: mapa.get(claveHost(i.host)) })).filter((i) => i.activo_id);
    const ext = await alcanceExtra(tx, cliente, extra);
    // El alcance son los equipos que cubrió el escaneo, no todos los que nombra un hallazgo
    // (en un archivo, los dos coinciden porque `hostsEscaneados` ya suma los de los hallazgos).
    const alcanceHosts = new Set(hosts.map(claveHost).filter(Boolean));
    const alcance = [...new Set([...[...mapa].filter(([k]) => alcanceHosts.has(k)).map(([, id]) => id), ...ext.ids])];

    const importacion = { id: uuidv4() };
    importacion.codigo = codigoDe(importacion.id);
    const delta = await M.aplicar(M.repoSQL(tx), {
      cliente, tenant: cli.tenant_id, fuente, items: conActivo, alcance, importacion, usuario, nuevoId: uuidv4, cierreMinimo,
    });
    // Prioridad y plazo de lo que entró, cambió de severidad o se reabrió, con lo que ya tienen las
    // cachés de KEV y EPSS. Lo que la caché de EPSS no tiene se completa después (completarCliente).
    await (deps.enriquecimiento || E.crear(deps)).recalcular({ cliente, db: tx });
    await registrarImportacion(tx, { id: importacion.id, tenant: cli.tenant_id, cliente, fuente, origen, conectorId, archivo,
      alcance, delta, activosNuevos, usuario, usuarioId });
    return {
      importacion_id: importacion.id, codigo: importacion.codigo, fuente, origen, ...delta,
      activos_nuevos: activosNuevos, alcance: alcance.length, sin_activo: items.length - conActivo.length,
      alcance_no_reconocido: ext.sinActivo,
    };
  });
}

/** La fila del historial de importaciones, con los nombres de los equipos del alcance. */
async function registrarImportacion(db, { id, tenant, cliente, fuente, origen = "manual", conectorId = null, archivo = null, alcance,
  delta, activosNuevos, usuario = null, usuarioId = null }) {
  const nombres = [];
  for (const t of M.trozos(alcance)) {
    nombres.push(...await db.qRows(`SELECT id, nombre FROM activos WHERE id IN (${t.map(() => "?").join(",")})`, t));
  }
  await db.qRun(
    `INSERT INTO vuln_importaciones (id, tenant_id, cliente_id, fuente, origen, conector_id, archivo, alcance, alcance_cantidad, items,
       nuevos, cerrados, reabiertos, sin_cambios, activos_nuevos, usuario, usuario_id)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [id, tenant, cliente, fuente, origen, conectorId, archivo ? String(archivo).slice(0, 255) : null,
     JSON.stringify(nombres.map((n) => ({ id: n.id, nombre: n.nombre }))), alcance.length, delta.total,
     delta.nuevos, delta.cerrados, delta.reabiertos, delta.sin_cambios, activosNuevos, usuario, usuarioId]);
}

// ── Rutas ────────────────────────────────────────────────────────────────────────────────────────
const ORDEN_SEVERIDAD = "FIELD(v.severidad,'critical','high','medium','low','info')";
/** Sin prioridad calculada (no debería quedar ninguna) va al final, no al principio como haría FIELD. */
const ORDEN_PRIORIDAD = "COALESCE(NULLIF(FIELD(v.prioridad,'urgente','alta','media','baja'),0),5)";

/** Fechas de calendario como texto: un DATE convertido a JSON se correría de día por la zona. */
function conDerivados(f, hoy) {
  const o = { ...f, fecha_limite: P.ymd(f.fecha_limite), kev_vence: P.ymd(f.kev_vence) };
  o.estado_plazo = P.estadoPlazo(o, hoy);
  return o;
}

// En Community no hay inquilinos (`tenant_id` no existe): el administrador de la instalación es el staff.
const esStaffAdmin = (req) => req.user?.role === "admin" && req.user?.tenant_id == null;

function montar(app, deps) {
  const faltan = ["auth", "auditLog", "qRow", "qRows", "qRun", "transaccion"].filter((k) => !deps[k]);
  if (faltan.length) throw new Error(`vulnerabilidades.montar: faltan dependencias: ${faltan.join(", ")}`);
  const { auditLog, qRow, qRows, qRun } = deps;
  const mw = middlewares(deps);
  const enr = deps.enriquecimiento || E.crear({ qRow, qRows, qRun });
  deps = { ...deps, enriquecimiento: enr };
  const subida = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024, files: 1 } });
  const fallo = (res, e, donde) => { console.error(`[vulnerabilidades] ${donde}:`, e.message); res.status(500).json({ error: "No se pudo completar la operación." }); };
  const auditar = (req, accion, id, detalle) => auditLog(req.user?.id, req.user?.username, accion, "vulnerabilidades", id, detalle, req.ip);

  function clienteO403(req, res) {
    const c = clienteDelPedido(req);
    if (!c) { res.status(403).json({ error: "Elegí un cliente al que tengas acceso." }); return null; }
    return c;
  }
  /** Trae la vulnerabilidad y verifica que su cliente sea visible para quien pide. Si no, 404. */
  async function hallazgoO404(req, res, id) {
    const h = await qRow("SELECT * FROM vuln_hallazgos WHERE id = ?", [id]);
    if (!h || !req.clientesVisibles?.has(h.cliente_id)) { res.status(404).json({ error: "Vulnerabilidad no encontrada." }); return null; }
    return h;
  }

  /** Filtros del listado, siempre dentro del cliente. */
  function filtros(req, cliente) {
    const w = ["v.cliente_id = ?"], p = [cliente];
    const { estado, severidad, fuente, activo, q, prioridad, kev, plazo } = req.query;
    if (estado === "abiertas") { w.push(`v.estado IN (${M.ABIERTOS.map(() => "?").join(",")})`); p.push(...M.ABIERTOS); }
    else if (estado === "cerradas") { w.push(`v.estado IN (${M.CERRADOS.map(() => "?").join(",")})`); p.push(...M.CERRADOS); }
    else if (M.ESTADOS.includes(estado)) { w.push("v.estado = ?"); p.push(estado); }
    if (M.SEVERIDADES.includes(severidad)) { w.push("v.severidad = ?"); p.push(severidad); }
    if (M.FUENTES.includes(fuente)) { w.push("v.fuente = ?"); p.push(fuente); }
    if (activo) { w.push("v.activo_id = ?"); p.push(String(activo)); }
    if (P.PRIORIDADES.includes(prioridad)) { w.push("v.prioridad = ?"); p.push(prioridad); }
    if (kev === "1") w.push("v.kev = 1");
    if (["vencida", "por_vencer", "en_plazo"].includes(plazo)) {
      // El día de hoy lo pone el servidor de la aplicación (zona local), no la base.
      const hoy = P.hoyLocal(), tope = P.sumarDias(hoy, P.POR_VENCER_DIAS);
      w.push(`v.estado IN (${M.ABIERTOS.map(() => "?").join(",")})`); p.push(...M.ABIERTOS);
      if (plazo === "vencida") { w.push("v.fecha_limite < ?"); p.push(hoy); }
      else if (plazo === "por_vencer") { w.push("v.fecha_limite >= ? AND v.fecha_limite <= ?"); p.push(hoy, tope); }
      else { w.push("v.fecha_limite > ?"); p.push(tope); }
    }
    if (q && String(q).trim()) {
      const like = `%${String(q).trim().slice(0, 200).replace(/[\\%_]/g, (c) => "\\" + c)}%`;
      w.push("(v.titulo LIKE ? OR v.cves LIKE ? OR a.nombre LIKE ? OR a.ip LIKE ? OR a.hostname LIKE ?)");
      p.push(like, like, like, like, like);
    }
    return { where: w.join(" AND "), params: p };
  }

  const COLS_LISTA = `v.id, v.cliente_id, v.activo_id, v.fuente, v.fuente_ultima, v.titulo, v.severidad, v.cvss, v.cves, v.cwe,
    v.puerto, v.protocolo, v.servicio, v.estado, v.primera_vez, v.ultima_vez, v.fecha_cierre, v.reaperturas, v.responsable,
    v.prioridad, v.epss, v.epss_percentil, v.kev, v.kev_ransomware, v.kev_vence, v.fecha_limite,
    a.nombre AS activo_nombre, a.ip AS activo_ip, a.hostname AS activo_hostname`;

  // ── Rutas fijas antes de /:id ────────────────────────────────────────────────────────────────
  app.get("/api/vulnerabilidades/catalogo", ...mw.leer, (_req, res) => {
    res.json({ estados: M.ESTADOS, manuales: M.MANUALES, severidades: M.SEVERIDADES, fuentes: M.FUENTES, importables: M.IMPORTABLES,
      prioridades: P.PRIORIDADES, estados_plazo: P.ESTADOS_PLAZO });
  });

  /** Detalle de KEV de una lista de CVE (para la insignia: nombre, ransomware, fechas de CISA). */
  async function detalleKev(cves) {
    const m = new Map();
    for (const t of P.lotes([...new Set(cves)], 500)) {
      if (!t.length) continue;
      for (const k of await qRows(`SELECT cve, nombre, proveedor, producto, alta, vence, ransomware FROM vuln_kev WHERE cve IN (${t.map(() => "?").join(",")})`, t)) {
        m.set(k.cve, { cve: k.cve, nombre: k.nombre, proveedor: k.proveedor, producto: k.producto, alta: P.ymd(k.alta), vence: P.ymd(k.vence), ransomware: Number(k.ransomware) === 1 });
      }
    }
    return m;
  }

  // ── Etapa 2: métricas, enriquecimiento y plazos ─────────────────────────────────────────────
  app.get("/api/vulnerabilidades/metricas", ...mw.leer, async (req, res) => {
    const cliente = clienteO403(req, res); if (!cliente) return;
    try {
      const ahora = new Date(), hoy = P.hoyLocal(ahora);
      const marcas = M.ABIERTOS.map(() => "?").join(",");
      const [abiertas, cerradas, eventos, propia, estado] = await Promise.all([
        qRows(`SELECT estado, severidad, prioridad, fecha_limite, kev, kev_ransomware, primera_vez FROM vuln_hallazgos
                WHERE cliente_id = ? AND estado IN (${marcas})`, [cliente, ...M.ABIERTOS]),
        qRows(`SELECT estado, severidad, primera_vez, fecha_cierre FROM vuln_hallazgos
                WHERE cliente_id = ? AND estado = 'remediado' AND fecha_cierre >= (NOW() - INTERVAL 90 DAY)`, [cliente]),
        // La tendencia se reconstruye con el historial completo del cliente (solo tres columnas).
        qRows("SELECT hallazgo_id, estado_despues, created_at FROM vuln_historial WHERE cliente_id = ? AND estado_despues IS NOT NULL", [cliente]),
        enr.politicaDelCliente(cliente),
        enr.estado(),
      ]);
      const global = await enr.politicaGlobal();
      res.json({
        hoy, ...P.resumenAbiertas(abiertas, hoy), mttr: P.mttr(cerradas, ahora, 90), tendencia: P.tendencia(eventos, ahora, 12),
        politica: { efectiva: P.politicaEfectiva(propia, global), propia: !!propia },
        enriquecimiento: { kev: estado.kev, epss: estado.epss, habilitada: estado.habilitada, en_curso: estado.en_curso },
      });
    } catch (e) { fallo(res, e, "métricas"); }
  });

  app.get("/api/vulnerabilidades/enriquecimiento", ...mw.leer, async (req, res) => {
    try { res.json({ ...(await enr.estado()), puede_actualizar: esStaffAdmin(req) }); } catch (e) { fallo(res, e, "estado del enriquecimiento"); }
  });

  /** "Actualizar ahora": KEV y EPSS son cachés de toda la instalación, por eso es del staff de AllSafe. */
  app.post("/api/vulnerabilidades/enriquecimiento/actualizar", ...mw.leer, async (req, res) => {
    if (!esStaffAdmin(req)) return res.status(403).json({ error: "La actualización de KEV y EPSS la hace un administrador de la plataforma." });
    if (!E.habilitada()) return res.status(409).json({ error: "La consulta a fuentes externas está deshabilitada en esta instalación." });
    const yaCorria = enr.enCurso();
    enr.actualizarTodo()
      .then((r) => auditar(req, "vuln_enriquecer", null, `KEV ${r.kev.ok ? r.kev.cantidad : r.kev.error}; EPSS ${r.epss.ok ? r.epss.consultados : r.epss.error}; ${r.recalculo.cambiados} recalculadas`))
      .catch((e) => console.error("[vulnerabilidades] actualizar ahora:", e.message));
    res.status(202).json({ ok: true, en_curso: true, ya_estaba: yaCorria });
  });

  app.get("/api/vulnerabilidades/plazos", ...mw.leer, async (req, res) => {
    const cliente = clienteO403(req, res); if (!cliente) return;
    try {
      const [global, propia] = await Promise.all([enr.politicaGlobal(), enr.politicaDelCliente(cliente)]);
      res.json({
        defecto: P.POLITICA_DEFECTO, global, cliente: propia, efectiva: P.politicaEfectiva(propia, global),
        kev_dias_max: P.KEV_DIAS_MAX, por_vencer_dias: P.POR_VENCER_DIAS, puede_editar_global: esStaffAdmin(req),
      });
    } catch (e) { fallo(res, e, "plazos"); }
  });

  /** La política global vale para todos los clientes sin política propia: es del staff de AllSafe. */
  app.put("/api/vulnerabilidades/plazos/global", ...mw.leer, async (req, res) => {
    if (!esStaffAdmin(req)) return res.status(403).json({ error: "La política global de plazos la define un administrador de la plataforma." });
    const v = P.validarPolitica(req.body?.politica);
    if (v.error) return res.status(400).json({ error: v.error });
    try {
      await enr.guardarPoliticaGlobal(v.politica);
      auditar(req, "vuln_plazos_global", null, JSON.stringify(v.politica));
      // El recálculo de toda la instalación va en segundo plano (por lotes).
      enr.recalcular().catch((e) => console.error("[vulnerabilidades] recálculo de plazos:", e.message));
      res.json({ ok: true, politica: v.politica });
    } catch (e) { fallo(res, e, "plazos globales"); }
  });

  app.put("/api/vulnerabilidades/plazos", ...mw.administrar, async (req, res) => {
    const cliente = clienteO403(req, res); if (!cliente) return;
    const v = P.validarPolitica(req.body?.politica);
    if (v.error) return res.status(400).json({ error: v.error });
    try {
      await enr.guardarPoliticaCliente(cliente, v.politica, req.user.username);
      const r = await enr.recalcular({ cliente });
      auditar(req, "vuln_plazos_cliente", cliente, JSON.stringify(v.politica));
      res.json({ ok: true, politica: v.politica, recalculadas: r.cambiados });
    } catch (e) { fallo(res, e, "plazos del cliente"); }
  });

  /** Sin política propia, el cliente vuelve a la global. */
  app.delete("/api/vulnerabilidades/plazos", ...mw.administrar, async (req, res) => {
    const cliente = clienteO403(req, res); if (!cliente) return;
    try {
      await enr.borrarPoliticaCliente(cliente);
      const r = await enr.recalcular({ cliente });
      auditar(req, "vuln_plazos_cliente", cliente, "vuelve a la política global");
      res.json({ ok: true, recalculadas: r.cambiados });
    } catch (e) { fallo(res, e, "plazos del cliente"); }
  });

  app.get("/api/vulnerabilidades/resumen", ...mw.leer, async (req, res) => {
    const cliente = clienteO403(req, res); if (!cliente) return;
    try {
      const marcas = M.ABIERTOS.map(() => "?").join(",");
      const [porSeveridad, porEstado, recientes, fuentes, ultima] = await Promise.all([
        qRows(`SELECT severidad, COUNT(*) AS n FROM vuln_hallazgos WHERE cliente_id = ? AND estado IN (${marcas}) GROUP BY severidad`, [cliente, ...M.ABIERTOS]),
        qRows("SELECT estado, COUNT(*) AS n FROM vuln_hallazgos WHERE cliente_id = ? GROUP BY estado", [cliente]),
        qRow("SELECT COUNT(*) AS n FROM vuln_hallazgos WHERE cliente_id = ? AND estado = 'remediado' AND fecha_cierre >= (NOW() - INTERVAL 30 DAY)", [cliente]),
        qRows("SELECT DISTINCT fuente FROM vuln_hallazgos WHERE cliente_id = ? ORDER BY fuente", [cliente]),
        qRow("SELECT id, fuente, created_at, nuevos, cerrados, reabiertos FROM vuln_importaciones WHERE cliente_id = ? ORDER BY created_at DESC LIMIT 1", [cliente]),
      ]);
      const abiertas = Object.fromEntries(M.SEVERIDADES.map((s) => [s, 0]));
      for (const f of porSeveridad) abiertas[f.severidad] = Number(f.n);
      const estados = Object.fromEntries(M.ESTADOS.map((s) => [s, 0]));
      for (const f of porEstado) if (f.estado in estados) estados[f.estado] = Number(f.n);
      res.json({
        abiertas, total_abiertas: Object.values(abiertas).reduce((a, b) => a + b, 0),
        reabiertas: estados.reabierto, remediadas_30d: Number(recientes?.n || 0), estados,
        fuentes: fuentes.map((f) => f.fuente), ultima_importacion: ultima || null,
      });
    } catch (e) { fallo(res, e, "resumen"); }
  });

  app.get("/api/vulnerabilidades/importaciones", ...mw.leer, async (req, res) => {
    const cliente = clienteO403(req, res); if (!cliente) return;
    try {
      res.json(await qRows(
        `SELECT id, fuente, origen, conector_id, archivo, alcance_cantidad, items, nuevos, cerrados, reabiertos, sin_cambios, activos_nuevos, usuario, created_at
           FROM vuln_importaciones WHERE cliente_id = ? ORDER BY created_at DESC LIMIT 200`, [cliente]));
    } catch (e) { fallo(res, e, "importaciones"); }
  });

  app.get("/api/vulnerabilidades/importaciones/:iid", ...mw.leer, async (req, res) => {
    try {
      const i = await qRow("SELECT * FROM vuln_importaciones WHERE id = ?", [req.params.iid]);
      if (!i || !req.clientesVisibles?.has(i.cliente_id)) return res.status(404).json({ error: "Importación no encontrada." });
      if (typeof i.alcance === "string") { try { i.alcance = JSON.parse(i.alcance); } catch { i.alcance = []; } }
      i.cambios = await qRows(
        `SELECT h.hallazgo_id, h.evento, h.estado_antes, h.estado_despues, v.titulo, v.severidad, a.nombre AS activo_nombre
           FROM vuln_historial h JOIN vuln_hallazgos v ON v.id = h.hallazgo_id LEFT JOIN activos a ON a.id = v.activo_id
          WHERE h.importacion_id = ? AND h.cliente_id = ? ORDER BY ${ORDEN_SEVERIDAD}, v.titulo LIMIT 1000`,
        [i.id, i.cliente_id]);
      res.json(i);
    } catch (e) { fallo(res, e, "importación"); }
  });

  // Auth antes que multer: un pedido sin sesión no llega a subir nada.
  app.post("/api/vulnerabilidades/importar", mw.editar[0], subida.single("archivo"), ...mw.editar.slice(1), async (req, res) => {
    const cliente = clienteO403(req, res); if (!cliente) return;
    const fuente = String(req.body?.fuente || "").toLowerCase();
    if (!M.IMPORTABLES.includes(fuente)) return res.status(400).json({ error: "Elegí la herramienta del archivo: OpenVAS, Nessus, Nmap, ZAP o Burp." });
    if (!req.file?.buffer?.length) return res.status(400).json({ error: "Falta el archivo del escaneo." });
    const extra = String(req.body?.alcance || "").split(/[\s,;]+/).filter(Boolean);
    try {
      const r = await importar(deps, {
        cliente, fuente, xml: req.file.buffer.toString("utf8"), extra,
        usuario: req.user.username, usuarioId: req.user.id, archivo: req.file.originalname,
      });
      if (r.error) return res.status(r.status || 400).json({ error: r.error });
      // EPSS de los CVE que la caché todavía no tiene: en segundo plano, sin demorar la respuesta.
      enr.completarCliente(cliente);
      auditar(req, "vuln_import", r.importacion_id,
        `${fuente}: ${r.nuevos} nuevas, ${r.cerrados} cerradas, ${r.reabiertos} reabiertas, ${r.sin_cambios} sin cambios`);
      res.json(r);
    } catch (e) { fallo(res, e, "importar"); }
  });

  app.get("/api/vulnerabilidades/activo/:activoId", ...mw.leer, async (req, res) => {
    try {
      const a = await qRow("SELECT id, tenant_id FROM activos WHERE id = ? AND eliminado_at IS NULL", [req.params.activoId]);
      if (!a || !req.clientesVisibles?.has(a.tenant_id)) return res.status(404).json({ error: "Activo no encontrado." });
      const hoy = P.hoyLocal();
      res.json((await qRows(
        `SELECT ${COLS_LISTA} FROM vuln_hallazgos v JOIN activos a ON a.id = v.activo_id
          WHERE v.activo_id = ? AND v.cliente_id = ? ORDER BY FIELD(v.estado,'reabierto','abierto','en_remediacion','riesgo_aceptado','falso_positivo','remediado'), ${ORDEN_PRIORIDAD}, ${ORDEN_SEVERIDAD}, v.primera_vez
          LIMIT ${MAX_LISTA}`, [a.id, a.tenant_id])).map((f) => conDerivados(f, hoy)));
    } catch (e) { fallo(res, e, "por activo"); }
  });

  app.get("/api/vulnerabilidades", ...mw.leer, async (req, res) => {
    const cliente = clienteO403(req, res); if (!cliente) return;
    try {
      const { where, params } = filtros(req, cliente);
      const limite = Math.min(Math.max(parseInt(req.query.limite, 10) || 100, 1), MAX_LISTA);
      const pagina = Math.max(parseInt(req.query.pagina, 10) || 1, 1);
      const total = await qRow(`SELECT COUNT(*) AS n FROM vuln_hallazgos v JOIN activos a ON a.id = v.activo_id WHERE ${where}`, params);
      // Orden: prioridad, después severidad, después antigüedad (lo más viejo primero).
      const crudas = await qRows(
        `SELECT ${COLS_LISTA} FROM vuln_hallazgos v JOIN activos a ON a.id = v.activo_id
          WHERE ${where} ORDER BY ${ORDEN_PRIORIDAD}, ${ORDEN_SEVERIDAD}, v.primera_vez, v.titulo LIMIT ${limite} OFFSET ${(pagina - 1) * limite}`, params);
      const hoy = P.hoyLocal();
      const kevs = await detalleKev(crudas.filter((f) => Number(f.kev) === 1).flatMap((f) => P.cvesDe(f.cves)));
      const filas = crudas.map((f) => {
        const o = conDerivados(f, hoy);
        if (Number(f.kev) === 1) o.kev_detalle = P.cvesDe(f.cves).map((c) => kevs.get(c)).filter(Boolean);
        return o;
      });
      res.json({ filas, total: Number(total?.n || 0), pagina, limite });
    } catch (e) { fallo(res, e, "listado"); }
  });

  /** Alta a mano (fuente `manual`): lo que no salió de un escáner. Ninguna importación lo cierra solo. */
  app.post("/api/vulnerabilidades", ...mw.editar, async (req, res) => {
    const cliente = clienteO403(req, res); if (!cliente) return;
    const b = req.body || {};
    const titulo = String(b.titulo || "").trim();
    if (!titulo) return res.status(400).json({ error: "La vulnerabilidad necesita un título." });
    if (titulo.length > 500) return res.status(400).json({ error: "El título supera los 500 caracteres." });
    if (b.severidad && !M.SEVERIDADES.includes(b.severidad)) return res.status(400).json({ error: "Severidad inválida." });
    const cvss = b.cvss === "" || b.cvss == null ? null : Number(b.cvss);
    if (cvss != null && (!Number.isFinite(cvss) || cvss < 0 || cvss > 10)) return res.status(400).json({ error: "El CVSS va de 0 a 10." });
    if (b.puerto && !/^\d{1,5}$/.test(String(b.puerto))) return res.status(400).json({ error: "Puerto inválido." });
    try {
      const a = await qRow("SELECT id FROM activos WHERE id = ? AND tenant_id = ? AND eliminado_at IS NULL", [String(b.activo_id || ""), cliente]);
      if (!a) return res.status(400).json({ error: "Elegí un activo del inventario del cliente." });
      const r = await deps.transaccion(async (tx) => {
        const cli = await tx.qRow("SELECT id, NULL AS tenant_id FROM clients WHERE id = ? FOR UPDATE", [cliente]);
        const item = {
          activo_id: a.id, titulo, severidad: b.severidad || "medium", cvss, cvss_vector: null, cves: M.normalizarCves(b.cves),
          cwe: b.cwe ? String(b.cwe).slice(0, 40) : null, puerto: b.puerto ? String(b.puerto) : null,
          protocolo: b.puerto ? String(b.protocolo || "tcp").toLowerCase().slice(0, 10) : null, servicio: null, regla: null,
          descripcion: b.descripcion ? String(b.descripcion).slice(0, 60000) : null, solucion: b.solucion ? String(b.solucion).slice(0, 60000) : null,
          evidencia: null,
        };
        const clave = M.claveDedup(item);
        const ya = await tx.qRow("SELECT id FROM vuln_hallazgos WHERE cliente_id = ? AND clave_dedup = ?", [cliente, clave]);
        if (ya) return { duplicada: ya.id };
        const id = uuidv4();
        const repo = M.repoSQL(tx);
        await repo.insertar({ ...item, id, tenant_id: cli.tenant_id, cliente_id: cliente, fuente: "manual", fuente_ultima: "manual",
          cves: item.cves.length ? item.cves.join(",") : null, clave_dedup: clave, estado: "abierto", created_by: req.user.username });
        if (b.responsable) await repo.actualizar(id, { responsable: String(b.responsable).slice(0, 120) });
        await repo.anotar({ id: uuidv4(), cliente_id: cliente, hallazgo_id: id, estado_antes: null, estado_despues: "abierto",
          evento: "alta_manual", motivo: "Alta manual", automatico: 0, fuente: "manual", usuario: req.user.username });
        await enr.recalcular({ ids: [id], db: tx });
        return { id };
      });
      if (r.duplicada) return res.status(409).json({ error: "Ese activo ya tiene esa vulnerabilidad registrada.", id: r.duplicada });
      enr.completarCliente(cliente);
      auditar(req, "vuln_create", r.id, titulo);
      res.status(201).json(r);
    } catch (e) { fallo(res, e, "alta"); }
  });

  app.get("/api/vulnerabilidades/:id", ...mw.leer, async (req, res) => {
    try {
      const h = await hallazgoO404(req, res, req.params.id); if (!h) return;
      const a = await qRow("SELECT id, nombre, ip, hostname, criticidad FROM activos WHERE id = ?", [h.activo_id]);
      const historial = await qRows(
        `SELECT h.id, h.estado_antes, h.estado_despues, h.evento, h.motivo, h.automatico, h.importacion_id, h.fuente, h.usuario, h.created_at
           FROM vuln_historial h WHERE h.hallazgo_id = ? ORDER BY h.created_at DESC, h.id LIMIT 500`, [h.id]);
      delete h.clave_dedup;
      const cves = P.cvesDe(h.cves);
      const kevs = await detalleKev(cves);
      const epss = new Map();
      for (const t of P.lotes(cves, 500)) {
        if (!t.length) continue;
        for (const e of await qRows(`SELECT cve, epss, percentil, fecha FROM vuln_epss WHERE cve IN (${t.map(() => "?").join(",")})`, t)) epss.set(e.cve, e);
      }
      const cves_detalle = cves.map((c) => {
        const e = epss.get(c);
        return { cve: c, epss: e ? Number(e.epss) : null, percentil: e?.percentil != null ? Number(e.percentil) : null, fecha_epss: P.ymd(e?.fecha), kev: kevs.get(c) || null };
      });
      res.json({ ...conDerivados(h, P.hoyLocal()), plazo_desde: h.plazo_desde || h.primera_vez, activo: a, historial, cves_detalle,
        kev_detalle: cves_detalle.map((c) => c.kev).filter(Boolean) });
    } catch (e) { fallo(res, e, "ficha"); }
  });

  /** Cambio de estado con motivo. Aceptar un riesgo es una decisión de quien conduce, no de quien escanea. */
  app.put("/api/vulnerabilidades/:id/estado", ...mw.editar, async (req, res) => {
    const estado = String(req.body?.estado || "");
    const motivo = String(req.body?.motivo || "").trim();
    if (motivo.length < 3) return res.status(400).json({ error: "Contá el motivo del cambio." });
    if (motivo.length > 1000) return res.status(400).json({ error: "El motivo supera los 1000 caracteres." });
    if (estado === "riesgo_aceptado" && !ROLES_ADMINISTRAR.includes(req.user.role)) {
      return res.status(403).json({ error: "Aceptar un riesgo lo decide un administrador o un auditor." });
    }
    try {
      const h = await hallazgoO404(req, res, req.params.id); if (!h) return;
      const t = M.transicionManual(h.estado, estado);
      if (t.error) return res.status(400).json({ error: t.error });
      await deps.transaccion(async (tx) => {
        const repo = M.repoSQL(tx);
        await repo.actualizar(h.id, t.cambios);
        await repo.anotar({ id: uuidv4(), cliente_id: h.cliente_id, hallazgo_id: h.id, estado_antes: h.estado, estado_despues: estado,
          evento: "manual", motivo, automatico: 0, usuario: req.user.username });
        // Una reapertura reinicia el plazo desde hoy.
        if (t.cambios.plazo_desde) await enr.recalcular({ ids: [h.id], db: tx });
      });
      auditar(req, "vuln_estado", h.id, `${h.estado} -> ${estado}: ${motivo.slice(0, 200)}`);
      res.json({ ok: true, estado });
    } catch (e) { fallo(res, e, "estado"); }
  });

  /** Responsable y notas. El estado va por su ruta, con motivo. */
  app.put("/api/vulnerabilidades/:id", ...mw.editar, async (req, res) => {
    const b = req.body || {};
    try {
      const h = await hallazgoO404(req, res, req.params.id); if (!h) return;
      const cambios = {};
      if ("responsable" in b) cambios.responsable = b.responsable ? String(b.responsable).trim().slice(0, 120) : null;
      if ("notas" in b) cambios.notas = b.notas ? String(b.notas).slice(0, 10000) : null;
      if (!Object.keys(cambios).length) return res.status(400).json({ error: "No hay cambios." });
      await M.repoSQL({ qRow, qRows, qRun }).actualizar(h.id, cambios);
      auditar(req, "vuln_update", h.id, Object.keys(cambios).join(", "));
      res.json({ ok: true });
    } catch (e) { fallo(res, e, "edición"); }
  });

  return { importar: (o) => importar(deps, o), enriquecimiento: enr };
}

/** Para el inventario: al fusionar dos activos, sus vulnerabilidades pasan al que queda. */
function alFusionar({ qRow, qRows, qRun }) {
  return (principalId, absorbidoId) => M.moverDeActivo({ qRow, qRows, qRun }, principalId, absorbidoId);
}

/**
 * Tablas del seguimiento continuo. Van después de las del inventario: cuelgan de `activos`.
 *
 * ⚠️ Las claves foráneas exigen la misma intercalación que la columna destino, y la de `clients`
 * puede venir de una instalación vieja: se copia, como hace el inventario.
 */
async function crearTablas({ qRows, qRun }) {
  const cotejo = async (tabla, col) => {
    const c = (await qRows(
      "SELECT CHARACTER_SET_NAME AS cs, COLLATION_NAME AS co FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?",
      [tabla, col]))[0];
    return c?.cs && c?.co ? ` CHARACTER SET ${c.cs} COLLATE ${c.co}` : "";
  };
  const deCliente = await cotejo("clients", "id");
  const deActivo = await cotejo("activos", "id");

  await qRun(`CREATE TABLE IF NOT EXISTS vuln_hallazgos (
    id                    VARCHAR(36)  PRIMARY KEY,
    tenant_id             VARCHAR(36)  NULL,
    cliente_id            VARCHAR(36)${deCliente} NOT NULL,
    activo_id             VARCHAR(36)${deActivo} NOT NULL,
    -- La fuente que lo trajo primero: es la única que puede cerrarlo por ausencia.
    fuente                VARCHAR(20)  NOT NULL,
    fuente_ultima         VARCHAR(20)  NULL,
    titulo                VARCHAR(500) NOT NULL,
    severidad             VARCHAR(10)  NOT NULL DEFAULT 'medium',
    cvss                  DECIMAL(3,1) NULL,
    cvss_vector           VARCHAR(200) NULL,
    cves                  VARCHAR(2000) NULL,
    cwe                   VARCHAR(40)  NULL,
    puerto                VARCHAR(10)  NULL,
    protocolo             VARCHAR(10)  NULL,
    servicio              VARCHAR(80)  NULL,
    regla                 VARCHAR(200) NULL,
    descripcion           MEDIUMTEXT   NULL,
    solucion              MEDIUMTEXT   NULL,
    evidencia             MEDIUMTEXT   NULL,
    -- sha256 de la fórmula v1 (vulnerabilidades-motor.js). Única por cliente.
    clave_dedup           CHAR(64)     NOT NULL,
    estado                VARCHAR(20)  NOT NULL DEFAULT 'abierto',
    primera_vez           DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ultima_vez            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    fecha_cierre          DATETIME     NULL,
    reaperturas           INT          NOT NULL DEFAULT 0,
    responsable           VARCHAR(120) NULL,
    notas                 TEXT         NULL,
    ultima_importacion_id VARCHAR(36)  NULL,
    -- Etapa 2 (priorización y plazos): se completan cuando llegue EPSS/KEV y el SLA por severidad.
    epss                  DECIMAL(6,5) NULL,
    epss_percentil        DECIMAL(6,5) NULL,
    kev                   TINYINT(1)   NULL,
    fecha_limite          DATE         NULL,
    -- Etapa 3 (conectores y API): el id con que la herramienta conoce al hallazgo.
    externo_id            VARCHAR(191) NULL,
    -- Etapa 4 (pase a engagement): el engagement y el hallazgo del informe que nacieron de este.
    engagement_id         VARCHAR(36)  NULL,
    finding_id            VARCHAR(36)  NULL,
    created_by            VARCHAR(80)  NULL,
    created_at            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_vh_clave (cliente_id, clave_dedup),
    INDEX idx_vh_estado (cliente_id, estado, severidad),
    INDEX idx_vh_cierre (cliente_id, fuente, estado, activo_id),
    INDEX idx_vh_activo (activo_id),
    CONSTRAINT fk_vh_cliente FOREIGN KEY (cliente_id) REFERENCES clients(id) ON DELETE CASCADE,
    CONSTRAINT fk_vh_activo FOREIGN KEY (activo_id) REFERENCES activos(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await qRun(`CREATE TABLE IF NOT EXISTS vuln_importaciones (
    id               VARCHAR(36)  PRIMARY KEY,
    tenant_id        VARCHAR(36)  NULL,
    cliente_id       VARCHAR(36)${deCliente} NOT NULL,
    fuente           VARCHAR(20)  NOT NULL,
    -- manual (archivo subido); etapa 3: conector (programado) o api (CI/CD).
    origen           VARCHAR(20)  NOT NULL DEFAULT 'manual',
    conector_id      VARCHAR(36)  NULL,
    archivo          VARCHAR(255) NULL,
    -- Los activos que el escaneo cubrió: el alcance del cierre por ausencia.
    alcance          JSON         NULL,
    alcance_cantidad INT          NOT NULL DEFAULT 0,
    items            INT          NOT NULL DEFAULT 0,
    nuevos           INT          NOT NULL DEFAULT 0,
    cerrados         INT          NOT NULL DEFAULT 0,
    reabiertos       INT          NOT NULL DEFAULT 0,
    sin_cambios      INT          NOT NULL DEFAULT 0,
    activos_nuevos   INT          NOT NULL DEFAULT 0,
    usuario          VARCHAR(80)  NULL,
    usuario_id       VARCHAR(36)  NULL,
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_vi_cliente (cliente_id, created_at),
    CONSTRAINT fk_vi_cliente FOREIGN KEY (cliente_id) REFERENCES clients(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await qRun(`CREATE TABLE IF NOT EXISTS vuln_historial (
    id              VARCHAR(36)  PRIMARY KEY,
    cliente_id      VARCHAR(36)  NOT NULL,
    hallazgo_id     VARCHAR(36)  NOT NULL,
    estado_antes    VARCHAR(20)  NULL,
    estado_despues  VARCHAR(20)  NULL,
    -- alta, alta_manual, cierre_auto, reapertura, manual
    evento          VARCHAR(20)  NOT NULL,
    motivo          VARCHAR(1000) NULL,
    automatico      TINYINT(1)   NOT NULL DEFAULT 0,
    importacion_id  VARCHAR(36)  NULL,
    fuente          VARCHAR(20)  NULL,
    usuario         VARCHAR(80)  NULL,
    -- Con milésimas: el alta y un cambio a mano en el mismo segundo tienen que salir en orden.
    created_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    INDEX idx_vhi_hallazgo (hallazgo_id, created_at),
    INDEX idx_vhi_importacion (importacion_id),
    CONSTRAINT fk_vhi_hallazgo FOREIGN KEY (hallazgo_id) REFERENCES vuln_hallazgos(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
}

/**
 * Tablas de Community: seguimiento, cachés de KEV y EPSS y plazos por cliente, y la columna `huella`
 * del motor. Sin `vuln_conectores` ni `api_keys.cliente_id` (son de Pro): al pasar a Pro, su arranque
 * las agrega solo y el resto ya está igual.
 */
async function crearTablasCompletas(dep) {
  await crearTablas(dep);
  await E.crearTablas(dep);
  // `huella` la usa el motor en cada importación (en Pro la agrega la etapa de conectores).
  const columnas = new Set((await dep.qRows(
    "SELECT COLUMN_NAME AS c FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vuln_hallazgos'")).map((f) => f.c));
  if (!columnas.has("huella")) await dep.qRun("ALTER TABLE vuln_hallazgos ADD COLUMN huella CHAR(40) NULL");
}

module.exports = { montar, importar, importarItems, registrarImportacion, crearTablas, crearTablasCompletas, alFusionar, resolverActivos, alcanceExtra, claveHost };
