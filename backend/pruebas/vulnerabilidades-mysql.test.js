/**
 * Vulnerabilidades contra un MySQL o MariaDB de verdad: el esquema se crea, la ingesta del inventario
 * reconoce los equipos, el delta sale bien y la transacción deshace todo si algo falla.
 *
 * Solo corre con una base de prueba VACÍA o descartable:
 *
 *   GUNGNIR_PRUEBA_DB=mysql://usuario:clave@127.0.0.1:3306/base_de_prueba npm test
 *
 * Sin la variable se saltea (npm test no necesita base). ⛔ Nunca apuntarla a una base con datos.
 *
 * Portada de Gungnir Pro con la tabla `clients` de Community (sin inquilino) y su adaptador.
 */
"use strict";
const { test, describe, before, after } = require("node:test");
const assert = require("node:assert/strict");
const URL_DB = process.env.GUNGNIR_PRUEBA_DB;

describe("vulnerabilidades contra la base", { skip: !URL_DB && "sin GUNGNIR_PRUEBA_DB" }, () => {
  let pool, deps;
  const sufijo = Date.now().toString(36);
  const CA = `prueba-A-${sufijo}`, CB = `prueba-B-${sufijo}`;

  before(async () => {
    const mysql = require("mysql2/promise");
    pool = mysql.createPool({ uri: URL_DB, connectionLimit: 4, charset: "utf8mb4" });
    const qRows = async (sql, p) => { const [r] = await pool.execute(sql, p || []); return r; };
    const qRow = async (sql, p) => (await qRows(sql, p))[0] || null;
    const qRun = (sql, p) => pool.execute(sql, p || []);
    const transaccion = async (fn) => {
      const con = await pool.getConnection();
      try {
        await con.beginTransaction();
        const r2 = async (sql, p) => { const [r] = await con.execute(sql, p || []); return r; };
        const out = await fn({ qRows: r2, qRow: async (s, p) => (await r2(s, p))[0] || null, qRun: (s, p) => con.execute(s, p || []) });
        await con.commit();
        return out;
      } catch (e) { await con.rollback(); throw e; } finally { con.release(); }
    };
    // Una base vacía no tiene `clients`: se crea la mínima, como la de Community (sin inquilino).
    await qRun(`CREATE TABLE IF NOT EXISTS clients (id VARCHAR(36) PRIMARY KEY, name VARCHAR(200) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
    await qRun("CREATE TABLE IF NOT EXISTS settings (`key` VARCHAR(191) PRIMARY KEY, `value` MEDIUMTEXT) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    await require("../inventario-community").prepararEsquema({ qRows, qRun });
    await require("../vulnerabilidades").crearTablasCompletas({ qRows, qRun });
    // Dos veces: el esquema es idempotente (también las columnas e índices que agrega la etapa 2).
    await require("../inventario-community").prepararEsquema({ qRows, qRun });
    await require("../vulnerabilidades").crearTablasCompletas({ qRows, qRun });
    await qRun("INSERT INTO clients (id, name) VALUES (?,?), (?,?)", [CA, "Cliente A", CB, "Cliente B"]);
    deps = { qRow, qRows, qRun, transaccion };
  });

  after(async () => {
    if (!pool) return;
    // El borrado del cliente arrastra activos, vulnerabilidades, historial e importaciones.
    await pool.execute("DELETE FROM clients WHERE id IN (?,?)", [CA, CB]);
    await pool.execute("DELETE FROM vuln_kev WHERE cve LIKE 'CVE-2099-%' OR cve = 'CVE-2023-38408'");
    await pool.execute("DELETE FROM vuln_epss WHERE cve = 'CVE-2023-38408'");
    await pool.end();
  });

  const { importar } = require("../vulnerabilidades");
  const resultado = (host, nombre, oid, cve, puerto = "22/tcp", score = "7.5") =>
    `<result id="${oid}"><name>${nombre}</name><host>${host}</host><port>${puerto}</port><nvt oid="${oid}"><refs>${cve ? `<ref type="cve" id="${cve}"/>` : ""}</refs></nvt><severity>${score}</severity><description>d</description></result>`;
  const informe = (resultados, hosts) => `<report><results>${resultados.join("")}</results>${hosts.map((h) => `<host><ip>${h}</ip></host>`).join("")}</report>`;

  const X1 = informe([
    resultado("10.9.0.1", "OpenSSH obsoleto", "oid.1", "CVE-2023-38408"),
    resultado("10.9.0.1", "TLS 1.0 habilitado", "oid.2", null, "443/tcp", "5.0"),
    resultado("10.9.0.2", "SMB firmado deshabilitado", "oid.3", null, "445/tcp", "5.0"),
  ], ["10.9.0.1", "10.9.0.2", "10.9.0.3"]);
  const X2 = informe([resultado("10.9.0.1", "OpenSSH obsoleto", "oid.1", "CVE-2023-38408")], ["10.9.0.1"]);
  const imp = (cliente, xml, fuente = "openvas", extra = []) => importar(deps, { cliente, fuente, xml, extra, usuario: "prueba" });
  const estados = async (cliente) => Object.fromEntries((await deps.qRows(
    "SELECT v.titulo, v.estado, v.reaperturas FROM vuln_hallazgos v WHERE v.cliente_id = ?", [cliente])).map((f) => [f.titulo, `${f.estado}/${f.reaperturas}`]));

  test("primera importación: crea los equipos por la ingesta del inventario y todo es nuevo", async () => {
    const r = await imp(CA, X1);
    assert.equal(r.error, undefined, r.error);
    assert.equal(r.nuevos, 3); assert.equal(r.cerrados, 0);
    assert.equal(r.activos_nuevos, 3, "el equipo limpio 10.9.0.3 también entra al inventario");
    assert.equal(r.alcance, 3);
    const activos = await deps.qRows("SELECT ip, origen FROM activos WHERE tenant_id = ? ORDER BY ip", [CA]);
    assert.deepEqual(activos.map((a) => a.ip), ["10.9.0.1", "10.9.0.2", "10.9.0.3"]);
    assert.equal(activos[0].origen, "escaneo");
  });

  test("reimportar con alcance parcial: cierra solo dentro del alcance", async () => {
    const r = await imp(CA, X2);
    assert.deepEqual([r.nuevos, r.cerrados, r.reabiertos, r.sin_cambios, r.activos_nuevos], [0, 1, 0, 1, 0]);
    assert.deepEqual(await estados(CA), {
      "OpenSSH obsoleto": "abierto/0", "TLS 1.0 habilitado": "remediado/0", "SMB firmado deshabilitado": "abierto/0",
    });
    const h = await deps.qRow(
      `SELECT h.motivo, h.evento FROM vuln_historial h JOIN vuln_hallazgos v ON v.id = h.hallazgo_id
        WHERE v.cliente_id = ? AND v.titulo = 'TLS 1.0 habilitado' AND h.evento = 'cierre_auto'`, [CA]);
    assert.match(h.motivo, /^Cerrado: no apareció en la importación [0-9A-F]{8} de OpenVAS$/);
  });

  test("🔴 el mismo escaneo en otro cliente crea sus propios equipos y no toca al primero", async () => {
    const r = await imp(CB, X2);
    assert.equal(r.nuevos, 1); assert.equal(r.activos_nuevos, 1);
    const antes = await estados(CA);
    await imp(CB, informe([], ["10.9.0.1"]));         // CB queda limpio
    assert.deepEqual(await estados(CB), { "OpenSSH obsoleto": "remediado/0" });
    assert.deepEqual(await estados(CA), antes, "la importación de B cambió lo de A");
  });

  test("lo remediado que vuelve se reabre", async () => {
    const r = await imp(CA, X1);
    assert.deepEqual([r.nuevos, r.reabiertos, r.sin_cambios], [0, 1, 2]);
    assert.equal((await estados(CA))["TLS 1.0 habilitado"], "reabierto/1");
  });

  test("otra herramienta con el mismo CVE en el mismo puerto no duplica, ni el equipo ni la vulnerabilidad", async () => {
    const nessus = `<NessusClientData_v2><Report><ReportHost name="10.9.0.1"><ReportItem port="22" protocol="tcp" severity="3" pluginID="178910" pluginName="OpenSSH &lt; 9.3p2 RCE"><description>d</description><cve>CVE-2023-38408</cve></ReportItem></ReportHost></Report></NessusClientData_v2>`;
    const r = await imp(CA, nessus, "nessus");
    assert.deepEqual([r.nuevos, r.sin_cambios, r.cerrados, r.activos_nuevos], [0, 1, 0, 0]);
    const f = await deps.qRow("SELECT fuente, fuente_ultima FROM vuln_hallazgos WHERE cliente_id = ? AND cves = 'CVE-2023-38408'", [CA]);
    assert.deepEqual({ ...f }, { fuente: "openvas", fuente_ultima: "nessus" });
  });

  test("riesgo aceptado no se cierra por ausencia", async () => {
    await deps.qRun("UPDATE vuln_hallazgos SET estado = 'riesgo_aceptado' WHERE cliente_id = ? AND titulo = 'SMB firmado deshabilitado'", [CA]);
    const r = await imp(CA, informe([], ["10.9.0.2"]));
    assert.equal(r.cerrados, 0);
    assert.equal((await estados(CA))["SMB firmado deshabilitado"], "riesgo_aceptado/0");
  });

  test("alcance agregado a mano: un equipo que el archivo no nombra también cuenta (si existe)", async () => {
    const r = await imp(CA, informe([], ["10.9.0.3"]), "openvas", ["10.9.0.1", "no-existe.local"]);
    assert.equal(r.cerrados, 2, "no cerró lo de 10.9.0.1");
    assert.deepEqual(r.alcance_no_reconocido, ["no-existe.local"]);
    const n = await deps.qRow("SELECT COUNT(*) AS n FROM activos WHERE tenant_id = ? AND nombre = 'no-existe.local'", [CA]);
    assert.equal(Number(n.n), 0, "un nombre tipeado creó un equipo");
  });

  test("🔑 si algo falla a mitad de camino, no queda nada a medias", async () => {
    const contar = async () => Number((await deps.qRow("SELECT (SELECT COUNT(*) FROM vuln_hallazgos WHERE cliente_id = ?) + (SELECT COUNT(*) FROM activos WHERE tenant_id = ?) AS n", [CA, CA])).n);
    const antes = await contar();
    const rota = { ...deps, transaccion: (fn) => deps.transaccion(async (tx) => { await fn(tx); throw new Error("falla simulada"); }) };
    await assert.rejects(importar(rota, { cliente: CA, fuente: "openvas", xml: informe([resultado("10.9.0.77", "Nueva", "oid.77", null)], ["10.9.0.77"]), usuario: "prueba" }), /falla simulada/);
    assert.equal(await contar(), antes);
  });

  test("la importación queda registrada con su delta", async () => {
    const filas = await deps.qRows("SELECT fuente, nuevos, cerrados, reabiertos, sin_cambios, alcance_cantidad, alcance FROM vuln_importaciones WHERE cliente_id = ? ORDER BY created_at, id", [CA]);
    assert.ok(filas.length >= 5);
    const primera = filas.find((f) => f.nuevos === 3);
    assert.equal(primera.alcance_cantidad, 3);
    const alc = typeof primera.alcance === "string" ? JSON.parse(primera.alcance) : primera.alcance;
    assert.equal(alc.length, 3);
  });

  test("al fusionar dos activos, las vulnerabilidades pasan al que queda (y se unen si coinciden)", async () => {
    const M = require("../vulnerabilidades-motor");
    const [a1] = await deps.qRows("SELECT id FROM activos WHERE tenant_id = ? AND ip = '10.9.0.1'", [CA]);
    const [a3] = await deps.qRows("SELECT id FROM activos WHERE tenant_id = ? AND ip = '10.9.0.3'", [CA]);
    const antes = Number((await deps.qRow("SELECT COUNT(*) AS n FROM vuln_hallazgos WHERE activo_id = ?", [a1.id])).n);
    const r = await M.moverDeActivo(deps, a3.id, a1.id);
    assert.equal(r.vulnerabilidades, antes);
    assert.equal(Number((await deps.qRow("SELECT COUNT(*) AS n FROM vuln_hallazgos WHERE activo_id = ?", [a3.id])).n), antes);
  });
  // ── Etapa 2: prioridad, plazos y métricas contra la base ──────────────────────────────────
  test("etapa 2: el recálculo toma KEV y EPSS de las cachés y fija prioridad y plazo", async () => {
    const E = require("../vulnerabilidades-enriquecimiento");
    const P = require("../vulnerabilidades-prioridad");
    await deps.qRun("INSERT INTO vuln_kev (cve, nombre, alta, vence, ransomware) VALUES ('CVE-2023-38408', 'OpenSSH PKCS#11', '2026-10-01', '2026-10-22', 1)");
    await deps.qRun("INSERT INTO vuln_epss (cve, epss, percentil, fecha) VALUES ('CVE-2023-38408', 0.797, 0.99606, '2026-11-02')");
    const enr = E.crear({ ...deps, log: { log() {}, error() {} } });
    const r = await enr.recalcular({ cliente: CA });
    assert.ok(r.cambiados >= 1);
    const h = await deps.qRow("SELECT * FROM vuln_hallazgos WHERE cliente_id = ? AND cves = 'CVE-2023-38408'", [CA]);
    assert.equal(h.prioridad, "urgente"); assert.equal(Number(h.kev), 1); assert.equal(Number(h.kev_ransomware), 1);
    assert.equal(Number(h.epss), 0.797); assert.ok(h.kev_desde);
    const desde = P.ymd(h.plazo_desde || h.primera_vez);
    assert.equal(P.ymd(h.fecha_limite), P.fechaLimite({ desde, severidad: h.severidad, politica: P.POLITICA_DEFECTO, kev: 1, kev_vence: "2026-10-22" }));
    const sinCve = await deps.qRow("SELECT prioridad, kev FROM vuln_hallazgos WHERE cliente_id = ? AND titulo = 'SMB firmado deshabilitado'", [CA]);
    assert.equal(Number(sinCve.kev), 0); assert.ok(sinCve.prioridad);
    assert.equal((await enr.recalcular({ cliente: CA })).cambiados, 0, "un segundo recálculo no cambia nada");
  });

  test("etapa 2: rutas de métricas, listado con filtros y plazos por cliente con SQL de verdad", async () => {
    const { appFalsa, invocar: inv, authFalsa } = require("./arnes");
    const app = appFalsa();
    require("../vulnerabilidades").montar(app, { auth: authFalsa(), auditLog: () => {}, ...deps });
    const invocar = async (...a) => { const r = await inv(...a); for (let i = 0; i < 500 && !r.res.terminado; i++) await new Promise((ok) => setTimeout(ok, 2)); return r; };
    const staff = { id: "s", username: "s", role: "admin" };
    // Quedó remediada en las pruebas de arriba: reabrirla a mano reinicia el plazo desde hoy.
    const P = require("../vulnerabilidades-prioridad");
    const ssh = await deps.qRow("SELECT id, estado FROM vuln_hallazgos WHERE cliente_id = ? AND cves = 'CVE-2023-38408'", [CA]);
    assert.equal(ssh.estado, "remediado");
    const re = await invocar(app, "put", "/api/vulnerabilidades/:id/estado", { user: staff, params: { id: ssh.id }, body: { estado: "abierto", motivo: "volvió a aparecer" } });
    assert.equal(re.res.statusCode, 200, JSON.stringify(re.res.cuerpo));
    const tras = await deps.qRow("SELECT plazo_desde, fecha_limite FROM vuln_hallazgos WHERE id = ?", [ssh.id]);
    assert.equal(P.ymd(tras.plazo_desde), P.hoyLocal());
    assert.equal(P.ymd(tras.fecha_limite), P.sumarDias(P.hoyLocal(), 15), "KEV con dueDate pasado: 15 días desde la reapertura");
    const m = await invocar(app, "get", "/api/vulnerabilidades/metricas", { user: staff, query: { cliente: CA } });
    assert.equal(m.res.statusCode, 200, JSON.stringify(m.res.cuerpo));
    assert.equal(m.res.cuerpo.en_kev, 1);
    assert.equal(m.res.cuerpo.tendencia.length, 12);
    assert.ok(m.res.cuerpo.tendencia[11].abiertas >= 1);
    const l = await invocar(app, "get", "/api/vulnerabilidades", { user: staff, query: { cliente: CA, estado: "abiertas", kev: "1", prioridad: "urgente" } });
    assert.equal(l.res.statusCode, 200, JSON.stringify(l.res.cuerpo));
    assert.equal(l.res.cuerpo.filas.length, 1);
    assert.match(l.res.cuerpo.filas[0].fecha_limite, /^\d{4}-\d{2}-\d{2}$/);
    assert.equal(l.res.cuerpo.filas[0].kev_detalle[0].ransomware, true);
    for (const plazo of ["vencida", "por_vencer", "en_plazo"]) {
      const x = await invocar(app, "get", "/api/vulnerabilidades", { user: staff, query: { cliente: CA, plazo } });
      assert.equal(x.res.statusCode, 200, plazo);
    }
    const put = await invocar(app, "put", "/api/vulnerabilidades/plazos", { user: staff, query: { cliente: CA }, body: { politica: { critical: 2, high: 3, medium: 4, low: 5, info: null } } });
    assert.equal(put.res.statusCode, 200, JSON.stringify(put.res.cuerpo));
    const g = await invocar(app, "get", "/api/vulnerabilidades/plazos", { user: staff, query: { cliente: CA } });
    assert.deepEqual(g.res.cuerpo.cliente, { critical: 2, high: 3, medium: 4, low: 5, info: null });
    const del = await invocar(app, "delete", "/api/vulnerabilidades/plazos", { user: staff, query: { cliente: CA } });
    assert.equal(del.res.statusCode, 200);
    const ficha = await deps.qRow("SELECT id FROM vuln_hallazgos WHERE cliente_id = ? AND cves = 'CVE-2023-38408'", [CA]);
    const f = await invocar(app, "get", "/api/vulnerabilidades/:id", { user: staff, params: { id: ficha.id } });
    assert.equal(f.res.statusCode, 200);
    assert.equal(f.res.cuerpo.cves_detalle[0].epss, 0.797);
  });
});
