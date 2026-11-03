/**
 * Vulnerabilidades (seguimiento continuo): deduplicación, cierre solo dentro del alcance y de la
 * misma fuente, reapertura, decisiones de una persona que no se tocan, delta y aislamiento.
 *
 * No necesita base: el motor trabaja contra un repositorio en memoria y las rutas contra el arnés.
 * La prueba contra MySQL de verdad está en vulnerabilidades-mysql.test.js.
 *
 * Portadas de Gungnir Pro. El motor y los parsers son los mismos (y tienen que dar las mismas claves);
 * las rutas cambian: Community es de una sola organización, así que no hay aislamiento entre
 * inquilinos sino entre clientes de la instalación, y el administrador es el staff.
 */
"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const M = require("../vulnerabilidades-motor");
const esc = require("../importacion-escaneres");
const { appFalsa, invocar, authFalsa } = require("./arnes");

// ── Repositorio en memoria con la misma interfaz que repoSQL ──────────────────────────────────
function repoMemoria() {
  const filas = [], historial = [];
  return {
    filas, historial,
    async porClaves(cliente, claves) {
      return new Map(filas.filter((f) => f.cliente_id === cliente && claves.includes(f.clave_dedup)).map((f) => [f.clave_dedup, f]));
    },
    async abiertosEnAlcance(cliente, fuente, activos) {
      return filas.filter((f) => f.cliente_id === cliente && f.fuente === fuente && M.ABIERTOS.includes(f.estado) && activos.includes(f.activo_id));
    },
    async insertar(h) { filas.push({ ...h, reaperturas: 0, fecha_cierre: null, vista: 1 }); },
    async actualizar(id, cambios) {
      const f = filas.find((x) => x.id === id);
      for (const [k, v] of Object.entries(cambios)) f[k] = v === "+1" ? f[k] + 1 : v;
      if (cambios.ultima_vez) f.vista++;
    },
    async anotar(e) { historial.push(e); },
  };
}

let n = 0;
const nuevoId = () => `id-${++n}`;
const item = (activo_id, extra = {}) => ({
  activo_id, titulo: "OpenSSH obsoleto", severidad: "high", cvss: 7.5, cvss_vector: null, cves: [], cwe: null,
  puerto: "22", protocolo: "tcp", servicio: "ssh", regla: null, descripcion: "d", solucion: "s", evidencia: null, ...extra,
});
const importacion = (codigo = "IMP1") => ({ id: `imp-${codigo}`, codigo });
const aplicar = (repo, o) => M.aplicar(repo, { cliente: "C1", fuente: "openvas", nuevoId, usuario: "pen", importacion: importacion(), ...o });
const de = (repo, titulo) => repo.filas.find((f) => f.titulo === titulo);

describe("clave de deduplicación", () => {
  const base = { activo_id: "A1", puerto: "443", protocolo: "tcp", cves: ["CVE-2021-44228"], regla: "nessus:1", titulo: "Log4Shell" };

  test("es estable: mismos datos, misma clave, y es un sha256", () => {
    assert.equal(M.claveDedup(base), M.claveDedup({ ...base }));
    assert.match(M.claveDedup(base), /^[0-9a-f]{64}$/);
  });

  test("🔑 no depende de la fuente: el mismo CVE en el mismo puerto visto por dos herramientas es uno", () => {
    const nessus = { ...base, regla: "nessus:155999", titulo: "Apache Log4j < 2.15.0 RCE" };
    const openvas = { ...base, regla: "openvas:1.3.6.1.4.1.25623.1.0.117842", titulo: "Apache Log4j Remote Code Execution (Log4Shell)" };
    assert.equal(M.claveDedup(nessus), M.claveDedup(openvas));
  });

  test("los CVE no dependen del orden, las mayúsculas ni los repetidos", () => {
    const a = M.claveDedup({ ...base, cves: ["CVE-2020-1", "cve-2019-11111", "CVE-2020-1"] });
    assert.equal(a, M.claveDedup({ ...base, cves: "cve-2019-11111, CVE-2020-1" }));
  });

  test("sin CVE manda la regla de la herramienta; el título no cambia la clave", () => {
    const r = { ...base, cves: [] };
    assert.equal(M.claveDedup({ ...r, titulo: "OpenSSH 8.9 detectado" }), M.claveDedup({ ...r, titulo: "OpenSSH 9.6 detectado" }));
    assert.notEqual(M.claveDedup({ ...r, regla: "nessus:1" }), M.claveDedup({ ...r, regla: "zap:1" }), "plugins de dos herramientas con el mismo número no son lo mismo");
  });

  test("sin CVE ni regla, el título normalizado (acentos, mayúsculas, signos)", () => {
    const t = { ...base, cves: [], regla: "" };
    assert.equal(M.claveDedup({ ...t, titulo: "Cifrado  DÉBIL: TLS 1.0!" }), M.claveDedup({ ...t, titulo: "cifrado debil tls 1 0" }));
  });

  test("el activo y el puerto sí la cambian", () => {
    assert.notEqual(M.claveDedup(base), M.claveDedup({ ...base, activo_id: "A2" }));
    assert.notEqual(M.claveDedup(base), M.claveDedup({ ...base, puerto: "8443" }));
    assert.notEqual(M.claveDedup(base), M.claveDedup({ ...base, protocolo: "udp" }));
    assert.equal(M.claveDedup({ ...base, puerto: "0" }), M.claveDedup({ ...base, puerto: "" }), "puerto 0 es sin puerto");
  });
});

describe("importación: delta, cierre y reapertura", () => {
  test("primera importación: todo es nuevo y queda en el historial", async () => {
    const repo = repoMemoria();
    const d = await aplicar(repo, { items: [item("A1"), item("A2", { titulo: "SMB v1", puerto: "445", regla: "openvas:9" })], alcance: ["A1", "A2"] });
    assert.deepEqual({ ...d }, { nuevos: 2, cerrados: 0, reabiertos: 0, sin_cambios: 0, decisiones_mantenidas: 0, total: 2,
      nuevas_por_severidad: { critical: 0, high: 2, medium: 0, low: 0, info: 0 } });
    assert.equal(repo.filas.every((f) => f.estado === "abierto"), true);
    assert.equal(repo.historial.filter((h) => h.evento === "alta").length, 2);
  });

  test("reimportar lo mismo no duplica: todo sin cambios", async () => {
    const repo = repoMemoria();
    await aplicar(repo, { items: [item("A1")], alcance: ["A1"] });
    const d = await aplicar(repo, { items: [item("A1", { severidad: "critical" })], alcance: ["A1"], importacion: importacion("IMP2") });
    assert.equal(d.nuevos, 0); assert.equal(d.sin_cambios, 1);
    assert.equal(repo.filas.length, 1);
    assert.equal(repo.filas[0].severidad, "critical", "los datos del escáner se refrescan");
  });

  test("lo repetido dentro del mismo archivo es uno, con la severidad más alta", async () => {
    const repo = repoMemoria();
    const d = await aplicar(repo, { items: [item("A1", { severidad: "low" }), item("A1", { severidad: "critical" })], alcance: ["A1"] });
    assert.equal(d.nuevos, 1); assert.equal(repo.filas[0].severidad, "critical");
  });

  test("🔑 se cierra lo que no apareció si su activo estaba en el alcance y es de la misma fuente", async () => {
    const repo = repoMemoria();
    await aplicar(repo, { items: [item("A1"), item("A1", { titulo: "TLS 1.0", puerto: "443", regla: "openvas:7" })], alcance: ["A1"] });
    const d = await aplicar(repo, { items: [item("A1")], alcance: ["A1"], importacion: importacion("IMP2") });
    assert.equal(d.cerrados, 1); assert.equal(d.sin_cambios, 1);
    const tls = de(repo, "TLS 1.0");
    assert.equal(tls.estado, "remediado"); assert.equal(tls.fecha_cierre, "ahora");
    const h = repo.historial.find((x) => x.hallazgo_id === tls.id && x.evento === "cierre_auto");
    assert.match(h.motivo, /^Cerrado: no apareció en la importación IMP2 de OpenVAS/);
    assert.equal(h.importacion_id, "imp-IMP2");
  });

  test("🔴 un activo fuera del alcance de la importación no cierra nada", async () => {
    const repo = repoMemoria();
    await aplicar(repo, { items: [item("A1"), item("A2")], alcance: ["A1", "A2"] });
    const d = await aplicar(repo, { items: [item("A1")], alcance: ["A1"], importacion: importacion("IMP2") });
    assert.equal(d.cerrados, 0, "el escaneo de la red A cerró lo de la red B");
    assert.equal(repo.filas.find((f) => f.activo_id === "A2").estado, "abierto");
  });

  test("🔴 otra fuente no cierra lo que encontró una herramienta distinta", async () => {
    const repo = repoMemoria();
    await aplicar(repo, { items: [item("A1")], alcance: ["A1"] });                       // openvas
    const d = await aplicar(repo, { fuente: "nmap", items: [], alcance: ["A1"], importacion: importacion("IMP2") });
    assert.equal(d.cerrados, 0, "un Nmap cerró lo de un OpenVAS");
    assert.equal(repo.filas[0].estado, "abierto");
  });

  test("un activo en el alcance sin ningún hallazgo cierra todo lo suyo (salió limpio)", async () => {
    const repo = repoMemoria();
    await aplicar(repo, { items: [item("A1"), item("A1", { titulo: "x", regla: "openvas:2" })], alcance: ["A1"] });
    const d = await aplicar(repo, { items: [], alcance: ["A1"], importacion: importacion("IMP2") });
    assert.equal(d.cerrados, 2);
  });

  test("🔑 lo remediado que vuelve a aparecer se reabre y suma una reapertura", async () => {
    const repo = repoMemoria();
    await aplicar(repo, { items: [item("A1")], alcance: ["A1"] });
    await aplicar(repo, { items: [], alcance: ["A1"], importacion: importacion("IMP2") });
    assert.equal(repo.filas[0].estado, "remediado");
    const d = await aplicar(repo, { items: [item("A1")], alcance: ["A1"], importacion: importacion("IMP3") });
    assert.equal(d.reabiertos, 1); assert.equal(d.nuevos, 0);
    assert.equal(repo.filas[0].estado, "reabierto"); assert.equal(repo.filas[0].reaperturas, 1);
    assert.equal(repo.filas[0].fecha_cierre, null);
    assert.match(repo.historial.at(-1).motivo, /^Reabierto: volvió a aparecer en la importación IMP3/);
    // Y si se vuelve a ir y a volver, cuenta otra vez.
    await aplicar(repo, { items: [], alcance: ["A1"], importacion: importacion("IMP4") });
    await aplicar(repo, { items: [item("A1")], alcance: ["A1"], importacion: importacion("IMP5") });
    assert.equal(repo.filas[0].reaperturas, 2);
  });

  test("lo reabierto cuenta como abierto: si desaparece de nuevo se cierra", async () => {
    const repo = repoMemoria();
    await aplicar(repo, { items: [item("A1")], alcance: ["A1"] });
    await aplicar(repo, { items: [], alcance: ["A1"] });
    await aplicar(repo, { items: [item("A1")], alcance: ["A1"] });
    const d = await aplicar(repo, { items: [], alcance: ["A1"] });
    assert.equal(d.cerrados, 1); assert.equal(repo.filas[0].estado, "remediado");
  });

  for (const decision of ["riesgo_aceptado", "falso_positivo"]) {
    test(`🔑 ${decision} no se cierra por ausencia ni se reabre: solo se anota que se vio`, async () => {
      const repo = repoMemoria();
      await aplicar(repo, { items: [item("A1")], alcance: ["A1"] });
      repo.filas[0].estado = decision;
      const ausente = await aplicar(repo, { items: [], alcance: ["A1"] });
      assert.equal(ausente.cerrados, 0); assert.equal(repo.filas[0].estado, decision);
      const vistas = repo.filas[0].vista;
      const presente = await aplicar(repo, { items: [item("A1")], alcance: ["A1"] });
      assert.equal(presente.reabiertos, 0); assert.equal(presente.decisiones_mantenidas, 1);
      assert.equal(repo.filas[0].estado, decision);
      assert.equal(repo.filas[0].vista, vistas + 1, "no se actualizó la última vez visto");
    });
  }

  test("🔴 aislamiento: la importación de un cliente no toca lo de otro con el mismo activo y la misma clave", async () => {
    const repo = repoMemoria();
    await aplicar(repo, { cliente: "C1", items: [item("A1")], alcance: ["A1"] });
    await aplicar(repo, { cliente: "C2", items: [item("A1")], alcance: ["A1"] });
    assert.equal(repo.filas.length, 2, "se unió con la vulnerabilidad de otro cliente");
    const d = await aplicar(repo, { cliente: "C2", items: [], alcance: ["A1"] });
    assert.equal(d.cerrados, 1);
    assert.equal(repo.filas.find((f) => f.cliente_id === "C1").estado, "abierto", "cerró la de otro cliente");
  });

  test("delta completo en una sola importación", async () => {
    const repo = repoMemoria();
    await aplicar(repo, { items: [item("A1", { titulo: "a", regla: "r:a" }), item("A1", { titulo: "b", regla: "r:b" }), item("A1", { titulo: "c", regla: "r:c" })], alcance: ["A1"] });
    await aplicar(repo, { items: [item("A1", { titulo: "a", regla: "r:a" }), item("A1", { titulo: "b", regla: "r:b" })], alcance: ["A1"] });  // cierra c
    de(repo, "b").estado = "falso_positivo";
    const d = await aplicar(repo, { items: [item("A1", { titulo: "b", regla: "r:b" }), item("A1", { titulo: "c", regla: "r:c" }), item("A1", { titulo: "d", regla: "r:d" })], alcance: ["A1"] });
    // a se cierra, b sigue falso positivo, c se reabre, d es nueva
    // Nuevas por severidad cuenta las nuevas y las reabiertas (lo que mira un pipeline para cortar).
    assert.deepEqual({ ...d }, { nuevos: 1, cerrados: 1, reabiertos: 1, sin_cambios: 1, decisiones_mantenidas: 1, total: 3,
      nuevas_por_severidad: { critical: 0, high: 2, medium: 0, low: 0, info: 0 } });
  });
});

describe("cambio de estado a mano", () => {
  test("reabrir algo remediado cuenta como reapertura y saca la fecha de cierre", () => {
    assert.deepEqual(M.transicionManual("remediado", "abierto").cambios, { estado: "abierto", fecha_cierre: null, reaperturas: "+1", plazo_desde: "ahora" });
  });
  test("cerrar fecha el cierre; reabierto solo lo pone una importación", () => {
    assert.equal(M.transicionManual("abierto", "falso_positivo").cambios.fecha_cierre, "ahora");
    assert.ok(M.transicionManual("remediado", "reabierto").error);
    assert.ok(M.transicionManual("abierto", "abierto").error);
  });
});

describe("parsers: lo que necesita el seguimiento continuo", () => {
  test("Nessus: IP y nombre del host, puerto, plugin y CVE", () => {
    const xml = `<NessusClientData_v2><Report><ReportHost name="10.0.0.5"><HostProperties><tag name="host-ip">10.0.0.5</tag><tag name="host-fqdn">srv01.corp.local</tag></HostProperties>
      <ReportItem port="443" svc_name="www" protocol="tcp" severity="4" pluginID="155999" pluginName="Apache Log4j RCE"><description>d</description><solution>s</solution><cve>CVE-2021-44228</cve><cve>CVE-2021-45046</cve><cvss3_base_score>10.0</cvss3_base_score></ReportItem>
      </ReportHost><ReportHost name="10.0.0.6"><ReportItem port="0" protocol="tcp" severity="1" pluginID="1" pluginName="Info"><description>x</description></ReportItem></ReportHost></Report></NessusClientData_v2>`;
    const f = esc.parseNessus(xml).map(M.desdeParser);
    assert.deepEqual(f[0].host, { ip: "10.0.0.5", hostname: "srv01.corp.local" });
    assert.equal(f[0].puerto, "443"); assert.equal(f[0].protocolo, "tcp"); assert.equal(f[0].regla, "nessus:155999");
    assert.deepEqual(f[0].cves, ["CVE-2021-44228", "CVE-2021-45046"]); assert.equal(f[0].cvss, 10); assert.equal(f[0].severidad, "critical");
    assert.deepEqual(f[1].host, { ip: "10.0.0.6", hostname: "" }); assert.equal(f[1].puerto, null);
    assert.deepEqual(esc.hostsEscaneados("nessus", xml).map((h) => h.ip), ["10.0.0.5", "10.0.0.6"]);
  });

  test("OpenVAS: host, puerto, OID y CVE; y los equipos escaneados aunque no tengan resultados", () => {
    const xml = `<report><results><result id="r1"><name>OpenSSH obsoleto</name><host>192.168.1.10<asset asset_id="x"/><hostname>srv02</hostname></host>
      <port>22/tcp</port><nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>OpenSSH</name><refs><ref type="cve" id="CVE-2023-38408"/><ref type="url" id="http://x"/></refs></nvt>
      <severity>9.8</severity><description>d</description></result></results>
      <host><ip>192.168.1.10</ip></host><host><ip>192.168.1.11</ip></host></report>`;
    const [f] = esc.parseOpenVAS(xml).map(M.desdeParser);
    assert.deepEqual(f.host, { ip: "192.168.1.10", hostname: "srv02" });
    assert.equal(f.puerto, "22"); assert.equal(f.regla, "openvas:1.3.6.1.4.1.25623.1.0.1"); assert.deepEqual(f.cves, ["CVE-2023-38408"]);
    assert.deepEqual(esc.hostsEscaneados("openvas", xml).map((h) => h.ip).sort(), ["192.168.1.10", "192.168.1.11"]);
  });

  test("Nmap: un puerto abierto se sigue por puerto, no por la versión del servicio", () => {
    const xml = (v) => `<nmaprun><host><status state="up"/><address addr="10.1.1.1" addrtype="ipv4"/><ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="${v}"/></port></ports></host>
      <host><status state="up"/><address addr="10.1.1.2" addrtype="ipv4"/></host></nmaprun>`;
    const a = M.desdeParser(esc.parseNmap(xml("8.9"))[0]), b = M.desdeParser(esc.parseNmap(xml("9.6"))[0]);
    assert.notEqual(a.titulo, b.titulo);
    assert.equal(M.claveDedup({ ...a, activo_id: "X" }), M.claveDedup({ ...b, activo_id: "X" }));
    assert.deepEqual(esc.hostsEscaneados("nmap", xml("8.9")).map((h) => h.ip), ["10.1.1.1", "10.1.1.2"], "el equipo sin puertos abiertos también está en el alcance");
  });

  test("ZAP: el sitio, el puerto por esquema y el plugin", () => {
    const xml = `<OWASPZAPReport><site name="https://app.cliente.com" host="app.cliente.com" port="443" ssl="true"><alerts><alertitem><pluginid>10020</pluginid><alert>Falta X-Frame-Options</alert><riskcode>2</riskcode><desc>d</desc><instances><instance><uri>https://app.cliente.com/login</uri></instance></instances><uri>https://app.cliente.com/login</uri></alertitem></alerts></site></OWASPZAPReport>`;
    const [f] = esc.parseZAP(xml).map(M.desdeParser);
    assert.deepEqual(f.host, { ip: "", hostname: "app.cliente.com" }); assert.equal(f.puerto, "443"); assert.equal(f.regla, "zap:10020");
  });

  test("la importación a un engagement sigue igual (los campos nuevos van con guion bajo)", () => {
    const xml = `<report><results><result id="r1"><name>N</name><host>1.2.3.4</host><port>80/tcp</port><severity>5.0</severity></result></results></report>`;
    const [f] = esc.parseOpenVAS(xml);
    assert.equal(f.affected_asset, "1.2.3.4:80/tcp");
    assert.ok(Object.keys(f).filter((k) => !k.startsWith("_")).every((k) => ["title", "severity", "affected_asset", "description", "steps_to_reproduce", "recommendation", "cvss_vector_31", "cvss_score_31", "cwe_id", "owasp_category"].includes(k)));
  });
});

// ── Rutas: alcance por cliente y permisos ───────────────────────────────────────────────────
// Community no tiene inquilinos: los clientes de la instalación los ve cualquiera con sesión (como
// el listado de clientes). Lo que se prueba es que cada consulta vaya acotada al cliente pedido, que
// un cliente que no existe no abra nada y los permisos por rol.
describe("rutas: alcance por cliente y permisos (Community)", () => {
  const CLIENTES = [{ id: "CA" }, { id: "CB" }];
  // VX cuelga de un cliente que ya no está en la instalación.
  const HALLAZGOS = [{ id: "VB", cliente_id: "CB", activo_id: "AB", estado: "abierto" }, { id: "VA", cliente_id: "CA", activo_id: "AA", estado: "abierto" },
    { id: "VX", cliente_id: "CX", activo_id: "AX", estado: "abierto" }];
  const consultas = [];
  const qRows = async (sql, p = []) => {
    consultas.push({ sql, p });
    if (/FROM clients/.test(sql)) return CLIENTES;
    return [];
  };
  const qRow = async (sql, p = []) => {
    consultas.push({ sql, p });
    if (/FROM vuln_hallazgos WHERE id = \?/.test(sql)) return HALLAZGOS.find((h) => h.id === p[0]) || null;
    if (/FROM activos WHERE id = \?/.test(sql)) return { id: p[0], tenant_id: { AB: "CB", AA: "CA" }[p[0]] || "CX" };
    return { n: 0 };
  };
  const qRun = async () => [{ affectedRows: 1 }];
  const app = appFalsa();
  require("../vulnerabilidades").montar(app, { auth: authFalsa(), auditLog: () => {}, qRow, qRows, qRun, transaccion: async (fn) => fn({ qRow, qRows, qRun }) });
  const con = (role) => ({ id: "u", username: "u", role });

  test("🔴 un cliente que no existe en la instalación: 403 y sin consultar vulnerabilidades", async () => {
    consultas.length = 0;
    const { res } = await invocar(app, "get", "/api/vulnerabilidades", { user: con("admin"), query: { cliente: "CX" } });
    assert.equal(res.statusCode, 403);
    assert.equal(consultas.some((c) => /vuln_hallazgos/.test(c.sql)), false, "llegó a consultar las vulnerabilidades");
  });

  test("sin cliente no hay listado", async () => {
    const { res } = await invocar(app, "get", "/api/vulnerabilidades", { user: con("admin") });
    assert.equal(res.statusCode, 403);
  });

  test("cada listado va acotado al cliente pedido (el lector también lee)", async () => {
    for (const cliente of ["CA", "CB"]) {
      consultas.length = 0;
      const { res } = await invocar(app, "get", "/api/vulnerabilidades", { user: con("lector"), query: { cliente } });
      assert.equal(res.statusCode, 200);
      const q = consultas.find((c) => /FROM vuln_hallazgos v JOIN activos a/.test(c.sql) && /LIMIT/.test(c.sql));
      assert.equal(q.p[0], cliente);
    }
  });

  test("la ficha de una vulnerabilidad de un cliente que no está responde 404; la de uno que está, no", async () => {
    assert.equal((await invocar(app, "get", "/api/vulnerabilidades/:id", { user: con("admin"), params: { id: "VX" } })).res.statusCode, 404);
    assert.notEqual((await invocar(app, "get", "/api/vulnerabilidades/:id", { user: con("admin"), params: { id: "VB" } })).res.statusCode, 404);
  });

  test("🔴 tampoco se le cambia el estado, ni se ven las de un activo de un cliente que no está", async () => {
    const est = await invocar(app, "put", "/api/vulnerabilidades/:id/estado", { user: con("admin"), params: { id: "VX" }, body: { estado: "falso_positivo", motivo: "no aplica" } });
    assert.equal(est.res.statusCode, 404);
    const act = await invocar(app, "get", "/api/vulnerabilidades/activo/:activoId", { user: con("admin"), params: { activoId: "AX" } });
    assert.equal(act.res.statusCode, 404);
  });

  test("el lector no importa ni cambia estados", async () => {
    const imp = await invocar(app, "post", "/api/vulnerabilidades/importar", { user: con("lector"), body: { cliente: "CA" } });
    assert.equal(imp.res.statusCode, 403);
    const est = await invocar(app, "put", "/api/vulnerabilidades/:id/estado", { user: con("lector"), params: { id: "VA" }, body: { estado: "remediado", motivo: "parche" } });
    assert.equal(est.res.statusCode, 403);
  });

  test("aceptar un riesgo es de administrador o auditor, no de pentester", async () => {
    const pen = await invocar(app, "put", "/api/vulnerabilidades/:id/estado", { user: con("pentester"), params: { id: "VA" }, body: { estado: "riesgo_aceptado", motivo: "lo acepta el cliente" } });
    assert.equal(pen.res.statusCode, 403);
    const aud = await invocar(app, "put", "/api/vulnerabilidades/:id/estado", { user: con("auditor"), params: { id: "VA" }, body: { estado: "riesgo_aceptado", motivo: "lo acepta el cliente" } });
    assert.equal(aud.res.statusCode, 200);
  });

  test("el cambio de estado exige motivo", async () => {
    const { res } = await invocar(app, "put", "/api/vulnerabilidades/:id/estado", { user: con("admin"), params: { id: "VA" }, body: { estado: "remediado" } });
    assert.equal(res.statusCode, 400);
  });

  test("Community no monta conectores ni la API para CI/CD (son de Pro)", () => {
    assert.equal(app.rutas.some((r) => /conectores|claves|\/api\/v1\//.test(r.ruta)), false);
  });
});

describe("inventario: alcance por cliente (adaptador de Community)", () => {
  const CLIENTES = [{ id: "CA" }, { id: "CB" }];
  const consultas = [];
  const qRows = async (sql, p = []) => { consultas.push({ sql, p }); return /FROM clients/.test(sql) ? CLIENTES : []; };
  const qRow = async (sql, p = []) => { consultas.push({ sql, p }); return /FROM activos WHERE id = \?/.test(sql) ? { id: p[0], tenant_id: "CX" } : { n: 0 }; };
  const app = appFalsa();
  require("../inventario-community").montar(app, { auth: authFalsa(), auditLog: () => {}, qRow, qRows, qRun: async () => [{}] });
  const con = (role) => ({ id: "u", username: "u", role });

  test("🔴 un cliente que no existe no lista activos", async () => {
    consultas.length = 0;
    const { res } = await invocar(app, "get", "/api/inventario", { user: con("admin"), query: { cliente: "CX" } });
    assert.equal(res.statusCode, 403);
    assert.equal(consultas.some((c) => /FROM activos/.test(c.sql)), false);
  });

  test("con un cliente de la instalación lista, acotado a ese cliente", async () => {
    consultas.length = 0;
    const { res } = await invocar(app, "get", "/api/inventario", { user: con("lector"), query: { cliente: "CA" } });
    assert.equal(res.statusCode, 200);
    const q = consultas.find((c) => /FROM activos a WHERE/.test(c.sql));
    assert.ok(q.p.includes("CA") && !q.p.includes("CB"));
  });

  test("🔴 la ficha de un activo de un cliente que no está responde 404", async () => {
    const { res } = await invocar(app, "get", "/api/inventario/:id", { user: con("admin"), params: { id: "X" } });
    assert.equal(res.statusCode, 404);
  });

  test("el lector no da de alta activos; el pentester no importa planillas", async () => {
    const alta = await invocar(app, "post", "/api/inventario", { user: con("lector"), query: { cliente: "CA" }, body: { nombre: "x" } });
    assert.equal(alta.res.statusCode, 403);
    const imp = await invocar(app, "post", "/api/inventario/importar", { user: con("pentester"), query: { cliente: "CA" }, body: {} });
    assert.equal(imp.res.statusCode, 403);
  });

  test("Community no expone el inventario a otros sistemas (la sincronización es de Pro)", () => {
    assert.equal(app.rutas.some((r) => r.ruta === "/api/inventario/export" || r.ruta.startsWith("/api/inventario/sincronizacion") || r.ruta.startsWith("/api/inventario/conectores")), false);
  });
});
