/**
 * Vulnerabilidades, etapa 4: importadores SARIF 2.1.0, Trivy JSON y Nuclei JSONL (con muestras de la
 * estructura oficial de cada herramienta, sin datos de clientes), su deduplicación y su alcance de
 * cierre y el pase a engagement sin duplicar. Sin base ni red. Copia de la de Gungnir Pro sin el
 * puente con Gjallarhorn (es de Pro) y sin inquilinos.
 */
"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const M = require("../vulnerabilidades-motor");
const F = require("../vulnerabilidades-formatos");
const V = require("../vulnerabilidades");
const VE = require("../vulnerabilidades-engagement");
const arnes = require("./arnes");
const { appFalsa, authFalsa } = arnes;

/**
 * `invocar` del arnés, esperando a que la ruta responda: el middleware que carga los clientes llama a
 * `next()` sin esperarlo, así que la cadena sigue después de que `invocar` vuelve.
 */
async function invocar(...a) {
  const r = await arnes.invocar(...a);
  for (let i = 0; i < 200 && !r.res.terminado; i++) await new Promise((ok) => setImmediate(ok));
  return r;
}

const muestra = (f) => fs.readFileSync(path.join(__dirname, "muestras", f), "utf8");

// ── Repositorio en memoria con la interfaz de repoSQL (lo que usa M.aplicar) ───────────────────
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
    async insertar(h) { filas.push({ ...h, reaperturas: 0, fecha_cierre: null }); },
    async actualizar(id, cambios) {
      const f = filas.find((x) => x.id === id);
      for (const [k, v] of Object.entries(cambios)) f[k] = v === "+1" ? f[k] + 1 : v;
    },
    async anotar(e) { historial.push(e); },
  };
}

let n = 0;
const nuevoId = () => `id-${++n}`;

/**
 * Lo mismo que hace `importar` para un formato nuevo, con el inventario simulado: cada activo de código
 * o host recibe un id estable por su clave (como la ingesta del inventario con su identificador externo).
 */
function importarEnMemoria(repo, fuente, texto, { activo = null, extra = [] } = {}) {
  const { crudos, hosts, cierre } = F.leer(fuente, texto, { activo });
  const items = crudos.map(M.desdeParser);
  const mapa = new Map();
  for (const h of [...hosts, ...items.map((i) => i.host)]) {
    const k = V.claveHost(h);
    if (k && !mapa.has(k)) mapa.set(k, `activo:${k}`);
  }
  const conActivo = items.map((i) => ({ ...i, activo_id: mapa.get(V.claveHost(i.host)) })).filter((i) => i.activo_id);
  const alcance = [...new Set([...hosts.map((h) => mapa.get(V.claveHost(h))), ...extra.map((k) => mapa.get(k) || `activo:${k}`)])];
  return M.aplicar(repo, {
    cliente: "C1", fuente, items: conActivo, alcance, importacion: { id: `imp-${++n}`, codigo: `I${n}` }, usuario: "pen", nuevoId,
    filtroCierre: V.filtroDeCierre(cierre, mapa),
  });
}

/** Saca resultados de un SARIF (para simular una corrida en la que se corrigió algo). */
function sinResultados(texto, quedan) {
  const d = JSON.parse(texto);
  for (const r of d.runs) r.results = r.results.filter((x) => quedan(x));
  return JSON.stringify(d);
}

const abiertas = (repo) => repo.filas.filter((f) => M.ABIERTOS.includes(f.estado));

describe("SARIF 2.1.0", () => {
  test("Semgrep: lee reglas, severidad por nivel, CWE de los tags y ubicación archivo:línea", () => {
    const r = F.leer("sarif", muestra("semgrep.sarif"), { activo: "https://x-access-token:SECRETO@github.com/Ejemplo-Org/tienda-web.git" });
    assert.equal(r.crudos.length, 2);
    const [xss, sqli] = r.crudos;
    assert.equal(xss.severity, "medium");
    assert.equal(sqli.severity, "high");
    assert.equal(xss.cwe_id, "CWE-79");
    assert.equal(sqli.cwe_id, "CWE-89");
    assert.equal(xss._ubicacion, "src/rutas/buscar.js:27");
    assert.match(xss._regla, /^sarif:javascript\.express/);
    assert.equal(xss._servicio, "Semgrep OSS");
    assert.ok(!/Semgrep Finding/.test(xss.title), "el título de Semgrep no dice qué es");
    // 🔴 La credencial que un pipeline pone en la URL del clon no llega al inventario.
    assert.equal(xss._activo.clave, "repo:github.com/ejemplo-org/tienda-web");
    assert.ok(!JSON.stringify(r).includes("SECRETO"));
  });

  test("sin versionControlProvenance ni activo, pide el activo (no inventa uno)", () => {
    assert.throws(() => F.leer("sarif", muestra("semgrep.sarif")), (e) => e.lectura && /repositorio/.test(e.message));
  });

  test("CodeQL: repositorio desde versionControlProvenance y severidad desde security-severity", () => {
    const r = F.leer("sarif", muestra("codeql.sarif"));
    assert.equal(r.hosts[0].ref.clave, "repo:github.com/ejemplo-org/tienda-web");
    assert.equal(r.hosts[0].ref.tipo, "desarrollo_propio");
    assert.equal(r.crudos[0].severity, "high");
    assert.equal(r.crudos[0].cvss_score_31, 8.8);
    assert.equal(r.crudos[0].cwe_id, "CWE-89");
    assert.equal(r.crudos[0].title, "Database query built from user-controlled sources");
  });

  test("las reglas del run acotan el cierre solo si el run declara su juego completo", () => {
    const codeql = F.leer("sarif", muestra("codeql.sarif"));
    assert.ok(codeql.cierre[0].reglas.includes("sarif:js/path-injection"), "CodeQL lista reglas sin resultados: es su juego completo");
    // Trivy en SARIF lista solo las reglas que encontró: acotar por ellas impediría cerrar lo corregido.
    const soloEncontradas = { runs: [{ tool: { driver: { name: "Trivy", rules: [{ id: "CVE-2024-6387" }] } },
      versionControlProvenance: [{ repositoryUri: "https://github.com/ejemplo-org/tienda-web" }],
      results: [{ ruleId: "CVE-2024-6387", level: "error", message: { text: "m" }, locations: [{ physicalLocation: { artifactLocation: { uri: "Dockerfile" }, region: { startLine: 1 } } }] }] }], version: "2.1.0" };
    const t = F.leer("sarif", JSON.stringify(soloEncontradas));
    assert.equal(t.cierre[0].reglas, null);
    assert.deepEqual(t.crudos[0]._cves, ["CVE-2024-6387"], "Trivy en SARIF: la regla es el CVE");
  });

  test("dedup y cierre: la siguiente corrida de Semgrep cierra lo corregido y no duplica lo que sigue", async () => {
    const repo = repoMemoria();
    const activo = "github.com/ejemplo-org/tienda-web";
    let d = await importarEnMemoria(repo, "sarif", muestra("semgrep.sarif"), { activo });
    assert.equal(d.nuevos, 2);
    d = await importarEnMemoria(repo, "sarif", muestra("semgrep.sarif"), { activo });
    assert.equal(d.nuevos, 0); assert.equal(d.sin_cambios, 2);
    const corregida = sinResultados(muestra("semgrep.sarif"), (x) => !/sqli/.test(x.ruleId));
    d = await importarEnMemoria(repo, "sarif", corregida, { activo });
    assert.equal(d.cerrados, 1);
    assert.equal(abiertas(repo).length, 1);
    assert.match(abiertas(repo)[0].ubicacion, /buscar\.js:27/);
  });

  test("🔑 un CodeQL sobre el mismo repositorio no cierra lo que encontró Semgrep", async () => {
    const repo = repoMemoria();
    await importarEnMemoria(repo, "sarif", muestra("semgrep.sarif"), { activo: "github.com/ejemplo-org/tienda-web" });
    const d = await importarEnMemoria(repo, "sarif", muestra("codeql.sarif"));
    assert.equal(d.nuevos, 1, "CodeQL trae su propio hallazgo (otra regla, otra clave)");
    assert.equal(d.cerrados, 0, "CodeQL cerró hallazgos de Semgrep");
    assert.equal(abiertas(repo).length, 3);
    // Y CodeQL sí cierra lo suyo cuando desaparece.
    const limpio = sinResultados(muestra("codeql.sarif"), () => false);
    const d2 = await importarEnMemoria(repo, "sarif", limpio);
    assert.equal(d2.cerrados, 1);
    assert.equal(abiertas(repo).length, 2);
  });

  test("🔑 un Semgrep corrido con otra configuración no cierra reglas que no corrió", async () => {
    const repo = repoMemoria();
    const activo = "github.com/ejemplo-org/tienda-web";
    await importarEnMemoria(repo, "sarif", muestra("semgrep.sarif"), { activo });
    // Otra configuración: solo la regla de child_process (declarada, sin resultados) y nada más.
    const d = JSON.parse(muestra("semgrep.sarif"));
    d.runs[0].tool.driver.rules = d.runs[0].tool.driver.rules.filter((r) => /child-process/.test(r.id));
    d.runs[0].results = [];
    const r = await importarEnMemoria(repo, "sarif", JSON.stringify(d), { activo });
    assert.equal(r.cerrados, 0);
    assert.equal(abiertas(repo).length, 2);
  });
});

describe("Trivy JSON", () => {
  test("imagen: el activo es la imagen SIN la etiqueta; el mismo CVE en dos paquetes son dos", () => {
    const r = F.leer("trivy", muestra("trivy-imagen.json"));
    assert.equal(r.hosts[0].ref.clave, "imagen:ghcr.io/ejemplo-org/tienda-web");
    assert.equal(r.crudos.length, 5);
    const glibc = r.crudos.filter((c) => c._cves.includes("CVE-2023-4911"));
    assert.equal(glibc.length, 2);
    assert.notEqual(glibc[0]._ubicacion, glibc[1]._ubicacion);
    const express = r.crudos.find((c) => c._servicio === "express");
    assert.equal(express._ubicacion, "app/package-lock.json:express", "en un lenguaje, el archivo de dependencias va adelante");
    assert.equal(express.cvss_score_31, 6.1);
    const ghsa = r.crudos.find((c) => c._regla === "trivy:GHSA-952p-6rrq-rcjv");
    assert.deepEqual(ghsa._cves, []);
    assert.match(r.crudos[0].recommendation, /9\.2p1-2\+deb12u3/);
  });

  test("dedup y cierre: la imagen nueva (otra etiqueta) cierra lo corregido y una limpia cierra todo", async () => {
    const repo = repoMemoria();
    let d = await importarEnMemoria(repo, "trivy", muestra("trivy-imagen.json"));
    assert.equal(d.nuevos, 5);
    // 1.5.0: openssh actualizado; el resto sigue.
    const doc = JSON.parse(muestra("trivy-imagen.json"));
    doc.ArtifactName = "ghcr.io/ejemplo-org/tienda-web:1.5.0";
    doc.Results[0].Target = "ghcr.io/ejemplo-org/tienda-web:1.5.0 (debian 12.6)";
    doc.Results[0].Vulnerabilities = doc.Results[0].Vulnerabilities.filter((v) => v.PkgName !== "openssh-client");
    d = await importarEnMemoria(repo, "trivy", JSON.stringify(doc));
    assert.equal(d.nuevos, 0, "cambiar la etiqueta creó vulnerabilidades nuevas");
    assert.equal(d.cerrados, 1);
    doc.Results = [];
    d = await importarEnMemoria(repo, "trivy", JSON.stringify(doc));
    assert.equal(d.cerrados, 4, "una imagen limpia cierra lo que tenía abierto");
  });

  test("un directorio local (\".\") pide el activo; con el activo, entra como repositorio", () => {
    const doc = JSON.stringify({ SchemaVersion: 2, ArtifactName: ".", ArtifactType: "filesystem", Results: [] });
    assert.throws(() => F.leer("trivy", doc), (e) => e.lectura && /activo/.test(e.message));
    assert.equal(F.leer("trivy", doc, { activo: "gitlab.com/ejemplo/api" }).hosts[0].ref.clave, "repo:gitlab.com/ejemplo/api");
    assert.equal(F.leer("trivy", doc, { activo: "imagen:registry.local:5000/app:7" }).hosts[0].ref.clave, "imagen:registry.local:5000/app");
  });

  test("no confunde otro JSON con un Trivy", () => {
    assert.throws(() => F.leer("trivy", '{"hola":1}'), (e) => e.lectura);
    assert.throws(() => F.leer("trivy", "<xml/>"), (e) => e.lectura);
  });
});

describe("Nuclei JSONL", () => {
  test("lee las coincidencias (no las de matcher-status false), con CVE, CWE y CVSS", () => {
    const r = F.leer("nuclei", muestra("nuclei.jsonl"));
    assert.equal(r.crudos.length, 3);
    const apache = r.crudos.find((c) => c._regla === "nuclei:CVE-2021-41773");
    assert.deepEqual(apache._cves, ["CVE-2021-41773"]);
    assert.equal(apache.cwe_id, "CWE-22");
    assert.equal(apache._ip, "203.0.113.20");
    assert.equal(apache._puerto, "8080");
    const git = r.crudos.find((c) => c._regla === "nuclei:git-config");
    assert.equal(git._hostname, "tienda.example.com");
    assert.equal(git._ip, "", "el sitio no se identifica por la IP que resolvió (dos sitios en una IP se unirían)");
  });

  test("el mismo template en dos rutas del mismo sitio son dos vulnerabilidades; lo que no vuelve se cierra", async () => {
    const repo = repoMemoria();
    let d = await importarEnMemoria(repo, "nuclei", muestra("nuclei.jsonl"));
    assert.equal(d.nuevos, 3);
    const git = repo.filas.filter((f) => f.regla === "nuclei:git-config");
    assert.equal(git.length, 2);
    const sinAdmin = muestra("nuclei.jsonl").split("\n").filter((l) => !l.includes("/admin/")).join("\n");
    d = await importarEnMemoria(repo, "nuclei", sinAdmin);
    assert.equal(d.cerrados, 1);
    assert.equal(d.sin_cambios, 2);
  });

  test("un host limpio no aparece en el JSONL: solo se cierra si se lo declara en el alcance", async () => {
    const repo = repoMemoria();
    await importarEnMemoria(repo, "nuclei", muestra("nuclei.jsonl"));
    const soloTienda = muestra("nuclei.jsonl").split("\n").filter((l) => !l.includes("203.0.113.20")).join("\n");
    let d = await importarEnMemoria(repo, "nuclei", soloTienda);
    assert.equal(d.cerrados, 0, "cerró lo de un host que este escaneo no nombra");
    d = await importarEnMemoria(repo, "nuclei", soloTienda, { extra: ["203.0.113.20|"] });
    assert.equal(d.cerrados, 1);
  });

  test("acepta también el arreglo de -json-export", () => {
    const arr = "[" + muestra("nuclei.jsonl").trim().split("\n").join(",") + "]";
    assert.equal(F.leer("nuclei", arr).crudos.length, 3);
  });
});

describe("clave v1 con ubicación", () => {
  test("sin ubicación, la clave de siempre (no cambia nada de lo ya importado)", () => {
    const base = { activo_id: "A", puerto: "443", protocolo: "tcp", cves: ["CVE-2024-0001"] };
    assert.equal(M.claveDedup(base), M.claveDedup({ ...base, ubicacion: null }));
    assert.notEqual(M.claveDedup(base), M.claveDedup({ ...base, ubicacion: "src/a.js:1" }));
  });
  test("fusionar activos recalcula la clave con la ubicación", async () => {
    const h = { id: "h1", cliente_id: "C", activo_id: "B", puerto: null, protocolo: null, ubicacion: "src/a.js:3", cves: null, regla: "sarif:r1", titulo: "t" };
    const corridas = [];
    await M.moverDeActivo({
      qRows: async () => [h], qRow: async () => null, qRun: async (sql, p) => { corridas.push(p); },
    }, "A", "B");
    assert.equal(corridas[0][1], M.claveDedup({ activo_id: "A", ubicacion: "src/a.js:3", regla: "sarif:r1", titulo: "t" }));
  });
});

// ── Rutas: pase a engagement y puente ───────────────────────────────────────────────────────────
function entorno() {
  const db = {
    clients: [{ id: "CA", tenant_id: "org-A", name: "Cliente A" }, { id: "CB", tenant_id: "org-B", name: "Cliente B" }],
    engagements: [
      { id: "EA", client_id: "CA", title: "Pentest A", status: "in_progress", tenant_id: "org-A" },
      { id: "EA2", client_id: "CA", title: "Viejo A", status: "archived", tenant_id: "org-A" },
      { id: "EB", client_id: "CB", title: "Pentest B", status: "in_progress", tenant_id: "org-B" },
    ],
    vulns: [
      { id: "VA1", cliente_id: "CA", activo_id: "AA", titulo: "OpenSSH regreSSHion", severidad: "high", cvss: "8.1", cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cves: "CVE-2024-6387", cwe: "CWE-364", puerto: "22", protocolo: "tcp", ubicacion: null, descripcion: "d", solucion: "s", evidencia: "e", estado: "abierto",
        fecha_limite: "2026-11-30", finding_id: null },
      { id: "VA2", cliente_id: "CA", activo_id: "AA", titulo: "XSS", severidad: "medium", cvss: null, cves: null, estado: "abierto", ubicacion: "src/a.js:3", finding_id: null },
      { id: "VB1", cliente_id: "CB", activo_id: "AB", titulo: "De B", severidad: "critical", estado: "abierto", finding_id: null },
    ],
    findings: [], historial: [], puente: [], auditoria: [],
  };
  const qRows = async (sql, p = []) => {
    if (/SELECT id FROM clients$/.test(sql)) return db.clients;
    if (/FROM engagements WHERE client_id = \?/.test(sql)) return db.engagements.filter((e) => e.client_id === p[0] && !p.slice(1).includes(e.status));
    if (/FROM engagements WHERE id = \?/.test(sql)) return db.engagements.filter((e) => e.id === p[0]);
    if (/FROM vuln_hallazgos v JOIN activos a/.test(sql)) {
      return db.vulns.filter((v) => v.cliente_id === p[0] && M.ABIERTOS.includes(v.estado))
        .map((v) => ({ ...v, activo_id: v.activo_id, activo_nombre: `srv-${v.activo_id}`, activo_ip: "10.0.0.5" }));
    }
    if (/SELECT id, cliente_id FROM vuln_hallazgos WHERE finding_id = \?/.test(sql)) return db.vulns.filter((v) => v.finding_id === p[0]);
    return [];
  };
  const qRow = async (sql, p = []) => {
    if (/FROM vuln_hallazgos WHERE id = \? AND cliente_id = \?/.test(sql)) return db.vulns.find((v) => v.id === p[0] && v.cliente_id === p[1]) || null;
    if (/FROM findings f JOIN engagements e ON e.id = f.engagement_id WHERE f.id = \?/.test(sql)) {
      const f = db.findings.find((x) => x.id === p[0]);
      return f ? { ...f, engagement_id: f.engagement_id } : null;
    }
    if (/FROM activos WHERE id = \?/.test(sql)) return { id: p[0], nombre: `srv-${p[0]}`, ip: "10.0.0.5", hostname: null };
    if (/FROM vuln_puente WHERE organizacion = \? AND cliente_id <> \?/.test(sql)) return db.puente.find((x) => x.organizacion === p[0] && x.cliente_id !== p[1]) || null;
    if (/FROM vuln_puente WHERE organizacion = \?/.test(sql)) return db.puente.find((x) => x.organizacion === p[0]) || null;
    if (/FROM vuln_puente WHERE cliente_id = \?/.test(sql)) return db.puente.find((x) => x.cliente_id === p[0]) || null;
    if (/FROM clients WHERE id = \?/.test(sql)) return db.clients.find((c) => c.id === p[0]) || null;
    return null;
  };
  const qRun = async (sql, p = []) => {
    if (/^INSERT INTO findings/.test(sql)) {
      const cols = /\(([^)]+)\) VALUES/.exec(sql)[1].split(",").map((s) => s.trim());
      db.findings.push(Object.fromEntries(cols.map((c, i) => [c, p[i]])));
    } else if (/^UPDATE vuln_hallazgos SET engagement_id/.test(sql)) {
      Object.assign(db.vulns.find((v) => v.id === p[2]), { engagement_id: p[0], finding_id: p[1] });
    } else if (/^INSERT INTO vuln_historial/.test(sql)) {
      db.historial.push({ hallazgo_id: p[2], evento: p[5], motivo: p[6] });
    } else if (/^INSERT INTO vuln_puente/.test(sql)) {
      db.puente = db.puente.filter((x) => x.cliente_id !== p[0]);
      db.puente.push({ cliente_id: p[0], organizacion: p[2] });
    } else if (/^DELETE FROM vuln_puente/.test(sql)) {
      db.puente = db.puente.filter((x) => x.cliente_id !== p[0]);
    }
    return [{ affectedRows: 1 }];
  };
  const app = appFalsa();
  const visibles = new Set(["EA", "EB"]);
  V.montar(app, {
    auth: authFalsa(), auditLog: (...a) => db.auditoria.push(a), qRow, qRows, qRun,
    transaccion: async (fn) => fn({ qRow, qRows, qRun }),
  });
  return { app, db, visibles };
}
const deA = (role = "pentester") => ({ id: "uA", username: "ana", role, tenant_id: "org-A" });

describe("pase a engagement", () => {
  test("crea el hallazgo con lo que sabe la vulnerabilidad y deja historial en los dos lados", async () => {
    const { app, db } = entorno();
    const { res } = await invocar(app, "post", "/api/vulnerabilidades/a-engagement", { user: deA(), body: { cliente: "CA", engagement_id: "EA", ids: ["VA1"] } });
    assert.equal(res.statusCode, 201);
    assert.equal(res.cuerpo.creados.length, 1);
    const f = db.findings[0];
    assert.equal(f.engagement_id, "EA");
    assert.equal(f.title, "OpenSSH regreSSHion");
    assert.equal(f.severity, "high");
    assert.equal(f.initial_severity, "high");
    assert.equal(Number(f.cvss_score_31), 8.1);
    assert.match(f.cvss_vector_31, /^CVSS:3\.1/);
    assert.equal(f.cwe_id, "CWE-364");
    assert.match(f.description, /CVE-2024-6387/);
    assert.match(f.references_list, /nvd\.nist\.gov\/vuln\/detail\/CVE-2024-6387/);
    assert.equal(f.affected_asset, "srv-AA (10.0.0.5) 22/tcp");
    assert.equal(f.recommendation, "s");
    assert.equal(f.steps_to_reproduce, "e");
    assert.equal(f.remediation_due_date, "2026-11-30");
    assert.equal(f.tenant_id, undefined, "en Community findings no tiene tenant_id");
    const v = db.vulns.find((x) => x.id === "VA1");
    assert.equal(v.finding_id, f.id);
    assert.equal(v.engagement_id, "EA");
    assert.ok(db.historial.some((h) => h.hallazgo_id === "VA1" && h.evento === "a_engagement"));
    assert.ok(db.auditoria.some((a) => a[2] === "finding_create" && a[3] === "engagements" && a[4] === "EA"), "el engagement no registró la actividad");
  });

  test("🔑 no duplica: la segunda vez la informa como ya llevada", async () => {
    const { app, db } = entorno();
    await invocar(app, "post", "/api/vulnerabilidades/a-engagement", { user: deA(), body: { cliente: "CA", engagement_id: "EA", ids: ["VA1"] } });
    const { res } = await invocar(app, "post", "/api/vulnerabilidades/a-engagement", { user: deA(), body: { cliente: "CA", engagement_id: "EA", ids: ["VA1", "VA2"] } });
    assert.equal(db.findings.length, 2, "se creó otro hallazgo para VA1");
    assert.equal(res.cuerpo.ya_llevadas.length, 1);
    assert.equal(res.cuerpo.ya_llevadas[0].id, "VA1");
    assert.equal(res.cuerpo.creados[0].id, "VA2");
    assert.equal(db.findings[1].affected_asset, "srv-AA (10.0.0.5) src/a.js:3");
  });

  test("si el hallazgo del engagement se borró, se puede volver a llevar", async () => {
    const { app, db } = entorno();
    await invocar(app, "post", "/api/vulnerabilidades/a-engagement", { user: deA(), body: { cliente: "CA", engagement_id: "EA", ids: ["VA1"] } });
    db.findings.length = 0;
    const { res } = await invocar(app, "post", "/api/vulnerabilidades/a-engagement", { user: deA(), body: { cliente: "CA", engagement_id: "EA", ids: ["VA1"] } });
    assert.equal(res.cuerpo.creados.length, 1);
  });

  test("🔴 solo a un engagement abierto del MISMO cliente", async () => {
    const { app, db } = entorno();
    for (const engagement_id of ["EB", "EA2", "NOEXISTE"]) {
      const { res } = await invocar(app, "post", "/api/vulnerabilidades/a-engagement", { user: deA(), body: { cliente: "CA", engagement_id, ids: ["VA1"] } });
      assert.equal(res.statusCode, 404, `aceptó el engagement ${engagement_id}`);
    }
    assert.equal(db.findings.length, 0);
  });

  test("🔴 una vulnerabilidad de otro cliente no se lleva, aunque se mande su id", async () => {
    const { app, db } = entorno();
    const { res } = await invocar(app, "post", "/api/vulnerabilidades/a-engagement", { user: deA(), body: { cliente: "CA", engagement_id: "EA", ids: ["VB1"] } });
    assert.deepEqual(res.cuerpo.no_encontradas, ["VB1"]);
    assert.equal(db.findings.length, 0);
  });

  test("el lector no lleva; la lista de engagements es del cliente y sin archivados", async () => {
    const { app } = entorno();
    const r = await invocar(app, "post", "/api/vulnerabilidades/a-engagement", { user: deA("lector"), body: { cliente: "CA", engagement_id: "EA", ids: ["VA1"] } });
    assert.equal(r.res.statusCode, 403);
    const l = await invocar(app, "get", "/api/vulnerabilidades/engagements", { user: deA(), query: { cliente: "CA" } });
    assert.deepEqual(l.res.cuerpo.map((e) => e.id), ["EA"]);
  });

  test("el retest queda en el historial de la vulnerabilidad y no cambia su estado", async () => {
    const { app, db } = entorno();
    await invocar(app, "post", "/api/vulnerabilidades/a-engagement", { user: deA(), body: { cliente: "CA", engagement_id: "EA", ids: ["VA1"] } });
    const fid = db.findings[0].id;
    const qRows = async (sql, p) => (/WHERE finding_id = \?/.test(sql) ? db.vulns.filter((v) => v.finding_id === p[0]) : []);
    const qRun = async (sql, p) => { if (/INSERT INTO vuln_historial/.test(sql)) db.historial.push({ hallazgo_id: p[2], evento: p[5], estado: p[4] }); };
    assert.equal(await VE.registrarRetest({ qRows, qRun }, fid, "passed", "ana"), 1);
    const ev = db.historial.find((h) => h.evento === "retest");
    assert.equal(ev.hallazgo_id, "VA1");
    assert.equal(ev.estado, null);
    assert.equal(db.vulns.find((v) => v.id === "VA1").estado, "abierto");
  });
});
