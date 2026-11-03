/**
 * Etapa 4 contra un MySQL o MariaDB de verdad: el esquema nuevo (`ubicacion`, `vuln_puente`), la
 * importación de SARIF, Trivy y Nuclei con el inventario real (repositorio e imagen como activos),
 * y el pase a engagement. Copia de la de Gungnir Pro sin el puente (es de Pro).
 *
 *   GUNGNIR_PRUEBA_DB=mysql://usuario:clave@127.0.0.1:3306/base_de_prueba npm test
 *
 * Sin la variable se saltea. ⛔ Nunca apuntarla a una base con datos.
 */
"use strict";
const { test, describe, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const URL_DB = process.env.GUNGNIR_PRUEBA_DB;
const muestra = (f) => fs.readFileSync(path.join(__dirname, "muestras", f), "utf8");

describe("etapa 4 contra la base", { skip: !URL_DB && "sin GUNGNIR_PRUEBA_DB" }, () => {
  let pool, deps;
  const sufijo = Date.now().toString(36);
  const CA = `e4-A-${sufijo}`, CB = `e4-B-${sufijo}`, EA = `e4-EA-${sufijo}`;

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
    await qRun(`CREATE TABLE IF NOT EXISTS clients (id VARCHAR(36) PRIMARY KEY, name VARCHAR(200) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
    await qRun("CREATE TABLE IF NOT EXISTS settings (`key` VARCHAR(191) PRIMARY KEY, `value` MEDIUMTEXT) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // Lo mínimo de engagements y findings con las columnas que usa el pase (sobre una base de Gungnir ya están).
    await qRun(`CREATE TABLE IF NOT EXISTS engagements (id VARCHAR(36) PRIMARY KEY, client_id VARCHAR(36) NOT NULL, title VARCHAR(200) NOT NULL,
      codename VARCHAR(80), status VARCHAR(30) NOT NULL DEFAULT 'planned', start_date DATE, end_date DATE, tenant_id VARCHAR(36) NULL,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
    await qRun(`CREATE TABLE IF NOT EXISTS findings (id VARCHAR(36) PRIMARY KEY, engagement_id VARCHAR(36) NOT NULL, tenant_id VARCHAR(36) NULL,
      phase_type ENUM('planning','recon','scanning','exploitation','post_exploitation','reporting'), title VARCHAR(500) NOT NULL,
      description LONGTEXT, steps_to_reproduce LONGTEXT, affected_asset VARCHAR(500), cvss_vector_31 VARCHAR(100), cvss_score_31 DECIMAL(4,2),
      cvss_vector_40 VARCHAR(200), cvss_score_40 DECIMAL(4,2), severity ENUM('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
      initial_severity ENUM('critical','high','medium','low','info') NULL, cwe_id VARCHAR(20), recommendation LONGTEXT, references_list JSON,
      remediation_due_date DATE NULL, status ENUM('open','in_remediation','fixed','accepted') NOT NULL DEFAULT 'open',
      retest_status ENUM('not_retested','passed','failed','partial') NOT NULL DEFAULT 'not_retested', retested_at DATETIME NULL,
      created_by VARCHAR(36), FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
    for (let i = 0; i < 2; i++) {             // dos veces: el esquema nuevo es idempotente
      await require("../inventario-community").prepararEsquema({ qRows, qRun });
      await require("../vulnerabilidades").crearTablasCompletas({ qRows, qRun });
    }
    await qRun("INSERT INTO clients (id, name) VALUES (?,?), (?,?)", [CA, "Cliente A", CB, "Cliente B"]);
    await qRun("INSERT INTO engagements (id, client_id, title, status, tenant_id) VALUES (?,?,?,?,?)", [EA, CA, "Pentest A", "in_progress", "org-A"]);
    deps = { qRow, qRows, qRun, transaccion };
  });

  after(async () => {
    if (!pool) return;
    await pool.execute("DELETE FROM engagements WHERE id = ?", [EA]);
    await pool.execute("DELETE FROM clients WHERE id IN (?,?)", [CA, CB]);
    await pool.end();
  });

  const V = require("../vulnerabilidades");
  const importar = (o) => V.importar(deps, { usuario: "e4", ...o });

  test("esquema: ubicacion en vuln_hallazgos", async () => {
    const c = await deps.qRow("SELECT COUNT(*) AS n FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vuln_hallazgos' AND COLUMN_NAME = 'ubicacion'");
    assert.equal(Number(c.n), 1);
  });

  test("SARIF: el repositorio entra como software con su identificador y se reconoce en la reimportación", async () => {
    let r = await importar({ cliente: CA, fuente: "sarif", xml: muestra("codeql.sarif") });
    assert.equal(r.nuevos, 1, JSON.stringify(r));
    assert.equal(r.activos_nuevos, 1);
    const a = await deps.qRow(
      `SELECT a.id, a.nombre, a.categoria, a.tipo FROM activos a JOIN activo_fuentes f ON f.activo_id = a.id
        WHERE a.tenant_id = ? AND f.externo_id = 'repo:github.com/ejemplo-org/tienda-web'`, [CA]);
    assert.equal(a.categoria, "software");
    assert.equal(a.tipo, "desarrollo_propio");
    r = await importar({ cliente: CA, fuente: "sarif", xml: muestra("semgrep.sarif"), activo: "https://github.com/ejemplo-org/tienda-web.git" });
    assert.equal(r.activos_nuevos, 0, "el mismo repositorio entró dos veces");
    assert.equal(r.nuevos, 2);
    assert.equal(r.cerrados, 0, "Semgrep cerró lo de CodeQL");
    const v = await deps.qRow("SELECT ubicacion, regla, servicio FROM vuln_hallazgos WHERE cliente_id = ? AND regla = 'sarif:js/sql-injection'", [CA]);
    assert.equal(v.ubicacion, "src/db/pedidos.js:42");
    assert.equal(v.servicio, "CodeQL");
  });

  test("Trivy: la imagen con otra etiqueta es el mismo activo; lo corregido se cierra", async () => {
    let r = await importar({ cliente: CA, fuente: "trivy", xml: muestra("trivy-imagen.json") });
    assert.equal(r.nuevos, 5);
    const doc = JSON.parse(muestra("trivy-imagen.json"));
    doc.ArtifactName = "ghcr.io/ejemplo-org/tienda-web:1.5.0";
    doc.Results[0].Vulnerabilities = doc.Results[0].Vulnerabilities.filter((v) => v.PkgName !== "openssh-client");
    r = await importar({ cliente: CA, fuente: "trivy", xml: JSON.stringify(doc) });
    assert.equal(r.activos_nuevos, 0);
    assert.equal(r.nuevos, 0);
    assert.equal(r.cerrados, 1);
  });

  test("Nuclei: el sitio entra como servicio expuesto y cada ruta es una vulnerabilidad", async () => {
    const r = await importar({ cliente: CA, fuente: "nuclei", xml: muestra("nuclei.jsonl") });
    assert.equal(r.nuevos, 3);
    const n = await deps.qRow("SELECT COUNT(*) AS n FROM vuln_hallazgos WHERE cliente_id = ? AND regla = 'nuclei:git-config'", [CA]);
    assert.equal(Number(n.n), 2);
  });

  test("pase a engagement con SQL de verdad, sin duplicar", async () => {
    const VE = require("../vulnerabilidades-engagement");
    const v = await deps.qRow("SELECT id FROM vuln_hallazgos WHERE cliente_id = ? AND cves = 'CVE-2023-4911' LIMIT 1", [CA]);
    const eng = await deps.qRow("SELECT * FROM engagements WHERE id = ?", [EA]);
    const usuario = { id: "u1", username: "e4" };
    const a = await deps.transaccion((tx) => VE.llevarUna(tx, { vulnId: v.id, cliente: CA, eng, usuario, tenantEnFinding: false }));
    assert.ok(a.creado);
    const b = await deps.transaccion((tx) => VE.llevarUna(tx, { vulnId: v.id, cliente: CA, eng, usuario, tenantEnFinding: false }));
    assert.ok(b.ya, "se duplicó");
    const f = await deps.qRow("SELECT * FROM findings WHERE id = ?", [a.creado.finding_id]);
    assert.equal(f.severity, "high");
    assert.match(f.affected_asset, /^ghcr\.io\/ejemplo-org\/tienda-web /);
    const otro = await deps.transaccion((tx) => VE.llevarUna(tx, { vulnId: v.id, cliente: CB, eng, usuario }));
    assert.ok(otro.noEncontrada, "llevó una vulnerabilidad pidiéndola con otro cliente");
    assert.equal(await VE.registrarRetest(deps, f.id, "passed", "e4"), 1);
    const h = await deps.qRow("SELECT evento, estado_despues FROM vuln_historial WHERE hallazgo_id = ? AND evento = 'retest'", [v.id]);
    assert.equal(h.estado_despues, null);
  });
});
