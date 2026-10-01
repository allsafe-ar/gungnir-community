// Pruebas de regresión de la segunda vuelta de la auditoría de octubre de 2026 (Gungnir
// Community): lo que la reauditoría encontró abierto o a medias. Cada una falla con el código
// anterior a la corrección. `npm test` desde backend/.
"use strict";
const { test, describe, before, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const AdmZip = require("adm-zip");
const { arrancar, SECRETO } = require("./servidor");

const SALUD = "/api/health";
const CLAVE = "Clave-de-prueba-1";
const HASH = bcrypt.hashSync(CLAVE, 4);
const usuario = (id, role, extra = {}) => ({ id, username: role, email: `${role}@x`, full_name: role, role, is_active: 1,
  token_version: 0, failed_attempts: 0, password_hash: HASH, totp_enabled: 0, totp_secret: null, ...extra });
const ADMIN = usuario("00000000-0000-0000-0000-00000000000a", "admin");
const NUEVO = usuario("00000000-0000-0000-0000-00000000000d", "nuevo", { role: "admin", must_change_password: 1 });
const tokenDe = (u) => jwt.sign({ id: u.id, role: u.role, tv: 0 }, SECRETO);
const ENG = "00000000-0000-0000-0000-0000000000e1";

async function subir(srv, ruta, campos, archivo, nombre, ms = 30000) {
  const form = new FormData();
  for (const [k, v] of Object.entries(campos)) form.append(k, v);
  form.append("file", new Blob([archivo]), nombre);
  const r = await fetch(srv.base + ruta, { method: "POST", body: form, headers: { Authorization: "Bearer " + tokenDe(ADMIN) }, signal: AbortSignal.timeout(ms) });
  const texto = await r.text();
  let json = null; try { json = JSON.parse(texto); } catch {}
  return { status: r.status, json, texto };
}

describe("rutas", () => {
  let srv;
  before(async () => {
    srv = await arrancar({
      salud: SALUD,
      env: { TRUST_PROXY: "false", ADMIN_PASSWORD_INICIAL: "" },
      datos: {
        usuarios: [ADMIN, NUEVO],
        reglas: [
          { re: "FROM engagements WHERE id=\\?", filas: [{ id: ENG }] },
          // mysql2 entrega las columnas JSON ya parseadas: el doble las devuelve como arrays.
          { re: "FROM arsenal_commands c LEFT JOIN", filas: [{ id: "c1", tool_key: "nmap", command: "nmap -sV", tags: ["recon", "red"] }] },
          { re: "SELECT \\* FROM script_overrides$", filas: [{ item_id: "s1", mitre_ids: ["T1046"], related_tools: ["nmap"], tags: ["x"] }] },
        ],
      },
    });
  });
  after(() => srv.cerrar());

  test("U-05: el JWT por ?token= ya no sirve para bajar evidencias", async () => {
    const archivo = "0123456789abcdef0123456789abcdef";
    const porQuery = await srv.pedir("GET", `/api/uploads/${archivo}?token=${tokenDe(ADMIN)}`);
    assert.equal(porQuery.status, 401);
    const porHeader = await srv.pedir("GET", `/api/uploads/${archivo}`, { token: tokenDe(ADMIN) });
    assert.equal(porHeader.status, 404); // autenticado, el archivo no existe
  });

  test("U-06: el arsenal y los overrides no rompen con columnas JSON ya parseadas", async () => {
    const cmds = await srv.pedir("GET", "/api/arsenal/commands", { token: tokenDe(ADMIN) });
    assert.equal(cmds.status, 200, cmds.texto);
    assert.deepEqual(cmds.json[0].tags, ["recon", "red"]);
    const ov = await srv.pedir("GET", "/api/scripts/overrides", { token: tokenDe(ADMIN) });
    assert.equal(ov.status, 200, ov.texto);
    assert.deepEqual(ov.json[0].mitre_ids, ["T1046"]);
  });

  test("U-08: un ZIP que declara más de lo permitido se rechaza antes de descomprimir", async () => {
    const zip = new AdmZip();
    zip.addFile("engagement.json", Buffer.from(JSON.stringify({ version: 1, engagement: { title: "x", client_name: "c" } })));
    zip.addFile("files/bomba", Buffer.alloc(101 * 1024 * 1024)); // ~100 KB comprimido
    const r = await subir(srv, "/api/engagements/import", {}, zip.toBuffer(), "bomba.zip");
    assert.equal(r.status, 400, r.texto);
    assert.match(r.json.error, /tamaño permitido/);
    assert.ok(!srv.sql().some(q => q.sql.startsWith("INSERT INTO engagements")), "no se tiene que crear nada");
  });

  test("U-09: cada hallazgo de Nessus queda con su host, no con el primero", async () => {
    const xml = `<NessusClientData_v2><Report>
      <ReportHost name="10.0.0.1"><ReportItem port="22" protocol="tcp" severity="2" pluginName="SSH debil"><description>a</description></ReportItem></ReportHost>
      <ReportHost name="10.0.0.2"><ReportItem port="80" protocol="tcp" severity="3" pluginName="HTTP viejo"><description>b</description></ReportItem></ReportHost>
    </Report></NessusClientData_v2>`;
    const r = await subir(srv, `/api/engagements/${ENG}/import-scan`, { scanner_type: "nessus" }, xml, "scan.nessus");
    assert.ok(r.status < 300, r.texto);
    const ins = srv.sql().filter(q => q.sql.startsWith("INSERT INTO findings"));
    const http = ins.find(q => q.p.includes("HTTP viejo"));
    assert.ok(http, JSON.stringify(ins.map(q => q.p)));
    assert.ok(http.p.some(v => typeof v === "string" && v.startsWith("10.0.0.2")), JSON.stringify(http.p));
  });

  test("U-10: activar el 2FA exige la contraseña", async () => {
    const sin = await srv.pedir("POST", "/api/auth/totp/setup", { token: tokenDe(ADMIN), body: {} });
    assert.equal(sin.status, 400);
    const mal = await srv.pedir("POST", "/api/auth/totp/setup", { token: tokenDe(ADMIN), body: { password: "otra" } });
    assert.equal(mal.status, 400);
    assert.ok(!srv.sql().some(q => /SET totp_secret=\?/.test(q.sql)), "no se tiene que generar el secreto");
    const ok = await srv.pedir("POST", "/api/auth/totp/setup", { token: tokenDe(ADMIN), body: { password: CLAVE } });
    assert.equal(ok.status, 200, ok.texto);
    assert.ok(ok.json.secret);
  });

  test("U-11: con la contraseña inicial solo se puede cambiarla", async () => {
    const r = await srv.pedir("GET", "/api/dashboard", { token: tokenDe(NUEVO) });
    assert.equal(r.status, 403);
    assert.equal(r.json.mustChangePassword, true);
    const me = await srv.pedir("GET", "/api/auth/me", { token: tokenDe(NUEVO) });
    assert.equal(me.status, 200);
    const cambio = await srv.pedir("POST", "/api/auth/change-password", { token: tokenDe(NUEVO), body: { current_password: CLAVE, new_password: "Otra-Clave-456" } });
    assert.equal(cambio.status, 200, cambio.texto);
    assert.match(srv.sql().filter(q => /SET password_hash=\?/.test(q.sql)).pop().sql, /must_change_password=0/);
  });

  test("U-11: el admin del primer arranque no es admin/admin123 y su contraseña sale una vez en el log", async () => {
    const ins = srv.sql().find(q => /^INSERT INTO users/.test(q.sql));
    assert.ok(ins, "no se creó el admin");
    assert.match(ins.sql, /must_change_password/);
    const hash = ins.p.find(v => typeof v === "string" && v.startsWith("$2"));
    assert.equal(bcrypt.compareSync("admin123", hash), false);
    const m = srv.salida().match(/se muestra una sola vez\): (\S+)/);
    assert.ok(m, srv.salida());
    assert.equal(bcrypt.compareSync(m[1], hash), true);
  });

  test("CSP: sin upgrade-insecure-requests, con las fuentes y el script en línea del panel", async () => {
    const r = await srv.pedir("GET", SALUD);
    const csp = r.headers.get("content-security-policy") || "";
    assert.ok(!/upgrade-insecure-requests/.test(csp), csp);
    assert.match(csp, /style-src [^;]*https:\/\/fonts\.googleapis\.com/);
    assert.match(csp, /font-src [^;]*https:\/\/fonts\.gstatic\.com/);
    // Si hay panel compilado, cada script en línea del index.html tiene que estar autorizado.
    const index = [path.join(__dirname, "..", "public", "index.html"), path.join(__dirname, "..", "..", "frontend", "dist", "index.html")].find(f => fs.existsSync(f));
    if (index) {
      for (const m of fs.readFileSync(index, "utf8").matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
        const h = crypto.createHash("sha256").update(m[1], "utf8").digest("base64");
        assert.ok(csp.includes(`'sha256-${h}'`), `falta el hash del script en línea: ${h}`);
      }
    }
  });
});

describe("U-09: el parser de Nessus es lineal", () => {
  let srv;
  before(async () => {
    srv = await arrancar({ salud: SALUD, env: { TRUST_PROXY: "false" }, datos: { usuarios: [ADMIN], reglas: [{ re: "FROM engagements WHERE id=\\?", filas: [{ id: ENG }] }] } });
  });
  after(() => srv.cerrar());

  test("1 MB de <ReportItem sin cerrar responde en segundos", async () => {
    const xml = '<ReportHost name="h">' + '<ReportItem a="1">'.repeat(60000);
    const t0 = Date.now();
    let r;
    try { r = await subir(srv, `/api/engagements/${ENG}/import-scan`, { scanner_type: "nessus" }, xml, "scan.nessus", 10000); }
    catch (e) { assert.fail(`no respondió en 10 s (${e.name})`); }
    assert.equal(r.status, 400, r.texto); // no hay hallazgos
    assert.ok(Date.now() - t0 < 5000, `tardó ${Date.now() - t0} ms`);
  });
});
