// Pruebas de regresión de la auditoría de seguridad de octubre de 2026 (Gungnir Community).
// Cada una falla con el código anterior a la corrección. Corren contra el server.js real, con
// el doble de mysql2 (ver servidor.js): `npm test` desde backend/.
"use strict";
const { test, describe, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const totp = require("../totp");
const { arrancar, correrHastaSalir, SECRETO } = require("./servidor");

const SALUD = "/api/health";
const CLAVE = "Clave-de-prueba-1";
const SECRETO_TOTP = "JBSWY3DPEHPK3PXP";
const HASH = bcrypt.hashSync(CLAVE, 4);
const usuario = (id, role, extra = {}) => ({ id, username: role, email: `${role}@x`, full_name: role, role, is_active: 1,
  token_version: 0, failed_attempts: 0, password_hash: HASH, totp_enabled: 0, totp_secret: null, ...extra });
const ADMIN     = usuario("00000000-0000-0000-0000-00000000000a", "admin");
const PENTESTER = usuario("00000000-0000-0000-0000-00000000000b", "pentester");
const LECTOR    = usuario("00000000-0000-0000-0000-00000000000c", "lector", { totp_enabled: 1, totp_secret: SECRETO_TOTP });
const tokenDe = (u) => jwt.sign({ id: u.id, role: u.role, tv: 0 }, SECRETO);
const codigoVigente = () => totp.codigoDe(SECRETO_TOTP, Math.floor(Date.now() / 30000));

describe("JWT_SECRET: el arranque rechaza valores de ejemplo o cortos", () => {
  test("no arranca con el valor del .env.example de antes", async () => {
    const r = await correrHastaSalir({ JWT_SECRET: "cambiar_esto_por_un_secreto_de_al_menos_32_caracteres_random" });
    assert.equal(r.codigo, 1, r.salida);
    assert.match(r.salida, /FATAL: JWT_SECRET/);
  });
  test("no arranca con menos de 32 caracteres", async () => {
    const r = await correrHastaSalir({ JWT_SECRET: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d" }); // 31
    assert.equal(r.codigo, 1, r.salida);
  });
  test("el .env.example no trae un secreto que arranque", async () => {
    const ej = fs.readFileSync(path.join(__dirname, "..", ".env.example"), "utf8");
    const r = await correrHastaSalir({ JWT_SECRET: (ej.match(/^JWT_SECRET=(.*)$/m) || [])[1] || "" });
    assert.equal(r.codigo, 1, r.salida);
  });
});

describe("rutas", () => {
  let srv;
  before(async () => {
    srv = await arrancar({
      salud: SALUD,
      env: { TRUST_PROXY: "false" },
      datos: {
        usuarios: [ADMIN, PENTESTER, LECTOR],
        reglas: [
          { re: "^SELECT `key`, `value` FROM settings", filas: [
            { key: "report_org_name", value: "Mi Org" },
            { key: "recon_key_shodan", value: "SHODAN-CLAVE-SECRETA" },
            { key: "recon_key_virustotal", value: "VT-CLAVE-SECRETA" },
          ] },
          { re: "FROM scripts s LEFT JOIN users", filas: [{ id: "s1", name: "x", content: "echo", mitre_ids: ["T1059"], related_tools: [], tags: ["a"] }] },
        ],
      },
    });
  });
  after(() => srv.cerrar());

  test("U-01: /api/settings no entrega las API keys de recon", async () => {
    const r = await srv.pedir("GET", "/api/settings", { token: tokenDe(LECTOR) });
    assert.equal(r.status, 200);
    assert.ok(!r.texto.includes("SHODAN-CLAVE-SECRETA"));
    assert.ok(!r.texto.includes("VT-CLAVE-SECRETA"));
    assert.equal(r.json.report_org_name, "Mi Org");
  });

  test("U-02: el rol lector no escribe en un engagement", async () => {
    const e = "/api/engagements/11111111-1111-1111-1111-111111111111";
    const rutas = [
      ["POST", `${e}/findings`, { title: "x", severity: "high" }],
      ["PUT", `${e}/findings/f1`, { title: "x" }],
      ["DELETE", `${e}/evidences/ev1`],
      ["POST", `${e}/scope`, { value: "10.0.0.1" }],
      ["POST", `${e}/targets`, { ip: "10.0.0.1" }],
      ["DELETE", `${e}/targets/t1`],
      ["POST", `${e}/phases/recon/logs`, { content: "x" }],
      ["PUT", `${e}/phases`, { phases: [] }],
      ["PUT", `${e}/phase`, { phase: "recon" }],
    ];
    for (const [m, ruta, body] of rutas) {
      const r = await srv.pedir(m, ruta, { token: tokenDe(LECTOR), body });
      assert.equal(r.status, 403, `${m} ${ruta} respondió ${r.status}`);
    }
    const r = await srv.pedir("POST", `${e}/findings`, { token: tokenDe(PENTESTER), body: { title: "x", severity: "high" } });
    assert.notEqual(r.status, 403, "el pentester sigue pudiendo escribir");
  });

  test("U-03: desactivar el 2FA exige contraseña y código", async () => {
    const t = tokenDe(LECTOR);
    const quitados = () => srv.sql().filter(q => /SET totp_secret=NULL/.test(q.sql)).length;
    let r = await srv.pedir("DELETE", "/api/auth/totp", { token: t, body: {} });
    assert.equal(r.status, 400);
    r = await srv.pedir("DELETE", "/api/auth/totp", { token: t, body: { password: CLAVE } });
    assert.equal(r.status, 400);
    r = await srv.pedir("DELETE", "/api/auth/totp", { token: t, body: { password: CLAVE, code: "000000" === codigoVigente() ? "111111" : "000000" } });
    assert.equal(r.status, 400);
    assert.equal(quitados(), 0, "no se tenía que desactivar");
    r = await srv.pedir("DELETE", "/api/auth/totp", { token: t, body: { password: CLAVE, code: codigoVigente() } });
    assert.equal(r.status, 200);
    assert.equal(quitados(), 1);
  });

  test("U-04: crear un script responde 201 y queda auditado (logAudit no existía)", async () => {
    const r = await srv.pedir("POST", "/api/scripts", { token: tokenDe(ADMIN), body: { name: "x", content: "echo hola" } });
    assert.equal(r.status, 201, r.texto);
    assert.ok(srv.sql().some(q => q.sql.startsWith("INSERT INTO audit_logs") && q.p.includes("script")));
  });

  test("U-06: GET /api/scripts con columnas JSON ya parseadas", async () => {
    const r = await srv.pedir("GET", "/api/scripts", { token: tokenDe(LECTOR) });
    assert.equal(r.status, 200, r.texto);
    assert.deepEqual(r.json[0].mitre_ids, ["T1059"]);
  });

  test("U-07: /api/uploads acepta el nombre que genera multer (hex de 32)", async () => {
    const r = await srv.pedir("GET", "/api/uploads/0123456789abcdef0123456789abcdef", { token: tokenDe(LECTOR) });
    assert.equal(r.status, 404); // validó el nombre y el token; el archivo no existe
    const r2 = await srv.pedir("GET", "/api/uploads/..%2f..%2fetc%2fpasswd", { token: tokenDe(LECTOR) });
    assert.equal(r2.status, 400);
  });

  test("trust proxy: X-Forwarded-For no elige la IP de la auditoría", async () => {
    const r = await srv.pedir("POST", "/api/auth/login", { body: { username: "admin", password: CLAVE }, headers: { "X-Forwarded-For": "1.3.3.7" } });
    assert.equal(r.status, 200, r.texto);
    const fila = srv.sql().filter(q => q.sql.startsWith("INSERT INTO audit_logs") && q.p.includes("login")).pop();
    assert.ok(fila);
    assert.ok(!fila.p.includes("1.3.3.7"), JSON.stringify(fila.p));
  });
});
