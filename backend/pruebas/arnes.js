/**
 * Arnés mínimo para probar rutas sin base ni red: un `app` falso que registra lo que cada módulo
 * monta con `montar(app, deps)`, un `res` que guarda la respuesta y un extractor de funciones del
 * server.js (que no exporta nada). No es un .test.js: lo usan las pruebas.
 *
 * Copia del de Gungnir Pro, sin `staffOnly` (Community no tiene staff ni inquilinos).
 */
"use strict";
const fs = require("node:fs");
const path = require("node:path");

function appFalsa() {
  const rutas = [];
  const app = {};
  for (const m of ["get", "post", "put", "patch", "delete", "use"]) {
    app[m] = (ruta, ...handlers) => { rutas.push({ metodo: m, ruta, handlers }); return app; };
  }
  app.rutas = rutas;
  return app;
}

function resFalsa() {
  const res = {
    statusCode: 200, cuerpo: undefined, cabeceras: {}, archivo: null, terminado: false,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.cuerpo = b; this.terminado = true; return this; },
    send(b) { this.cuerpo = b; this.terminado = true; return this; },
    set(k, v) { if (typeof k === "object") Object.assign(this.cabeceras, k); else this.cabeceras[k] = v; return this; },
    sendFile(f) { this.archivo = f; this.terminado = true; return this; },
    download(f) { this.archivo = f; this.terminado = true; return this; },
  };
  return res;
}

/** Corre la cadena de handlers de una ruta registrada, como lo haría Express. */
async function invocar(app, metodo, ruta, { user = null, body = {}, query = {}, params = {}, headers = {}, path: p = "", baseUrl = "" } = {}) {
  const r = app.rutas.find((x) => x.metodo === metodo && x.ruta === ruta);
  if (!r) throw new Error(`no hay ruta ${metodo.toUpperCase()} ${ruta}`);
  const req = { method: metodo === "delete" ? "DELETE" : metodo.toUpperCase(), user, body, query, params, headers,
                path: p, baseUrl, ip: "127.0.0.1", get: (h) => headers[h.toLowerCase()] ?? null };
  const res = resFalsa();
  let i = 0, siguio = false;
  const next = async (err) => {
    if (err) throw err;
    const h = r.handlers[i++];
    if (!h) { siguio = true; return; }
    await h(req, res, next);
  };
  await next();
  return { req, res, siguio };
}

/** auth() de prueba: respeta la lista de roles, como el real, y deja el usuario que trae el pedido. */
function authFalsa() {
  return (roles = []) => (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Sin token" });
    if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: "Sin permiso" });
    return next();
  };
}

const FUENTE_SERVER = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");

/** Devuelve el código de una función declarada a nivel superior del server.js. */
function fuenteDelServer(nombre) {
  const m = new RegExp(`^(?:async )?function ${nombre}\\s*\\(`, "m").exec(FUENTE_SERVER);
  if (!m) throw new Error(`no está la función ${nombre} en el server.js`);
  let prof = 0;
  for (let j = FUENTE_SERVER.indexOf("{", m.index); j < FUENTE_SERVER.length; j++) {
    if (FUENTE_SERVER[j] === "{") prof++;
    else if (FUENTE_SERVER[j] === "}" && --prof === 0) return FUENTE_SERVER.slice(m.index, j + 1);
  }
  throw new Error(`no se pudo delimitar ${nombre}`);
}

/** Arma funciones del server.js con las dependencias que se le pasan como contexto. */
function delServer(nombres, contexto = {}) {
  const claves = Object.keys(contexto);
  const src = nombres.map(fuenteDelServer).join("\n");
  return new Function(...claves, `${src}\nreturn { ${nombres.join(", ")} };`)(...claves.map((k) => contexto[k]));
}

const noop = () => {};
const asyncNoop = async () => {};

module.exports = { appFalsa, resFalsa, invocar, authFalsa, fuenteDelServer, delServer, FUENTE_SERVER, noop, asyncNoop };
