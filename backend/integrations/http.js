"use strict";
const https = require("https");
const http  = require("http");

const DEFAULT_UA = "Mozilla/5.0 (compatible; Gungnir-Recon/1.0; +https://gungnir.allsafe.com.ar)";

// httpRequest - soporta redirect following (max 5) y User-Agent por defecto
// 🔴 El certificado TLS se valida SIEMPRE salvo que la integración lo pida explícitamente con
// `insecureTls: true` (escáner con certificado propio). Antes no se validaba nunca, y las claves de
// Nessus, OpenVAS y Shodan viajaban a quien se pusiera en el medio.
function httpRequest(urlStr, { method = "GET", headers = {}, body = null, timeout = 10000, maxRedirects = 5, insecureTls = false } = {}) {
  return _doRequest(urlStr, { method, headers, body, timeout, maxRedirects, redirectCount: 0, insecureTls: insecureTls === true });
}

/** Opciones TLS de un pedido: se exportan para que la prueba las mire sin abrir conexiones. */
function opcionesTls(insecureTls) {
  return { rejectUnauthorized: insecureTls !== true };
}

/**
 * Opciones de pedido hacia un escáner configurado. La validación TLS se apaga solo si la integración
 * lo declara (`extra_config.verificar_tls === false`). 🔴 Y no se siguen redirecciones: con un 302 se
 * mandaban las credenciales a un destino que nunca pasó por el filtro de URLs.
 */
function opcionesEscaner(cfg) {
  return { insecureTls: cfg?.extra_config?.verificar_tls === false, maxRedirects: 0 };
}

function _doRequest(urlStr, { method, headers, body, timeout, maxRedirects, redirectCount, insecureTls }) {
  return new Promise((resolve, reject) => {
    let urlObj;
    try { urlObj = new URL(urlStr); }
    catch { return reject(new Error("URL inválida")); }

    const isHttps = urlObj.protocol === "https:";
    const mod  = isHttps ? https : http;
    const opts = {
      hostname: urlObj.hostname,
      port:     urlObj.port || (isHttps ? 443 : 80),
      path:     urlObj.pathname + urlObj.search,
      method,
      headers:  {
        "User-Agent":   DEFAULT_UA,
        "Accept":       "application/json, application/rdap+json, */*",
        "Content-Type": "application/json",
        ...headers,
      },
      ...opcionesTls(insecureTls),
    };

    const req = mod.request(opts, (res) => {
      // Seguir redirects (301, 302, 303, 307, 308)
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirectCount < maxRedirects) {
        const location = res.headers.location;
        const nextUrl  = location.startsWith("http") ? location : new URL(location, urlStr).toString();
        res.resume(); // Consumir y descartar el cuerpo del redirect
        resolve(_doRequest(nextUrl, { method: res.statusCode === 303 ? "GET" : method, headers, body, timeout, maxRedirects, redirectCount: redirectCount + 1, insecureTls }));
        return;
      }
      let data = "";
      res.on("data", c => { data += c; });
      res.on("end", () => resolve({ status: res.statusCode, data }));
    });

    req.setTimeout(timeout, () => { req.destroy(); reject(new Error("Timeout")); });
    req.on("error", e => reject(new Error(e.message)));
    if (body) req.write(typeof body === "string" ? body : JSON.stringify(body));
    req.end();
  });
}

function parseJSON(str) {
  try { return JSON.parse(str); } catch { return null; }
}

module.exports = { httpRequest, parseJSON, opcionesTls, opcionesEscaner };
