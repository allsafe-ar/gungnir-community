"use strict";

// ── Destinos permitidos para las integraciones ───────────────────────────────
//
// El problema que resuelve, y conviene tenerlo escrito porque no es obvio:
//
// La plataforma se conecta a escáneres (OpenVAS, Nessus), a webhooks de aviso y a
// lo que venga. En un pentest interno **buena parte de eso vive en la red del
// cliente**, y el producto puede correr todo en localhost. Un bloqueo liso de las
// direcciones privadas deja el producto inconfigurable desde su propio panel: las
// integraciones del lab tendrían que cargarse escribiendo directo en la base.
//
// Pero permitir cualquier dirección privada tampoco sirve, sobre todo pensando en
// la capa multi-tenant: ahí el admin de un cliente NO es dueño de la red donde
// corre el servidor, y sin control podría usar la plataforma para alcanzar la red
// interna de AllSafe.
//
// 🔑 La solución es de Emiliano: **el default sigue siendo denegar, y cada destino
// interno se declara explícitamente.** Contra un admin ya comprometido esto no
// protege mucho, porque ese admin también puede declarar la excepción. Donde sí
// gana es en todo lo demás:
//   · nada interno funciona por accidente, hay que declararlo a propósito;
//   · la lista es corta, con nombre y fecha, y se puede revisar; "permitimos todo
//     lo privado" no se revisa;
//   · y en modo hosteado la lista se fija por entorno y el cliente no la toca.
//
// ⛔ El link-local (169.254.0.0/16, que incluye el endpoint de metadatos de la
// nube) **no admite excepción, nunca**. Devuelve credenciales del proveedor que el
// admin de la plataforma no tiene: ahí sí hay una escalada real, no una molestia.

const ENV_ALLOWLIST = "NETWORK_ALLOWLIST";
const net = require("net");
const dnsPromesas = require("dns").promises;

function esIPv4(host) {
  const p = host.split(".");
  return p.length === 4 && p.every(x => /^\d{1,3}$/.test(x) && Number(x) <= 255);
}

/**
 * 🔴 SSRF (auditoría 2026-10): el filtro comparaba el texto del host tal como venía, y había
 * muchas formas de escribir la misma dirección interna que no coincidían: "0.0.0.0",
 * "localhost." con punto final, "[::1]" con corchetes (así lo devuelve `URL.hostname`),
 * "::ffff:127.0.0.1" (IPv4 mapeada en IPv6, que `URL` reescribe como "::ffff:7f00:1"),
 * "2130706433" (decimal) o "0177.0.0.1" (octal). Todo pasa ahora por acá antes de clasificar:
 * se sacan corchetes y punto final, el IPv4 en cualquier notación se lleva a la canónica con el
 * mismo parser que usa `URL`, y un IPv6 que lleva un IPv4 adentro (mapeado, compatible, NAT64 o
 * 6to4) se clasifica por ese IPv4.
 */
function hextetos(ip6) {
  let h = ip6.toLowerCase();
  const pct = h.indexOf("%");
  if (pct >= 0) h = h.slice(0, pct);                  // zona (fe80::1%eth0)
  const m = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(h);    // IPv4 embebido al final
  if (m) {
    const o = m[1].split(".").map(Number);
    h = h.slice(0, -m[1].length) + ((o[0] << 8) | o[1]).toString(16) + ":" + ((o[2] << 8) | o[3]).toString(16);
  }
  const [izq, der] = h.split("::");
  const a = izq ? izq.split(":") : [];
  const b = der !== undefined ? (der ? der.split(":") : []) : null;
  const partes = b === null ? a : [...a, ...Array(8 - a.length - b.length).fill("0"), ...b];
  return partes.length === 8 ? partes.map(x => parseInt(x || "0", 16)) : null;
}

/** IPv4 que viaja dentro de un IPv6 (::ffff:a.b.c.d, ::a.b.c.d, 64:ff9b::a.b.c.d, 2002:aabb:ccdd::), o null. */
function ipv4Embebido(ip6) {
  const x = hextetos(ip6);
  if (!x) return null;
  const v4 = (hi, lo) => [hi >> 8, hi & 255, lo >> 8, lo & 255].join(".");
  const ceros = (n) => x.slice(0, n).every(v => v === 0);
  if (ceros(5) && x[5] === 0xffff) return v4(x[6], x[7]);                      // mapeado
  if (ceros(6) && (x[6] || x[7] > 1)) return v4(x[6], x[7]);                   // compatible (obsoleto)
  if (x[0] === 0x64 && x[1] === 0xff9b && x.slice(2, 6).every(v => v === 0)) return v4(x[6], x[7]);  // NAT64
  if (x[0] === 0x64 && x[1] === 0xff9b && x[2] === 1) return v4(x[6], x[7]);  // NAT64 de uso local
  if (x[0] === 0x2002) return v4(x[1], x[2]);                                   // 6to4
  return null;
}

/** Host en forma canónica para comparar y clasificar. */
function canonizarHost(host) {
  let h = String(host ?? "").trim().toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  h = h.replace(/\.+$/, "");
  if (!h) return "";
  if (net.isIPv6(h.split("%")[0])) return ipv4Embebido(h) || h.split("%")[0];
  if (!net.isIPv4(h) && /^[0-9a-fx.]+$/.test(h)) {
    // Notaciones raras de IPv4 (decimal, octal, hexadecimal, con menos de cuatro partes).
    try { const u = new URL(`http://${h}/`).hostname; if (net.isIPv4(u)) return u; } catch { /* no es IP */ }
  }
  return h;
}

function aEntero(ip) {
  return ip.split(".").reduce((acc, o) => (acc << 8 >>> 0) + Number(o), 0) >>> 0;
}

/** 169.254.0.0/16, fe80::/10 y los metadatos de nube por IPv6. Bloqueado siempre, no se puede declarar. */
function esLinkLocal(hostCrudo) {
  const host = canonizarHost(hostCrudo);
  if (net.isIPv6(host)) {
    const x = hextetos(host);
    if (!x) return false;
    if ((x[0] & 0xffc0) === 0xfe80) return true;                     // fe80::/10 completo
    if (x[0] === 0xfd00 && x[1] === 0x0ec2) return true;             // metadatos de AWS (fd00:ec2::254)
    return false;
  }
  if (!esIPv4(host)) return false;
  const [a, b] = host.split(".").map(Number);
  return a === 169 && b === 254;
}

/** Rangos que exigen declaración explícita para poder usarse. */
function esPrivada(hostCrudo) {
  const host = canonizarHost(hostCrudo);
  if (host === "localhost" || host.endsWith(".localhost") || host === "localhost.localdomain") return true;
  if (net.isIPv6(host)) {
    const x = hextetos(host);
    if (!x) return true;                                   // no se entiende: se trata como interna
    if (x.every(v => v === 0)) return true;                // ::
    if (x.slice(0, 7).every(v => v === 0) && x[7] === 1) return true;   // ::1
    if ((x[0] & 0xfe00) === 0xfc00) return true;           // ULA fc00::/7
    if ((x[0] & 0xffc0) === 0xfec0) return true;           // site-local obsoleto
    if ((x[0] & 0xff00) === 0xff00) return true;           // multicast
    return false;
  }
  if (!esIPv4(host)) return false;
  const [a, b] = host.split(".").map(Number);
  return (
    a === 0 ||                            // 0.0.0.0/8: en Linux 0.0.0.0 llega al propio equipo
    a === 127 ||
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224                              // multicast, reservado y broadcast
  );
}

/**
 * Acepta "192.168.1.10", "192.168.1.0/24", "wazuh.interno", "http://host:9000/x".
 * Devuelve la entrada normalizada, o null si no sirve.
 */
function normalizarEntrada(entrada) {
  let v = String(entrada || "").trim().toLowerCase();
  if (!v) return null;
  if (v.includes("://")) {
    try { v = new URL(v).hostname; } catch { return null; }
  } else if (v.split("/").length === 2 && /\/\d{1,2}$/.test(v)) {
    const [red, bits] = v.split("/");     // CIDR, se conserva
    return `${canonizarHost(red)}/${bits}`;
  } else if (!(v.startsWith("[") || net.isIPv6(v.split("/")[0]))) {
    v = v.split("/")[0].split(":")[0];
  } else {
    v = v.split("/")[0].replace(/^\[([^\]]+)\].*$/, "$1");
  }
  return canonizarHost(v) || null;
}

function hostEnEntrada(hostCrudo, entrada) {
  const host = canonizarHost(hostCrudo);
  if (host === entrada) return true;
  if (entrada.includes("/") && esIPv4(host)) {
    const [red, bitsStr] = entrada.split("/");
    const bits = Number(bitsStr);
    if (!esIPv4(red) || !(bits >= 0 && bits <= 32)) return false;
    const mascara = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (aEntero(host) & mascara) === (aEntero(red) & mascara);
  }
  return false;
}

/** Lista fijada por entorno. Si existe, la interfaz la muestra pero no la edita. */
function allowlistDeEntorno() {
  const crudo = process.env[ENV_ALLOWLIST];
  if (crudo === undefined || crudo === null || String(crudo).trim() === "") return null;
  return String(crudo).split(/[\s,;]+/).map(normalizarEntrada).filter(Boolean);
}

function fijadaPorEntorno() {
  return allowlistDeEntorno() !== null;
}

/**
 * Decide si una URL de integración se puede guardar.
 * @param {string} urlStr
 * @param {string[]} declarados destinos internos declarados
 * @returns {{permitida: boolean, motivo?: string, host?: string}}
 */
function urlPermitida(urlStr, declarados = [], { sinExcepciones = false } = {}) {
  if (!urlStr) return { permitida: true };
  let host, u;
  try { u = new URL(urlStr); host = canonizarHost(u.hostname); }
  catch { return { permitida: false, motivo: "La URL no es válida." }; }
  if (!["http:", "https:"].includes(u.protocol))
    return { permitida: false, host, motivo: "Solo se aceptan URLs http o https." };
  return hostPermitido(host, declarados, { sinExcepciones });
}

/**
 * Lo mismo que `urlPermitida` pero para un host suelto (IP o nombre), sin resolver DNS.
 * `sinExcepciones` ignora las listas de destinos declarados: es para quien no es dueño de la
 * red del servidor (el cliente de una instalación SaaS), que no puede usar las excepciones
 * que AllSafe declaró para su propia red.
 */
function hostPermitido(hostCrudo, declarados = [], { sinExcepciones = false } = {}) {
  const host = canonizarHost(hostCrudo);
  if (!host) return { permitida: false, motivo: "Falta el destino." };

  if (esLinkLocal(host))
    return { permitida: false, host, motivo: "El rango link-local y el endpoint de metadatos de la nube están bloqueados siempre y no admiten excepción." };

  if (!esPrivada(host)) return { permitida: true, host };

  if (!sinExcepciones) {
    const lista = allowlistDeEntorno() ?? (declarados || []).map(normalizarEntrada).filter(Boolean);
    if (lista.some(e => hostEnEntrada(host, e))) return { permitida: true, host, declarado: true };
  }

  return {
    permitida: false, host,
    motivo: sinExcepciones
      ? `${host} es una dirección interna: no se puede usar como destino desde esta organización.`
      : `${host} es una dirección interna y no está declarada como destino permitido.` +
        (fijadaPorEntorno()
          ? " Esta instalación tiene la lista fijada por configuración del servidor."
          : " Agregala en Configuración → Destinos internos y volvé a guardar."),
  };
}

/**
 * 🔴 SSRF: un nombre de host no dice a dónde va. "interno.ejemplo.com" puede resolver a
 * 127.0.0.1, y el chequeo por texto lo dejaba pasar. Esta versión resuelve el nombre y exige
 * que TODAS las direcciones que devuelve el DNS estén permitidas. Un nombre declarado tal cual
 * en la lista (por ejemplo "wazuh.interno") se acepta por el nombre. Si no resuelve, se rechaza:
 * un destino que hoy no resuelve puede resolver mañana a cualquier cosa.
 *
 * ⚠️ El `httpRequest` de integrations/http.js SÍ sigue redirecciones y no las vuelve a chequear,
 * así que validar la URL de origen no alcanza: un 3xx puede saltar a un destino interno. Quien
 * use este guardia para salir a la red debe llamar con `maxRedirects: 0` (ver notificaciones.js),
 * o re-chequear cada salto.
 */
async function destinoPermitidoResuelto(hostCrudo, declarados = [], opciones = {}, resolver = dnsPromesas.lookup) {
  const base = hostPermitido(hostCrudo, declarados, opciones);
  if (!base.permitida || base.declarado) return base;
  const host = base.host;
  if (net.isIP(host)) return base;
  const lista = opciones.sinExcepciones ? []
    : (allowlistDeEntorno() ?? (declarados || []).map(normalizarEntrada).filter(Boolean));
  const nombreDeclarado = lista.includes(host);
  let direcciones;
  try { direcciones = (await resolver(host, { all: true, verbatim: true })).map(d => d.address); }
  catch { direcciones = []; }
  if (!direcciones.length) {
    return nombreDeclarado ? { permitida: true, host, declarado: true }
                           : { permitida: false, host, motivo: `No se pudo resolver ${host}.` };
  }
  for (const ip of direcciones) {
    // Un nombre declarado puede resolver a la red interna (para eso se declara), nunca a link-local.
    const r = nombreDeclarado
      ? (esLinkLocal(ip) ? { permitida: false, host: ip, motivo: "El rango link-local y el endpoint de metadatos de la nube están bloqueados siempre." } : { permitida: true })
      : hostPermitido(ip, declarados, opciones);
    if (!r.permitida) return { ...r, host, motivo: `${host} resuelve a ${r.host}. ${r.motivo}` };
  }
  return { permitida: true, host, direcciones };
}

async function urlPermitidaResuelta(urlStr, declarados = [], opciones = {}, resolver) {
  if (!urlStr) return { permitida: true };
  const base = urlPermitida(urlStr, declarados, opciones);
  if (!base.permitida) return base;
  return destinoPermitidoResuelto(new URL(urlStr).hostname, declarados, opciones, resolver);
}

module.exports = {
  urlPermitida, normalizarEntrada, esPrivada, esLinkLocal,
  canonizarHost, hostPermitido, destinoPermitidoResuelto, urlPermitidaResuelta,
  allowlistDeEntorno, fijadaPorEntorno, ENV_ALLOWLIST,
};
