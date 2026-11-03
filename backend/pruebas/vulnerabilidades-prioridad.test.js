/**
 * Vulnerabilidades, etapa 2: KEV y EPSS (parseo, máximo con varios CVE, descarga sin red), regla de
 * prioridad, plazos (KEV, reapertura, cambio de severidad, estados que no vencen), MTTR, antigüedad,
 * tendencia y aislamiento por cliente de las rutas nuevas.
 *
 * Sin red ni base: las descargas se simulan con un fetch falso y la base con un arnés en memoria.
 *
 * Portadas de Gungnir Pro. Las rutas se prueban con la regla de Community (una sola organización: el
 * administrador de la instalación hace lo que en Pro hace el staff). Sin el resumen semanal (es de Pro).
 */
"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const P = require("../vulnerabilidades-prioridad");
const E = require("../vulnerabilidades-enriquecimiento");
const M = require("../vulnerabilidades-motor");
const { appFalsa, invocar: invocarArnes, authFalsa } = require("./arnes");

/**
 * El cargador de clientes llama a `next()` sin esperarlo: con varias consultas en la ruta, el arnés
 * vuelve antes de la respuesta. Se espera a que la ruta responda.
 */
async function invocar(...args) {
  const r = await invocarArnes(...args);
  for (let i = 0; i < 200 && !r.res.terminado; i++) await new Promise((ok) => setImmediate(ok));
  return r;
}

// Recortes con la forma real (descargados el 02/11/2026).
const KEV = {
  title: "CISA Catalog of Known Exploited Vulnerabilities", catalogVersion: "2026.10.30", dateReleased: "2026-10-30T17:02:45.3665Z", count: 3,
  vulnerabilities: [
    { cveID: "CVE-2021-44228", vendorProject: "Apache", product: "Log4j2", vulnerabilityName: "Apache Log4j2 Remote Code Execution Vulnerability",
      dateAdded: "2021-12-10", dueDate: "2021-12-24", knownRansomwareCampaignUse: "Known", cwes: ["CWE-917"] },
    { cveID: "cve-2026-118527", vendorProject: "Ivanti", product: "Connect Secure", vulnerabilityName: "Ivanti Connect Secure Predictable Numbers",
      dateAdded: "2026-10-30", dueDate: "2026-11-13", knownRansomwareCampaignUse: "Unknown" },
    { cveID: "no-es-un-cve", vulnerabilityName: "basura" },
  ],
};
const EPSS = {
  status: "OK", "status-code": 200, version: "1.0", access: "public", total: 2, offset: 0, limit: 100,
  data: [
    { cve: "CVE-2023-38408", epss: "0.797000000", percentile: "0.996060000", date: "2026-11-02" },
    { cve: "CVE-2021-44228", epss: "0.999990000", percentile: "1.000000000", date: "2026-11-02" },
  ],
};

describe("KEV y EPSS: parseo", () => {
  test("KEV: CVE en mayúsculas, ransomware Known, fechas de CISA y descarta lo que no es un CVE", () => {
    const k = P.parsearKev(JSON.stringify(KEV));
    assert.equal(k.version, "2026.10.30");
    assert.equal(k.items.length, 2);
    const log4j = k.items.find((i) => i.cve === "CVE-2021-44228");
    assert.deepEqual({ ...log4j }, { cve: "CVE-2021-44228", nombre: "Apache Log4j2 Remote Code Execution Vulnerability", proveedor: "Apache",
      producto: "Log4j2", alta: "2021-12-10", vence: "2021-12-24", ransomware: 1 });
    assert.equal(k.items.find((i) => i.cve === "CVE-2026-118527").ransomware, 0);
  });

  test("🔴 KEV con otro formato o vacío falla (y así nunca vacía la caché)", () => {
    assert.throws(() => P.parsearKev({ foo: 1 }), /formato/);
    assert.throws(() => P.parsearKev({ vulnerabilities: [] }), /vacío/);
    assert.throws(() => P.parsearKev("<html>"));
  });

  test("EPSS: números, percentil y fecha del modelo", () => {
    const e = P.parsearEpss(EPSS);
    assert.deepEqual(e.find((x) => x.cve === "CVE-2023-38408"), { cve: "CVE-2023-38408", epss: 0.797, percentil: 0.99606, fecha: "2026-11-02" });
    assert.deepEqual(P.parsearEpss({ data: [{ cve: "CVE-2020-1234", epss: "7" }] }), [], "un EPSS fuera de 0..1 se descarta");
    assert.throws(() => P.parsearEpss({ status: "error" }), /formato/);
  });

  test("CVE de la columna y lotes de 100 para la API", () => {
    assert.deepEqual(P.cvesDe("cve-2020-0001, CVE-2020-0001;CVE-2021-12345 x"), ["CVE-2020-0001", "CVE-2021-12345"]);
    assert.deepEqual(P.lotes(Array.from({ length: 250 }, (_, i) => i)).map((l) => l.length), [100, 100, 50]);
  });
});

describe("un hallazgo con varios CVE", () => {
  const epss = new Map([["CVE-1", { epss: 0.02, percentil: 0.5 }], ["CVE-2", { epss: "0.61", percentil: "0.97" }]]);
  const kev = new Map([["CVE-3", { vence: "2026-12-01", ransomware: 0 }], ["CVE-4", { vence: "2026-11-20", ransomware: 1 }]]);

  test("toma el EPSS más alto y su percentil", () => {
    const c = P.combinar(["CVE-1", "CVE-2"], epss, kev);
    assert.equal(c.epss, 0.61); assert.equal(c.epss_percentil, 0.97); assert.equal(c.kev, 0);
  });

  test("kev = 1 si cualquiera está; ransomware si alguno lo tiene; el dueDate más cercano", () => {
    assert.deepEqual(P.combinar(["CVE-1", "CVE-3"], epss, kev), { epss: 0.02, epss_percentil: 0.5, kev: 1, kev_ransomware: 0, kev_vence: "2026-12-01" });
    const c = P.combinar(["CVE-3", "CVE-4"], epss, kev);
    assert.equal(c.kev_ransomware, 1); assert.equal(c.kev_vence, "2026-11-20");
  });

  test("sin datos: EPSS null; sin catálogo KEV cargado, kev queda null (no se sabe), no 0", () => {
    assert.deepEqual(P.combinar(["CVE-9"], epss, kev), { epss: null, epss_percentil: null, kev: 0, kev_ransomware: 0, kev_vence: null });
    assert.equal(P.combinar(["CVE-9"], epss, new Map(), false).kev, null);
  });
});

describe("prioridad", () => {
  const casos = [
    // severidad, epss, kev -> prioridad
    ["info", null, 1, "urgente"], ["low", 0, 1, "urgente"],
    ["critical", 0.5, 0, "urgente"], ["critical", 0.49, 0, "alta"], ["critical", null, 0, "alta"],
    ["high", 0.1, 0, "alta"], ["high", 0.09, 0, "media"], ["high", null, null, "media"],
    ["medium", 0.5, 0, "alta"], ["medium", 0.2, 0, "media"], ["medium", null, 0, "media"],
    ["low", 0.5, 0, "alta"], ["low", 0.1, 0, "media"], ["low", 0.05, 0, "baja"],
    ["info", 0.9, 0, "baja"],
  ];
  for (const [severidad, epss, kev, esperada] of casos) {
    test(`${severidad}, EPSS ${epss ?? "sin dato"}, KEV ${kev ?? "?"} -> ${esperada}`, () => {
      assert.equal(P.prioridad({ severidad, epss, kev }), esperada);
    });
  }

  test("la severidad pone el piso: un EPSS bajo nunca baja una crítica de alta", () => {
    for (const e of [0, 0.001, null]) assert.equal(P.prioridad({ severidad: "critical", epss: e, kev: 0 }), "alta");
  });
});

describe("plazos", () => {
  const pol = P.POLITICA_DEFECTO;

  test("política por defecto: 7/30/90/120 días; informativa sin plazo", () => {
    const desde = "2026-11-02 15:30:00";
    assert.deepEqual(["critical", "high", "medium", "low", "info"].map((s) => P.fechaLimite({ desde, severidad: s, politica: pol, kev: 0 })),
      ["2026-11-09", "2026-12-02", "2027-01-31", "2027-03-02", null]);
  });

  test("🔑 en KEV: como máximo 15 días desde la detección, aunque la política dé más", () => {
    assert.equal(P.fechaLimite({ desde: "2026-11-02", severidad: "medium", politica: pol, kev: 1, kev_vence: null }), "2026-11-17");
    assert.equal(P.fechaLimite({ desde: "2026-11-02", severidad: "info", politica: pol, kev: 1 }), "2026-11-17", "en KEV siempre hay plazo");
    assert.equal(P.fechaLimite({ desde: "2026-11-02", severidad: "critical", politica: pol, kev: 1 }), "2026-11-09", "si la política es más corta, manda la política");
  });

  test("🔑 en KEV: el dueDate de CISA acorta si cae después de la detección; si ya pasó, no cuenta", () => {
    assert.equal(P.fechaLimite({ desde: "2026-11-02", severidad: "high", politica: pol, kev: 1, kev_vence: "2026-11-13" }), "2026-11-13");
    assert.equal(P.fechaLimite({ desde: "2026-11-02", severidad: "high", politica: pol, kev: 1, kev_vence: "2021-12-24" }), "2026-11-17",
      "un dueDate de 2021 dejaría vencida el mismo día algo recién detectado");
  });

  test("🔑 reapertura: el plazo corre desde la reapertura, no desde la primera vez", () => {
    const base = { cves: null, severidad: "high", estado: "reabierto", primera_vez: new Date(2026, 0, 10, 9, 0) };
    const ctx = { epssPorCve: new Map(), kevPorCve: new Map(), kevCargado: true, politica: pol };
    assert.equal(P.calcular(base, ctx).fecha_limite, "2026-02-09");
    assert.equal(P.calcular({ ...base, plazo_desde: new Date(2026, 10, 2, 23, 50) }, ctx).fecha_limite, "2026-12-02");
    assert.deepEqual(M.transicionManual("remediado", "en_remediacion").cambios.plazo_desde, "ahora", "reabrir a mano reinicia el plazo");
    assert.equal(M.transicionManual("riesgo_aceptado", "abierto").cambios.plazo_desde, undefined, "volver de una decisión no lo reinicia");
  });

  test("🔑 cambio de severidad o de política: se recalcula desde la misma fecha", () => {
    const h = { cves: "CVE-2023-38408", severidad: "medium", estado: "abierto", primera_vez: "2026-11-02 10:00:00" };
    const ctx = { epssPorCve: new Map(), kevPorCve: new Map(), kevCargado: true, politica: pol };
    assert.equal(P.calcular(h, ctx).fecha_limite, "2027-01-31");
    assert.equal(P.calcular({ ...h, severidad: "critical" }, ctx).fecha_limite, "2026-11-09");
    const propia = P.politicaEfectiva({ critical: 3, high: 15, medium: 45, low: null, info: null }, { ...pol, medium: 60 });
    assert.equal(P.calcular(h, { ...ctx, politica: propia }).fecha_limite, "2026-12-17");
    assert.equal(P.calcular(h, { ...ctx, politica: P.politicaEfectiva(null, { ...pol, medium: 60 }) }).fecha_limite, "2027-01-01", "sin propia rige la global");
  });

  test("estados: en plazo, por vencer (7 días o menos, con el día límite incluido) y vencida", () => {
    const hoy = "2026-11-02";
    const est = (fecha_limite, estado = "abierto") => P.estadoPlazo({ estado, fecha_limite }, hoy);
    assert.equal(est("2026-11-10"), "en_plazo");
    assert.equal(est("2026-11-09"), "por_vencer");
    assert.equal(est("2026-11-02"), "por_vencer");
    assert.equal(est("2026-11-01"), "vencida");
    assert.equal(est(new Date(2026, 9, 31)), "vencida", "también con el Date que devuelve mysql2");
    assert.equal(est(null), "sin_plazo");
    assert.equal(est("2026-11-01", "en_remediacion"), "vencida");
    assert.equal(est("2026-11-01", "reabierto"), "vencida");
  });

  test("🔑 remediado, riesgo aceptado y falso positivo no vencen", () => {
    for (const e of ["remediado", "riesgo_aceptado", "falso_positivo"]) {
      assert.equal(P.estadoPlazo({ estado: e, fecha_limite: "2020-01-01" }, "2026-11-02"), "no_aplica");
    }
  });

  test("validación de la política", () => {
    assert.deepEqual(P.validarPolitica({ critical: "5", high: 20, medium: "", low: null }).politica, { critical: 5, high: 20, medium: null, low: null, info: null });
    assert.ok(P.validarPolitica({ critical: 0 }).error);
    assert.ok(P.validarPolitica({ critical: 1.5 }).error);
    assert.ok(P.validarPolitica({ critical: 99999 }).error);
    assert.ok(P.validarPolitica(null).error);
  });

  test("fechas de calendario sin correrse de día (fin de mes y de año)", () => {
    assert.equal(P.sumarDias("2026-12-28", 7), "2027-01-04");
    assert.equal(P.sumarDias("2028-02-27", 2), "2028-02-29");
    assert.equal(P.diasEntre("2026-11-02", "2026-11-01"), -1);
    assert.equal(P.ymd(new Date(2026, 10, 2, 23, 59, 59)), "2026-11-02");
  });
});

describe("métricas", () => {
  const ahora = new Date(2026, 10, 2, 12, 0, 0);
  const hoy = P.hoyLocal(ahora);

  test("MTTR por severidad: solo remediadas en los últimos 90 días, de la primera vez al cierre", () => {
    const d = (dia, mes = 10) => new Date(2026, mes, dia, 12, 0, 0);
    const filas = [
      { estado: "remediado", severidad: "critical", primera_vez: d(1, 9), fecha_cierre: d(5, 9) },   // 4 días
      { estado: "remediado", severidad: "critical", primera_vez: d(1, 9), fecha_cierre: d(11, 9) },  // 10 días
      { estado: "remediado", severidad: "high", primera_vez: d(1, 0), fecha_cierre: d(1, 1) },       // cerrada hace más de 90 días
      { estado: "riesgo_aceptado", severidad: "high", primera_vez: d(1, 9), fecha_cierre: d(2, 9) }, // no es remediación
    ];
    const m = P.mttr(filas, ahora, 90);
    assert.deepEqual(m.critical, { dias: 7, cerradas: 2 });
    assert.deepEqual(m.high, { dias: null, cerradas: 0 });
  });

  test("abiertas por prioridad, plazo, KEV y antigüedad (0-30, 31-90, 91-180, >180)", () => {
    const hace = (n) => P.sumarDias(hoy, -n);
    const filas = [
      { estado: "abierto", prioridad: "urgente", kev: 1, kev_ransomware: 1, fecha_limite: hace(1), primera_vez: hace(0) },
      { estado: "reabierto", prioridad: "alta", kev: 0, fecha_limite: hace(-3), primera_vez: hace(30) },
      { estado: "en_remediacion", prioridad: "media", kev: 0, fecha_limite: hace(-30), primera_vez: hace(31) },
      { estado: "abierto", prioridad: null, kev: null, fecha_limite: null, primera_vez: hace(180) },
      { estado: "abierto", prioridad: "baja", kev: 0, fecha_limite: hace(400), primera_vez: hace(181) },
      { estado: "remediado", prioridad: "urgente", kev: 1, fecha_limite: hace(10), primera_vez: hace(500) },
    ];
    const r = P.resumenAbiertas(filas, hoy);
    assert.deepEqual(r.por_prioridad, { urgente: 1, alta: 1, media: 1, baja: 2 });
    assert.equal(r.vencidas, 2); assert.equal(r.por_vencer, 1);
    assert.equal(r.en_kev, 1); assert.equal(r.kev_ransomware, 1);
    assert.deepEqual(r.antiguedad, { "0-30": 2, "31-90": 1, "91-180": 1, "180+": 1 });
  });

  test("tendencia de 12 semanas reconstruida con el historial (altas, cierres y reaperturas)", () => {
    const hace = (dias) => new Date(ahora.getTime() - dias * 86400000);
    const ev = [
      { hallazgo_id: "a", estado_despues: "abierto", created_at: hace(100) },   // antes de la ventana: cuenta desde el inicio
      { hallazgo_id: "b", estado_despues: "abierto", created_at: hace(60) },
      { hallazgo_id: "b", estado_despues: "remediado", created_at: hace(30) },
      { hallazgo_id: "b", estado_despues: "reabierto", created_at: hace(10) },
      { hallazgo_id: "c", estado_despues: "abierto", created_at: hace(20) },
      { hallazgo_id: "c", estado_despues: "falso_positivo", created_at: hace(1) },
    ];
    const t = P.tendencia(ev, ahora, 12);
    assert.equal(t.length, 12);
    assert.equal(t[11].semana, hoy);
    assert.equal(t[0].semana, P.sumarDias(hoy, -77));
    assert.deepEqual(t.map((x) => x.abiertas), [1, 1, 1, 2, 2, 2, 2, 1, 1, 2, 3, 2]);
  });
});

// ── Descargas simuladas y base en memoria ──────────────────────────────────────────────────────
function respuesta(cuerpo, status = 200) {
  const texto = typeof cuerpo === "string" ? cuerpo : JSON.stringify(cuerpo);
  return { ok: status >= 200 && status < 300, status, headers: { get: () => String(texto.length) }, text: async () => texto };
}

/** Base mínima en memoria para el enriquecimiento: settings, cachés y hallazgos. */
function baseFalsa(hallazgos = []) {
  const settings = new Map(), kev = new Map(), epss = new Map(), plazos = new Map();
  const updates = [];
  const enLista = (sql, p, desde) => p.slice(desde);
  const qRows = async (sql, p = []) => {
    if (/SELECT COUNT\(\*\) AS n FROM vuln_kev/.test(sql)) return [{ n: kev.size }];
    if (/COUNT\(\*\) AS n, MAX\(fecha\)/.test(sql)) return [{ n: epss.size, fecha: null }];
    if (/SELECT `value` FROM settings/.test(sql)) return settings.has(p[0]) ? [{ value: settings.get(p[0]) }] : [];
    if (/FROM vuln_plazos_cliente WHERE cliente_id = \?/.test(sql)) return plazos.has(p[0]) ? [plazos.get(p[0])] : [];
    if (/SELECT DISTINCT cves FROM vuln_hallazgos/.test(sql)) return [...new Set(hallazgos.filter((h) => h.cves && (!p[0] || h.cliente_id === p[0])).map((h) => h.cves))].map((cves) => ({ cves }));
    if (/SELECT cve FROM vuln_epss WHERE cve IN/.test(sql)) return enLista(sql, p, 0).filter((c) => epss.has(c)).map((cve) => ({ cve }));
    if (/SELECT cve, epss, percentil FROM vuln_epss/.test(sql)) return p.filter((c) => epss.has(c)).map((c) => ({ cve: c, ...epss.get(c) }));
    if (/SELECT cve, vence, ransomware FROM vuln_kev/.test(sql)) return p.filter((c) => kev.has(c)).map((c) => ({ cve: c, ...kev.get(c) }));
    if (/SELECT cve FROM vuln_kev$/.test(sql.trim())) return [...kev.keys()].map((cve) => ({ cve }));
    if (/FROM vuln_hallazgos WHERE id > \?/.test(sql)) {
      let i = 1;
      const desde = p[0];
      const cli = /cliente_id = \?/.test(sql) ? p[i++] : null;
      const ids = /id IN/.test(sql) ? p.slice(i) : null;
      return hallazgos.filter((h) => h.id > desde && (!cli || h.cliente_id === cli) && (!ids || ids.includes(h.id))
        && (!/prioridad IS NULL/.test(sql) || h.prioridad == null)).sort((a, b) => (a.id < b.id ? -1 : 1)).map((h) => ({ ...h }));
    }
    return [];
  };
  const qRow = async (sql, p) => (await qRows(sql, p))[0] || null;
  const qRun = async (sql, p = []) => {
    if (/INSERT INTO settings/.test(sql)) settings.set(p[0], p[1]);
    else if (/INSERT INTO vuln_kev/.test(sql)) for (let i = 0; i < p.length; i += 7) kev.set(p[i], { nombre: p[i + 1], vence: p[i + 5], ransomware: p[i + 6] });
    else if (/DELETE FROM vuln_kev/.test(sql)) for (const c of p) kev.delete(c);
    else if (/INSERT INTO vuln_epss/.test(sql)) for (let i = 0; i < p.length; i += 4) epss.set(p[i], { epss: p[i + 1], percentil: p[i + 2], fecha: p[i + 3] });
    else if (/INSERT INTO vuln_plazos_cliente/.test(sql)) plazos.set(p[0], { critical: p[1], high: p[2], medium: p[3], low: p[4], info: p[5] });
    else if (/UPDATE vuln_hallazgos SET/.test(sql)) {
      const id = p[p.length - 1];
      const h = hallazgos.find((x) => x.id === id);
      const asign = sql.match(/SET (.*), updated_at = updated_at WHERE/)[1].split(", ");
      let j = 0;
      for (const a of asign) {
        const [col, val] = a.split(" = ");
        h[col] = val === "?" ? p[j++] : val === "NULL" ? null : "AHORA";
      }
      updates.push(id);
    }
    return [{ affectedRows: 1 }];
  };
  return { qRow, qRows, qRun, settings, kev, epss, plazos, hallazgos, updates };
}

describe("enriquecimiento: descargas sin red real", () => {
  test("descargarTexto: sin seguir redirecciones, con tiempo máximo y el error de red legible", async () => {
    let opciones;
    await E.descargarTexto("https://x", { fetchImpl: async (_u, o) => { opciones = o; return respuesta("{}"); } });
    assert.equal(opciones.redirect, "error");
    await assert.rejects(E.descargarTexto("https://x", { fetchImpl: async () => respuesta("no", 503) }), /HTTP 503/);
    await assert.rejects(E.descargarTexto("https://x", { timeout: 20, fetchImpl: (_u, o) => new Promise((_r, rej) => o.signal.addEventListener("abort", () => rej(Object.assign(new Error("abort"), { name: "AbortError" })))) }), /tiempo de espera/);
    await assert.rejects(E.descargarTexto("https://x", { fetchImpl: async () => { throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ENOTFOUND" } }); } }), /ENOTFOUND/);
  });

  test("KEV: baja el catálogo, lo guarda entero y anota la versión", async () => {
    const db = baseFalsa();
    const pedidas = [];
    const enr = E.crear({ ...db, fetchImpl: async (u) => { pedidas.push(u); return respuesta(KEV); }, pausa: 0 });
    const r = await enr.actualizarKev();
    assert.equal(r.ok, true); assert.equal(r.cantidad, 2);
    assert.deepEqual(pedidas, [E.URL_KEV]);
    assert.equal(db.kev.get("CVE-2021-44228").ransomware, 1);
    const est = await enr.estado();
    assert.equal(est.kev.version, "2026.10.30"); assert.equal(est.kev.cantidad, 2); assert.equal(est.kev.error, null);
  });

  test("🔴 sin internet: no rompe, la caché queda como estaba y el estado informa el error", async () => {
    const db = baseFalsa([{ id: "h1", cliente_id: "CA", cves: "CVE-2021-44228" }]);
    db.kev.set("CVE-2021-44228", { vence: "2021-12-24", ransomware: 1 });
    const sinRed = async () => { throw Object.assign(new TypeError("fetch failed"), { cause: { code: "EAI_AGAIN" } }); };
    const enr = E.crear({ ...db, fetchImpl: sinRed, pausa: 0, log: { log() {}, error() {} } });
    const k = await enr.actualizarKev();
    const e = await enr.actualizarEpss();
    assert.equal(k.ok, false); assert.equal(e.ok, false);
    assert.equal(db.kev.size, 1, "se vació la caché de KEV");
    const est = await enr.estado();
    assert.match(est.kev.error, /EAI_AGAIN/);
    assert.equal(est.kev.ultima_ok, undefined);
  });

  test("EPSS: solo los CVE de los hallazgos, de a 100 por pedido", async () => {
    const hallazgos = Array.from({ length: 230 }, (_, i) => ({ id: `h${i}`, cliente_id: "CA", cves: `CVE-2024-${String(10000 + i)}` }));
    hallazgos.push({ id: "hx", cliente_id: "CA", cves: null });
    const db = baseFalsa(hallazgos);
    const urls = [];
    const fetchImpl = async (u) => {
      urls.push(u);
      const cves = new URL(u).searchParams.get("cve").split(",");
      return respuesta({ data: cves.map((cve) => ({ cve, epss: "0.01", percentile: "0.5", date: "2026-11-02" })) });
    };
    const r = await E.crear({ ...db, fetchImpl, pausa: 0 }).actualizarEpss();
    assert.equal(r.ok, true); assert.equal(r.consultados, 230); assert.equal(r.guardados, 230);
    assert.equal(urls.length, 3);
    assert.ok(urls.every((u) => u.startsWith(`${E.URL_EPSS}?cve=`)));
    assert.equal(new URL(urls[0]).searchParams.get("cve").split(",").length, 100);
  });

  test("después de importar: solo se consultan los CVE de ese cliente que faltan en la caché", async () => {
    const db = baseFalsa([
      { id: "h1", cliente_id: "CA", cves: "CVE-2021-44228,CVE-2023-38408" },
      { id: "h2", cliente_id: "CB", cves: "CVE-2020-0001" },
    ]);
    db.epss.set("CVE-2021-44228", { epss: 0.9, percentil: 1 });
    const urls = [];
    const enr = E.crear({ ...db, fetchImpl: async (u) => { urls.push(u); return respuesta(EPSS); }, pausa: 0 });
    const cves = await enr.cvesAConsultar({ cliente: "CA", soloFaltantes: true });
    assert.deepEqual(cves, ["CVE-2023-38408"]);
  });

  test("recálculo: EPSS máximo, KEV, prioridad, plazo y fecha de alta en KEV; solo escribe lo que cambió", async () => {
    const db = baseFalsa([
      { id: "h1", cliente_id: "CA", cves: "CVE-2021-44228,CVE-2023-38408", severidad: "medium", estado: "abierto", primera_vez: "2026-11-02 10:00:00" },
      { id: "h2", cliente_id: "CA", cves: null, severidad: "high", estado: "abierto", primera_vez: "2026-11-02 10:00:00" },
      { id: "h3", cliente_id: "CB", cves: "CVE-2023-38408", severidad: "low", estado: "remediado", primera_vez: "2026-11-02 10:00:00" },
    ]);
    db.kev.set("CVE-2021-44228", { vence: "2021-12-24", ransomware: 1 });
    db.epss.set("CVE-2021-44228", { epss: "0.99999", percentil: "1.00000" });
    db.epss.set("CVE-2023-38408", { epss: "0.79700", percentil: "0.99606" });
    const enr = E.crear({ ...db, pausa: 0 });
    const r = await enr.recalcular();
    assert.equal(r.revisados, 3); assert.equal(r.cambiados, 3);
    const [h1, h2, h3] = db.hallazgos;
    assert.equal(h1.epss, 0.99999); assert.equal(h1.kev, 1); assert.equal(h1.kev_ransomware, 1); assert.equal(h1.kev_desde, "AHORA");
    assert.equal(h1.prioridad, "urgente"); assert.equal(h1.fecha_limite, "2026-11-17", "KEV con dueDate pasado: 15 días");
    assert.equal(h2.prioridad, "media"); assert.equal(h2.kev, 0); assert.equal(h2.fecha_limite, "2026-12-02");
    assert.equal(h3.prioridad, "alta", "baja con EPSS 0,797");
    db.updates.length = 0;
    const r2 = await enr.recalcular();
    assert.equal(r2.cambiados, 0, "un segundo recálculo sin cambios no escribe");
    // Política propia del cliente A: se recalcula solo A.
    await enr.guardarPoliticaCliente("CA", { critical: 3, high: 10, medium: 30, low: 60, info: null }, "u");
    await enr.recalcular({ cliente: "CA" });
    assert.equal(h2.fecha_limite, "2026-11-12");
    assert.deepEqual(db.updates, ["h2"], "tocó otro cliente o algo que no cambió");
  });
});

// ── Rutas nuevas: alcance por cliente y permisos ──────────────────────────────────────────────
describe("rutas de la etapa 2: alcance por cliente y permisos (Community)", () => {
  const CLIENTES = [{ id: "CA" }, { id: "CB" }];
  const consultas = [];
  const qRows = async (sql, p = []) => {
    consultas.push({ sql, p });
    if (/FROM clients/.test(sql)) return CLIENTES;
    return [];
  };
  const qRow = async (sql, p = []) => { consultas.push({ sql, p }); return /COUNT/.test(sql) ? { n: 0 } : null; };
  const escrituras = [];
  const qRun = async (sql, p = []) => { escrituras.push({ sql, p }); return [{ affectedRows: 1 }]; };
  let actualizaciones = 0;
  const enriquecimiento = {
    ...E.crear({ qRow, qRows, qRun }),
    actualizarTodo: async () => { actualizaciones++; return { kev: { ok: true, cantidad: 1 }, epss: { ok: true, consultados: 0 }, recalculo: { cambiados: 0 } }; },
    completarCliente: async () => null,
  };
  const app = appFalsa();
  require("../vulnerabilidades").montar(app, { auth: authFalsa(), auditLog: () => {}, qRow, qRows, qRun, transaccion: async (fn) => fn({ qRow, qRows, qRun }), enriquecimiento });
  const con = (role) => ({ id: "u", username: "u", role });

  test("🔴 métricas de un cliente que no existe: 403 y sin consultar vulnerabilidades", async () => {
    consultas.length = 0;
    const { res } = await invocar(app, "get", "/api/vulnerabilidades/metricas", { user: con("admin"), query: { cliente: "CX" } });
    assert.equal(res.statusCode, 403);
    assert.equal(consultas.some((c) => /vuln_/.test(c.sql)), false);
  });

  test("métricas de un cliente: todas las consultas acotadas a ese cliente", async () => {
    consultas.length = 0;
    const { res } = await invocar(app, "get", "/api/vulnerabilidades/metricas", { user: con("lector"), query: { cliente: "CA" } });
    assert.equal(res.statusCode, 200, JSON.stringify(res.cuerpo));
    const deVulns = consultas.filter((c) => /FROM vuln_(hallazgos|historial)/.test(c.sql));
    assert.ok(deVulns.length >= 3);
    for (const c of deVulns) assert.equal(c.p[0], "CA", c.sql);
    assert.equal(res.cuerpo.tendencia.length, 12);
    assert.deepEqual(Object.keys(res.cuerpo.antiguedad), ["0-30", "31-90", "91-180", "180+"]);
  });

  test("filtros (prioridad, KEV, plazo) acotados al cliente pedido, y el orden empieza por la prioridad", async () => {
    const { res } = await invocar(app, "get", "/api/vulnerabilidades", { user: con("admin"), query: { cliente: "CX", prioridad: "urgente", kev: "1", plazo: "vencida" } });
    assert.equal(res.statusCode, 403);
    consultas.length = 0;
    const ok = await invocar(app, "get", "/api/vulnerabilidades", { user: con("admin"), query: { cliente: "CA", prioridad: "urgente", kev: "1", plazo: "vencida" } });
    assert.equal(ok.res.statusCode, 200);
    const q = consultas.find((c) => /FROM vuln_hallazgos v JOIN activos a/.test(c.sql) && /LIMIT/.test(c.sql));
    assert.equal(q.p[0], "CA");
    assert.match(q.sql, /v\.prioridad = \?/); assert.match(q.sql, /v\.kev = 1/); assert.match(q.sql, /v\.fecha_limite < \?/);
    assert.match(q.sql, /ORDER BY COALESCE\(NULLIF\(FIELD\(v\.prioridad/, "el orden por defecto empieza por la prioridad");
  });

  test("🔴 plazos: los de un cliente que no existe no se leen ni se cambian", async () => {
    escrituras.length = 0;
    assert.equal((await invocar(app, "get", "/api/vulnerabilidades/plazos", { user: con("admin"), query: { cliente: "CX" } })).res.statusCode, 403);
    assert.equal((await invocar(app, "put", "/api/vulnerabilidades/plazos", { user: con("admin"), query: { cliente: "CX" }, body: { politica: { critical: 1 } } })).res.statusCode, 403);
    assert.equal((await invocar(app, "delete", "/api/vulnerabilidades/plazos", { user: con("admin"), query: { cliente: "CX" } })).res.statusCode, 403);
    assert.equal(escrituras.length, 0);
  });

  test("plazos de un cliente: los cambia un administrador o auditor, no un pentester ni un lector", async () => {
    const body = { politica: { critical: 5, high: 20, medium: 60, low: 90, info: null } };
    assert.equal((await invocar(app, "put", "/api/vulnerabilidades/plazos", { user: con("pentester"), query: { cliente: "CA" }, body })).res.statusCode, 403);
    assert.equal((await invocar(app, "put", "/api/vulnerabilidades/plazos", { user: con("lector"), query: { cliente: "CA" }, body })).res.statusCode, 403);
    escrituras.length = 0;
    const ok = await invocar(app, "put", "/api/vulnerabilidades/plazos", { user: con("auditor"), query: { cliente: "CA" }, body });
    assert.equal(ok.res.statusCode, 200, JSON.stringify(ok.res.cuerpo));
    const w = escrituras.find((e) => /INSERT INTO vuln_plazos_cliente/.test(e.sql));
    assert.deepEqual(w.p.slice(0, 6), ["CA", 5, 20, 60, 90, null]);
    const mal = await invocar(app, "put", "/api/vulnerabilidades/plazos", { user: con("admin"), query: { cliente: "CA" }, body: { politica: { critical: -1 } } });
    assert.equal(mal.res.statusCode, 400);
  });

  test("🔴 la política global y el \"Actualizar ahora\" son del administrador de la instalación, no de un auditor", async () => {
    const body = { politica: { critical: 5, high: 20, medium: 60, low: 90, info: null } };
    escrituras.length = 0;
    assert.equal((await invocar(app, "put", "/api/vulnerabilidades/plazos/global", { user: con("auditor"), body })).res.statusCode, 403);
    assert.equal((await invocar(app, "post", "/api/vulnerabilidades/enriquecimiento/actualizar", { user: con("pentester") })).res.statusCode, 403);
    assert.equal(escrituras.length, 0); assert.equal(actualizaciones, 0);
    assert.equal((await invocar(app, "put", "/api/vulnerabilidades/plazos/global", { user: con("admin"), body })).res.statusCode, 200);
    assert.ok(escrituras.some((e) => /INSERT INTO settings/.test(e.sql) && e.p[0] === "vuln_plazos"));
    const act = await invocar(app, "post", "/api/vulnerabilidades/enriquecimiento/actualizar", { user: con("admin") });
    assert.equal(act.res.statusCode, 202); assert.equal(actualizaciones, 1);
  });

  test("el estado del enriquecimiento lo ve cualquiera con sesión; dice si puede actualizar", async () => {
    const a = await invocar(app, "get", "/api/vulnerabilidades/enriquecimiento", { user: con("lector") });
    assert.equal(a.res.statusCode, 200); assert.equal(a.res.cuerpo.puede_actualizar, false);
    const s = await invocar(app, "get", "/api/vulnerabilidades/enriquecimiento", { user: con("admin") });
    assert.equal(s.res.cuerpo.puede_actualizar, true);
  });

  test("las rutas fijas van antes que /:id (no las captura la ficha)", () => {
    const orden = app.rutas.map((r) => `${r.metodo} ${r.ruta}`);
    for (const [m, ruta] of [["put", "/api/vulnerabilidades/plazos"], ["put", "/api/vulnerabilidades/plazos/global"], ["get", "/api/vulnerabilidades/metricas"]]) {
      const i = orden.indexOf(`${m} ${ruta}`), id = orden.indexOf(`${m} /api/vulnerabilidades/:id`);
      assert.ok(i >= 0 && (id < 0 || i < id), `${m} ${ruta}`);
    }
  });
});
