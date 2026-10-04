"use strict";
/**
 * Notificaciones de hallazgos — aviso por correo y/o webhook cuando entra un hallazgo
 * de severidad relevante.
 *
 * La configuración vive en `settings` bajo la clave `notificaciones` (JSON):
 *   { email_enabled, email_to, webhook_enabled, webhook_url, min_severity }
 * `min_severity` es el piso: 'critical' avisa solo de críticos, 'high' de altos y críticos, etc.
 *
 * El disparo es best-effort y NO corta el alta del hallazgo: si el correo o el webhook fallan,
 * se registra en el log y la petición sigue su curso. Un aviso que rompe la carga sería peor
 * que un aviso perdido.
 *
 * Cómo se monta:
 *   notificaciones.montar(app, { auth, staffOnly, qRow, qRun, auditLog });
 *   const notificador = notificaciones.crear({ qRow, correo, leerConfigSMTP, rutaLogo, urlBase });
 *   // en el alta de hallazgo: notificador.avisarHallazgo(finding, engagement).catch(()=>{})
 */
const { httpRequest } = require("./integrations/http");
const netGuard = require("./integrations/net-guard");

const ORDEN_SEV = ["info", "low", "medium", "high", "critical"];
const SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Medio", low: "Bajo", info: "Informativo" };
const CLAVE = "notificaciones";

function leerConfig(qRow) {
  return qRow("SELECT `value` FROM settings WHERE `key`=?", [CLAVE])
    .then(row => {
      const base = { email_enabled: false, email_to: "", webhook_enabled: false, webhook_url: "", min_severity: "high" };
      if (!row?.value) return base;
      try { return { ...base, ...JSON.parse(row.value) }; } catch { return base; }
    })
    .catch(() => ({ email_enabled: false, email_to: "", webhook_enabled: false, webhook_url: "", min_severity: "high" }));
}

/** Alcanza el piso de severidad configurado. */
function superaPiso(sev, piso) {
  const i = ORDEN_SEV.indexOf(String(sev || "").toLowerCase());
  const p = ORDEN_SEV.indexOf(String(piso || "high").toLowerCase());
  return i >= 0 && p >= 0 && i >= p;
}

// ── Fábrica del notificador ─────────────────────────────────────────────────────
function crear({ qRow, correo, leerConfigSMTP, rutaLogo, urlBase }) {
  async function avisarHallazgo(finding, engagement) {
    if (!finding) return;
    const cfg = await leerConfig(qRow);
    if (!superaPiso(finding.severity, cfg.min_severity)) return;

    const sevTxt = SEV_LABEL[finding.severity] || finding.severity;
    const engNombre = engagement?.name || finding.engagement_id;
    const link = `${String(urlBase || "").replace(/\/+$/, "")}/engagements/${finding.engagement_id}`;

    // ── Correo ──
    if (cfg.email_enabled && cfg.email_to) {
      try {
        const smtp = await leerConfigSMTP();
        await correo.enviar(smtp, {
          para: cfg.email_to,
          asunto: `[Gungnir] Hallazgo ${sevTxt}: ${finding.title}`,
          titulo: `Nuevo hallazgo ${sevTxt}`,
          parrafos: [
            `Se registró un hallazgo de severidad <strong>${sevTxt}</strong> en el engagement <strong>${engNombre}</strong>.`,
            finding.affected_asset ? `Activo afectado: ${finding.affected_asset}` : "",
            finding.title,
          ].filter(Boolean),
          boton: { texto: "Ver el engagement", url: link },
          pie: "Aviso automático de Gungnir.",
          rutaLogo,
        });
      } catch (e) { console.error("[notificaciones] correo:", e.message); }
    }

    // ── Webhook ──
    if (cfg.webhook_enabled && cfg.webhook_url) {
      try {
        // SSRF: se valida resolviendo el DNS y se prohíben las redirecciones (http.js las
        // seguiría sin volver a chequear el destino).
        const permiso = await netGuard.urlPermitidaResuelta(cfg.webhook_url, [], { sinExcepciones: true });
        if (!permiso.permitida) { console.error("[notificaciones] webhook bloqueado:", permiso.motivo); return; }
        const payload = {
          source: "gungnir",
          event: "finding.created",
          severity: finding.severity,
          title: finding.title,
          engagement: engNombre,
          engagement_id: finding.engagement_id,
          affected_asset: finding.affected_asset || null,
          url: link,
          at: new Date().toISOString(),
        };
        const r = await httpRequest(cfg.webhook_url, { method: "POST", body: payload, timeout: 8000, maxRedirects: 0 });
        if (r.status >= 400) console.error("[notificaciones] webhook respondió", r.status);
      } catch (e) { console.error("[notificaciones] webhook:", e.message); }
    }
  }
  return { avisarHallazgo };
}

// ── Rutas de configuración (solo staff global) ───────────────────────────────────
function montar(app, deps) {
  const faltan = ["auth", "staffOnly", "qRow", "qRun", "auditLog"].filter((k) => typeof deps[k] === "undefined");
  if (faltan.length) throw new Error(`notificaciones.montar: faltan dependencias: ${faltan.join(", ")}`);
  const { auth, staffOnly, qRow, qRun, auditLog } = deps;

  app.get("/api/settings/notifications", auth(["admin"]), async (req, res) => {
    if (!staffOnly(req, res)) return;
    res.json(await leerConfig(qRow));
  });

  app.put("/api/settings/notifications", auth(["admin"]), async (req, res) => {
    if (!staffOnly(req, res)) return;
    const b = req.body || {};
    const min = ORDEN_SEV.includes(String(b.min_severity)) ? b.min_severity : "high";
    // Antes de guardar, un webhook habilitado tiene que apuntar a un destino permitido.
    if (b.webhook_enabled && b.webhook_url) {
      const permiso = await netGuard.urlPermitidaResuelta(String(b.webhook_url), [], { sinExcepciones: true });
      if (!permiso.permitida) return res.status(400).json({ error: `URL de webhook no permitida: ${permiso.motivo}` });
    }
    const cfg = {
      email_enabled: !!b.email_enabled,
      email_to: String(b.email_to || "").slice(0, 300),
      webhook_enabled: !!b.webhook_enabled,
      webhook_url: String(b.webhook_url || "").slice(0, 500),
      min_severity: min,
    };
    await qRun(
      "INSERT INTO settings (`key`,`value`) VALUES (?,?) ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)",
      [CLAVE, JSON.stringify(cfg)]
    );
    auditLog(req.user.id, req.user.username, "update_notifications", "settings", CLAVE, `email=${cfg.email_enabled} webhook=${cfg.webhook_enabled} min=${cfg.min_severity}`, req.ip);
    res.json(cfg);
  });

  return {};
}

module.exports = { montar, crear, superaPiso };
