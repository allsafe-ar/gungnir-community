/**
 * Envío de correo de AllSafe. Común a los seis sistemas.
 *
 * Sale del `mailer.js` de Heimdall, que era el único que existía, generalizado
 * para que no dependa de la forma de una alerta. Mantiene el logo embebido por
 * `cid:` (nunca una URL remota, que los clientes de correo bloquean) y el navy
 * de los informes PDF.
 *
 * Config esperada: { host, port, secure, user, pass, from, sistema }
 */
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const LOGO_CID = "allsafe-logo";
const NAVY = "#0f1e50";
const ACENTO = "#0064d2";

function leerLogo(rutaLogo) {
  try { return fs.readFileSync(rutaLogo || path.join(__dirname, "assets", "allsafe-mail.png")); }
  catch { return null; }
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/** Cuerpo HTML genérico: título, párrafos, un botón opcional y un pie. */
function armarHTML({ titulo, parrafos = [], boton, pie }, conLogo) {
  const ps = parrafos.map((p) =>
    `<p style="margin:0 0 14px;font-size:15px;line-height:1.6;color:#333">${p}</p>`).join("");
  const btn = boton
    ? `<table cellpadding="0" cellspacing="0" style="margin:22px 0"><tr><td style="background:${ACENTO};border-radius:6px">
         <a href="${esc(boton.url)}" style="display:inline-block;padding:12px 26px;color:#fff;
            text-decoration:none;font-weight:700;font-size:15px">${esc(boton.texto)}</a></td></tr></table>`
    : "";
  const logo = conLogo
    ? `<img src="cid:${LOGO_CID}" alt="AllSafe Security Solutions" width="150" style="height:auto;width:150px;display:block;border:0">`
    : "";
  return `<!doctype html><html><body style="margin:0;padding:0;background:#f4f6f9">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:28px 12px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:10px;overflow:hidden">
  <tr><td style="background:${NAVY};padding:22px 26px">${logo}</td></tr>
  <tr><td style="padding:28px 26px">
    <h1 style="margin:0 0 18px;font-size:20px;color:${NAVY}">${esc(titulo)}</h1>
    ${ps}${btn}
    ${pie ? `<p style="margin:22px 0 0;font-size:12px;line-height:1.6;color:#777">${pie}</p>` : ""}
  </td></tr>
</table></td></tr></table></body></html>`;
}

function armarTexto({ titulo, parrafos = [], boton, pie }) {
  const limpio = (s) => String(s).replace(/<[^>]+>/g, "");
  return [titulo, "", ...parrafos.map(limpio), boton ? `\n${boton.texto}: ${boton.url}` : "",
          pie ? `\n${limpio(pie)}` : ""].join("\n");
}

function crearTransporte(cfg) {
  if (!cfg?.host || !cfg?.user) throw new Error("SMTP sin configurar");
  return nodemailer.createTransport({
    host: cfg.host,
    port: Number(cfg.port) || 465,
    secure: cfg.secure !== false,
    auth: { user: cfg.user, pass: cfg.pass },
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 20000,
  });
}

/**
 * Envía un correo. ⚠️ A diferencia de las alertas, acá SÍ interesa saber si falló:
 * quien invita tiene que enterarse de que el correo no salió, o queda un usuario
 * esperando un mensaje que nunca llega. Devuelve { ok } o { ok:false, error }.
 */
async function enviar(cfg, { para, asunto, titulo, parrafos, boton, pie, rutaLogo, adjuntos }) {
  try {
    if (!para) return { ok: false, error: "Sin destinatario" };
    const logo = leerLogo(rutaLogo);
    const cuerpo = { titulo, parrafos, boton, pie };
    await crearTransporte(cfg).sendMail({
      from: cfg.from || cfg.user,
      to: para,
      subject: cfg.sistema ? `[${cfg.sistema}] ${asunto}` : asunto,
      // ⚠️ Sin esto Gmail agrupa los correos de asunto igual y colapsa el texto
      // repetido detrás de unos puntos suspensivos, así que el destinatario abre
      // la invitación y no ve ni el botón. Un valor único por mensaje lo evita.
      headers: { "X-Entity-Ref-ID": crypto.randomUUID() },
      text: armarTexto(cuerpo),
      html: armarHTML(cuerpo, !!logo),
      // El logo va inline por cid; `adjuntos` son archivos de verdad, que el destinatario puede
      // guardar. Lo usa el emisor de licencias para mandar el archivo además del texto: pegar
      // desde el cuerpo de un correo corta o agrega espacios, y el síntoma que ve el cliente es
      // "la licencia está dañada", que no apunta a la causa.
      attachments: [
        ...(logo ? [{ filename: "allsafe.png", content: logo, cid: LOGO_CID, contentDisposition: "inline" }] : []),
        ...(Array.isArray(adjuntos) ? adjuntos : []),
      ],
    });
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function probarSMTP(cfg) {
  try { await crearTransporte(cfg).verify(); return { ok: true }; }
  catch (e) { return { ok: false, error: e.message }; }
}

module.exports = { enviar, probarSMTP, armarHTML, armarTexto };
