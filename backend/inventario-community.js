"use strict";
/**
 * Adaptador de Gungnir Community para el módulo único de activos (`inventario/`, copia del canónico
 * de `utiles/activos`, el mismo de Gungnir Pro, Skuld y Gjallarhorn). Acá va SOLO lo propio de
 * Gungnir Community: de quién es cada activo, quién puede qué y lo que cuelga del activo (las
 * vulnerabilidades del seguimiento continuo).
 *
 * 🔑 **La organización del inventario es el CLIENTE**, igual que en Gungnir Pro: `activos.tenant_id`
 * guarda `clients.id`. Los activos son de la organización que se audita, no de quien audita. Así el
 * esquema es el mismo en las dos ediciones y una instalación pasa a Pro sin mover nada.
 *
 * Community es on-premise y de una sola organización: no hay inquilinos, así que cualquier persona
 * con sesión ve los clientes de la instalación (como en el listado de clientes). Los permisos van por
 * rol, con la misma regla que Pro. Los avisos por correo de vencimientos y la sincronización con
 * otros sistemas son de la edición Pro.
 *
 * ⚠️ El contrato del módulo pide `alcance` y `permite` sincrónicos: cada cadena de middlewares
 * termina en `cargarClientes`, que deja en el pedido los clientes de la instalación.
 *
 * Cómo se monta en el server.js:
 *
 *   inventarioCommunity.montar(app, { auth, auditLog, qRow, qRows, qRun, alFusionar });
 *   ...
 *   await inventarioCommunity.prepararEsquema({ qRows, qRun });   // en initDB, con `clients` creada
 */
const { v4: uuidv4 } = require("uuid");
const inventario = require("./inventario/inventario");
const esquema = require("./inventario/esquema");

/** Roles de Gungnir: el lector solo mira; cargar y editar es de quien trabaja; borrar, importar y fusionar, de quien conduce. */
const ROLES_EDITAR = ["admin", "auditor", "pentester"];
const ROLES_ADMINISTRAR = ["admin", "auditor"];

/** Middleware: deja en `req.clientesVisibles` los clientes de la instalación (id -> inquilino, nulo en Community). */
function cargadorDeClientes({ qRows }) {
  return async (req, res, next) => {
    try {
      const filas = await qRows("SELECT id FROM clients");
      req.clientesVisibles = new Map(filas.map((f) => [f.id, null]));
      next();
    } catch (e) {
      console.error("[inventario] clientes:", e.message);
      res.status(500).json({ error: "No se pudo resolver la organización." });
    }
  };
}

/** El cliente llega en `?cliente=` (o en el cuerpo). Sin un cliente que exista no hay alcance: 403. */
function clienteDelPedido(req) {
  const c = String(req.query?.cliente || req.body?.cliente || "").trim();
  return c && req.clientesVisibles?.has(c) ? c : null;
}

function alcanceCommunity(req) {
  const cliente = clienteDelPedido(req);
  if (!cliente) return null;
  return { tenant: cliente, clause: " AND tenant_id = ?", params: [cliente] };
}

function permiteCommunity(req, tenantId) {
  return !!tenantId && !!req.clientesVisibles?.has(tenantId);
}

function middlewares({ auth, qRows }) {
  const cargar = cargadorDeClientes({ qRows });
  return {
    leer: [auth(), cargar],
    editar: [auth(ROLES_EDITAR), cargar],
    borrar: [auth(ROLES_ADMINISTRAR), cargar],
    administrar: [auth(ROLES_ADMINISTRAR), cargar],
  };
}

function montar(app, deps) {
  const faltan = ["auth", "auditLog", "qRow", "qRows", "qRun"].filter((k) => !deps[k]);
  if (faltan.length) throw new Error(`inventario-community.montar: faltan dependencias: ${faltan.join(", ")}`);
  const { auditLog, qRow, qRows, qRun } = deps;
  const mw = middlewares(deps);
  const dep = {
    qRow, qRows, qRun, uuidv4, sistema: "Gungnir", mw,
    alcance: (req) => alcanceCommunity(req),
    permite: (req, tenantId) => permiteCommunity(req, tenantId),
    usuario: (req) => req.user?.username,
    auditar: (req, accion, detalle) => auditLog(req.user?.id, req.user?.username, String(accion).toLowerCase(), "activos", null, detalle, req.ip),
    // Para elegir propietario: las personas activas de la instalación.
    personas: async () => qRows(
      "SELECT id, COALESCE(NULLIF(full_name,''), username) AS nombre, email AS correo FROM users WHERE is_active = 1 ORDER BY nombre").catch(() => []),
    // Las vulnerabilidades son historia del equipo: al unir dos activos pasan al que queda.
    alFusionar: deps.alFusionar,
    // La sincronización con otros sistemas es de la edición Pro.
    sincronizacion: false,
  };
  inventario.montar(app, dep);
  return { dep, mw };
}

/** Tablas del inventario, con `tenant_id` apuntando a `clients(id)` y borrado en cascada (como Pro). */
async function prepararEsquema({ qRows, qRun }) {
  await esquema.crearTablas({ qRun, qRows }, { fkTenant: "clients(id)" });
}

module.exports = { montar, prepararEsquema, middlewares, cargadorDeClientes, alcanceCommunity, permiteCommunity, clienteDelPedido, ROLES_EDITAR, ROLES_ADMINISTRAR };
