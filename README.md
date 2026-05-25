[![Español](https://img.shields.io/badge/lang-es-blue)](README.es.md)

<div align="center">
  <img src="logo.png" alt="Gungnir Logo" width="600"/>

  # Gungnir Community — Offensive Security Manager

  **Full-lifecycle pentest management platform — free and open source**

  *Powered by [AllSafe Security Solutions](https://www.allsafe.com.ar)*

  ![Node.js](https://img.shields.io/badge/Node.js-20+-339933?style=flat-square&logo=node.js&logoColor=white)
  ![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)
  ![MySQL](https://img.shields.io/badge/MySQL-8.0+-4479A1?style=flat-square&logo=mysql&logoColor=white)
  ![License](https://img.shields.io/badge/License-AGPL--3.0-blue?style=flat-square)
  ![Version](https://img.shields.io/badge/Version-Community-blue?style=flat-square)
</div>

---

Gungnir Community is a free, open-source pentest management platform that covers the entire engagement lifecycle — from client intake to PDF report delivery.

> The name comes from Gungnir — Odin's spear in Norse mythology. Forged by the dwarves of Nidavellir, it never misses its target. A symbol of precision and unstoppable force.

---

## What is Gungnir Community?

Gungnir Community includes everything a pentest team needs to run professional engagements:

- **Full engagement lifecycle** — clients, phases (Planning → Recon → Scanning → Exploitation → Post-Exploitation → Reporting), operation logs, scope management, evidence uploads, MITRE ATT&CK mapping
- **Finding editor** with CVSS 3.1 visual calculator, CWE + OWASP classification, and status tracking
- **CVE auto-populate** — enter a CVE ID and Gungnir auto-fills CVSS vector, score, description and CWE from the NVD API
- **PDF pentest report** — professional output with executive and technical sections
- **XML import** — import findings from Nessus (.nessus), Burp Suite (.xml), OpenVAS (.xml) and Nmap (-oX .xml) directly into any engagement phase
- **Command arsenal** — 2,200+ searchable pentest commands (Recon, Web, Network, Active Directory, Post-Exploitation, Evasion and more)
- **Finding templates** — 15 built-in templates (SQLi, XSS, CSRF, SSRF, XXE, RCE, path traversal, default credentials, open redirect, etc.) + custom library
- **OSINT / Recon** — Shodan, VirusTotal, Censys, crt.sh, RDAP, DNS using your own API keys (no vendor lock-in)
- **Notes** — personal markdown notes with tag system, pin support and note sharing between users
- **Auth** — JWT (12h), TOTP 2FA (RFC 6238), account lockout, role-based access
- **Internationalization** — Spanish (default) and English, switchable per user

> Looking for **live Nessus/OpenVAS scanner feeds**, **AllSafe CRM sync**, or the **executive Operations dashboard**? Those features are available in [Gungnir Pro](https://www.allsafe.com.ar).

---

## Community vs Pro

| Feature | Community | Pro |
|---|:---:|:---:|
| Client management | ✅ | ✅ |
| Engagement lifecycle (phases, logs, scope, evidence) | ✅ | ✅ |
| Finding editor (CVSS 3.1, CWE, OWASP, MITRE) | ✅ | ✅ |
| PDF pentest report | ✅ | ✅ |
| XML import (Nessus, Burp, OpenVAS, Nmap) | ✅ | ✅ |
| Command arsenal (2,200+ commands) | ✅ | ✅ |
| Finding templates (15 built-in + custom) | ✅ | ✅ |
| Notes with sharing | ✅ | ✅ |
| OSINT / Recon (Shodan, VirusTotal, Censys, crt.sh, DNS) | ✅ | ✅ |
| CVE auto-populate (NVD) | ✅ | ✅ |
| TOTP 2FA + account lockout | ✅ | ✅ |
| Roles: admin / auditor / pentester | ✅ | ✅ |
| i18n: Spanish + English | ✅ | ✅ |
| Audit log | ✅ | ✅ |
| Nessus live scan feed | ❌ | ✅ |
| OpenVAS live task feed | ❌ | ✅ |
| AllSafe CRM sync | ❌ | ✅ |
| Operations dashboard (exec metrics, charts) | ❌ | ✅ |
| Custom PDF branding + org logo | ❌ | ✅ |

> **Upgrade path**: Community and Pro share the same database schema. Upgrading is a file replacement — no migrations needed.

---

## Screenshots

<div align="center">

**Dashboard**
<br/>
<img src="screenshots/1-dashboard.png" alt="Dashboard" width="900"/>

<br/><br/>

| **Finding Editor** | **PDF Report** |
|:---:|:---:|
| <img src="screenshots/2-editor-hallazgos.png" alt="Finding Editor" width="440"/> | <img src="screenshots/4-reportes.png" alt="PDF Report" width="440"/> |

</div>

---

## Key Features

### Engagement Lifecycle
- **Client management** — company, industry, contact, engagement history
- **Engagements** — full lifecycle with structured phases: Planning → Recon → Scanning → Exploitation → Post-Exploitation → Reporting
- **Operation logs** — timestamped command/tool logs per phase, with target, tool, command and notes
- **Scope management** — in-scope/out-of-scope assets with annotations
- **Evidence uploads** — file attachments per engagement
- **MITRE ATT&CK mapping** — techniques linked directly to the engagement

### Findings
- **Full finding editor** with severity (Critical/High/Medium/Low/Info), status tracking, affected asset, description, steps to reproduce, and executive summary
- **CVSS 3.1 visual calculator** — interactive vector builder (AV/AC/PR/UI/S/C/I/A), score computed in real time
- **CWE + OWASP mapping** — per finding classification
- **MITRE tactic + technique** — mapped at the finding level
- **Business risk + exploitability** assessment fields
- **CVE auto-populate** — enter a CVE ID, Gungnir queries the NVD API and auto-fills CVSS vector, score, description, and CWE
- **Finding templates** — 15 built-in templates + custom library

### Reports
- **PDF generation** — pentest report with executive and technical sections
- **Per-operator logo** — uploadable from profile settings

### Arsenal & Reference
- **Command library** — 2,200+ categorized, searchable pentest commands
- **Script manager** — store and organize custom scripts
- **Library** — reference resources and documentation
- **Writeups** — vulnerability writeup management
- **Techniques browser** — searchable MITRE-style technique reference
- **Notes** — personal markdown notes with tag system, pin support, and read-only formatted viewer; optionally linked to a specific engagement; shareable with other users

### Scanner XML Import
Import findings from scanner output files directly into any engagement phase:

| Scanner | Format | Severity mapping |
|---------|--------|-----------------|
| Nessus | `.nessus` (XML) | Plugin severity 0–4 → info/low/medium/high/critical |
| Burp Suite | `.xml` | Issue severity string → mapped |
| OpenVAS | `.xml` | CVSS base score → severity bucket |
| Nmap | `-oX .xml` | Per-port heuristic → info default |

### OSINT / Recon
- **Shodan** — IP intelligence, open ports, CVEs, geolocation
- **VirusTotal** — domain/IP reputation and threat intel
- **Censys** — certificate and infrastructure data
- **crt.sh** — certificate transparency subdomain enumeration
- **RDAP** — domain registration and ownership data
- **DNS** — A, MX, NS, TXT, CNAME resolution

### Security & Auth
- **JWT** — 12h expiry, `token_version` revocation on password change or user disable
- **TOTP 2FA** — RFC 6238, setup via QR code, disable with confirmation
- **Account lockout** — 5 failed attempts → 15-minute lockout, persisted in DB (survives restarts)
- **Role-based access** — `admin` / `auditor` / `pentester` with fine-grained route guards
- **Audit log** — all create/update/delete/import actions logged with user, IP, and timestamp
- **OWASP Top 10 2021** — fully compliant, 100% parameterized queries, no injection vectors

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js + Express (single-file, fast startup) |
| Frontend | React 18 + Vite + TanStack Router |
| UI | shadcn/ui + Tailwind CSS v4 |
| State | Zustand (auth) + TanStack Query (server state) |
| Charts | Recharts |
| Database | MariaDB / MySQL 8.0+ |
| Auth | JWT + bcryptjs + pure-JS TOTP (RFC 6238) |
| PDF | jsPDF + html2canvas |
| File upload | multer (evidence, scanner XML, logos) |
| i18n | react-i18next |

---

## Installation

### Option A — Install script (recommended for Linux servers)

```bash
git clone https://github.com/allsafe-ar/gungnir-community.git
cd gungnir-community
chmod +x install.sh && sudo ./install.sh
```

Tested on Ubuntu 22.04 / 24.04 and Debian 12. Installs Node.js, MySQL, nginx and PM2 automatically.

### Option B — Docker

```bash
git clone https://github.com/allsafe-ar/gungnir-community.git
cd gungnir-community
cp backend/.env.example backend/.env
# Edit backend/.env: set DB_PASSWORD and JWT_SECRET
docker compose up -d
```

### Option C — Manual

```bash
# Backend
cd backend
npm install
cp .env.example .env
# Edit .env: DB credentials + strong JWT_SECRET (min 32 chars)
npm start

# Frontend
cd frontend
npm install
npm run build   # Production build → dist/
```

Default credentials (first run): `admin` / `admin123` — **change immediately**.

---

## Architecture

```
gungnir-community/
├── backend/
│   ├── server.js              # Single-file Express backend
│   ├── integrations/
│   │   ├── recon.js           # OSINT integrations (Shodan, VT, Censys, etc.)
│   │   └── http.js            # HTTP helper
│   ├── package.json
│   └── .env.example
└── frontend/
    ├── src/
    │   ├── features/          # One directory per feature domain
    │   ├── routes/            # TanStack Router file-based routing
    │   ├── components/        # Shared UI components + layout
    │   ├── stores/            # Zustand auth store
    │   ├── lib/               # API client, PDF generation, utilities
    │   └── locales/           # es.json + en.json
    └── ...
```

---

## Roles

| Role | Capabilities |
|------|-------------|
| `admin` | Full access — users, settings, all engagements, API keys |
| `auditor` | Create and manage engagements, findings, import scans — no user management |
| `pentester` | Operate within assigned engagements — create findings, logs, evidence |

---

## Legal Notice

Gungnir is designed exclusively for use in authorized environments: professional pentest engagements, Red Team exercises, security audits and CTF competitions — always with explicit written authorization from the system owner.

Using offensive security tools against systems without authorization is illegal in most jurisdictions. AllSafe Security Solutions and the authors of this platform assume no responsibility for unauthorized or unlawful use. The operator is solely responsible for ensuring the corresponding authorization before conducting any security assessment.

---

## Author

Created by **Eduardo Emiliano Alaniz** ([@h4wkby73](https://github.com/h4wkby73))
[AllSafe Security Solutions](https://www.allsafe.com.ar)

---

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE) file.

If you modify and deploy Gungnir Community as a service, you must publish your modifications under the same license.

---

## Security

Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md).

---

<div align="center">
  <sub>Powered by <a href="https://www.allsafe.com.ar">AllSafe Security Solutions</a></sub>
</div>
