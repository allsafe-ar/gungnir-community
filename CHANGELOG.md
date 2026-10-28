# Changelog

All notable changes to Gungnir Community are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); versioning follows [SemVer](https://semver.org/).

## [1.3.3] - 2026-10-28

### Security
- `qs` 6.16.2 in the backend (moderate advisory GHSA-6pq8-jhm2-2vcw, denial of service in `qs.stringify`). Back to **0 known vulnerabilities**.
- `install.sh` now requires **Node.js 24.22.1 or later**, the same as the README and `engines`. Before, any 24.x passed the check, including releases without the Brotli fix (CVE-2026-111497). If the installed Node.js is older, it upgrades it from NodeSource and stops with a clear message if it still cannot meet the minimum.

### Fixed
- **Docker: first start no longer restarts the app.** The database healthcheck now checks over TCP. Over the socket it passed while MySQL was still on its temporary first-run server, and the app connected too early and restarted until the real server came up.

## [1.3.2] - 2026-10-24

### Security
- **Node.js 24 LTS.** The Docker image moves from `node:20-alpine` to `node:24-alpine` and the install script sets up Node.js 24. Node.js 20 reached end of life and did not get the October 2026 security fixes (among them a remote code execution in the Brotli decoder). `engines` now asks for 24.22.1 or later.
- **MySQL 8.4 LTS** in `docker-compose.yml` (was 8.0, end of life). An existing data volume is upgraded in place on first start.
- Dependencies back to **0 known vulnerabilities** (backend and frontend, including development tooling): `nodemailer` 9 → 10, `body-parser`, `proxy-addr`, `dompurify`, `follow-redirects`, `fflate`, `zod`, `vite`, `seroval` and build/test tooling within their declared ranges.

### Changed
- README (EN/ES): requirements section, stack versions (Node.js 24, React 19, MySQL 8.4) and version badge brought up to date.

## [1.3.1] - 2026-10-16

### Changed
- Menu ordered by area, with two tones of the system colour and dividers.

## [1.3.0] - 2026-10-04 (flujo del pentest al día con Pro)

Baja a la edición Community el flujo del pentest que se construyó en la segunda vuelta de Pro.

### Added
- **Ciclo de remediación y reprueba (retest)** del hallazgo: fecha límite, reprueba passed/failed/partial, diff de severidad inicial↔retest, aceptación de riesgo con motivo, y resumen de remediación del engagement.
- **Registro de tiempo** por fase y operador, con resumen por fase y por operador.
- **Cobertura de metodología**: checklist OWASP WSTG v4.2 y PTES por engagement, con estado por ítem y % de cobertura.
- **Export de capa MITRE ATT&CK Navigator** de las técnicas del engagement, interoperable con Gjallarhorn.
- **Anotaciones sobre evidencia**: markup de capturas (rectángulos, flechas, trazo) que se guarda como evidencia nueva.
- **Avisos de hallazgos** por correo y/o webhook al superar un piso de severidad, configurables en Configuración. Webhook con validación SSRF. Requiere `nodemailer` y, para el correo, las variables SMTP_* del `.env`.

### Changed
- `/api/health` ahora reporta la versión real desde `package.json`.

## [1.2.1] - 2026-09-22

### Security
- **jsPDF 2.5 → 4.2.1** (and `jspdf-autotable` 5.0.8). The 2.x line carries critical path traversal and HTML injection advisories, and this is the library that builds the reports you hand to a client. Same combination already running in Heimdall and Gjallarhorn, with the same API surface. Verified with a clean `tsc --noEmit` and a full build.
- **adm-zip 0.5.17 → 0.6.1.** Three high advisories, one of them arbitrary file overwrite by following symlinks during extraction, which matters because engagement import takes a ZIP from the user.
- **axios 1.15 → 1.20** (28 advisories, prototype pollution among them) and `@tanstack/react-router` up to date, which clears the critical in `seroval`.
- `express` 4.21.2 → 4.22.3, the first release pinning a `qs` outside the vulnerable range.

### Removed
- **`@clerk/react`**, which was declared and never imported anywhere. A leftover from the shadcn-admin template that was dragging its own vulnerability tree for nothing.

## [1.2.0] - 2026-08-26

### Added
- Product version visible in the app (sidebar footer + login).
- CSV export of findings per engagement, with a button in the engagement workspace.
- Per-user dark/light theme preference persisted in the database.
- Markdown support in findings (description, steps, recommendation) with a per-field live preview.
- New built-in finding templates: Active Directory, IoT and Mobile. Idempotent template seeding.

## [1.1.1] - 2026-06-05

### Security
- `docker-compose.yml` now **requires** `DB_PASSWORD`, `DB_ROOT_PASSWORD` and `JWT_SECRET` (no known default secrets). Added root `.env.example`.

### Changed
- `install.sh`: excludes `.git/`, `node_modules/`, `screenshots/` from `/opt`; optional Let's Encrypt TLS when a real domain is provided.

### Fixed
- README Community/Pro table: moved the **Research Papers** row up alongside the other Community features (was listed below the Pro-only rows).

## [1.1.0]
- Arsenal expanded to 2,300+ commands; Export/Import engagements (ZIP); Community Engagements repository; inline engagement title editing; engagement auto-status.

## [1.0.0]
- Initial public release: full engagement lifecycle, finding editor (CVSS 3.1 / CWE / OWASP / MITRE), PDF reports, scanner XML import, OSINT/recon, JWT + TOTP 2FA + RBAC.
