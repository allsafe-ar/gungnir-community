# Changelog

All notable changes to Gungnir Community are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); versioning follows [SemVer](https://semver.org/).

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
