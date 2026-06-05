# Changelog

All notable changes to Gungnir Community are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); versioning follows [SemVer](https://semver.org/).

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
