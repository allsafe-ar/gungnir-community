[![English](https://img.shields.io/badge/lang-en-blue)](README.md)

<div align="center">
  <img src="logo.png" alt="Gungnir Logo" width="600"/>

  # Gungnir Community - Offensive Security Manager

  **Plataforma de gestión del ciclo de vida de pentesting - libre y open source**

  *Powered by [AllSafe Security Solutions](https://www.allsafe.com.ar)*

  ![Node.js](https://img.shields.io/badge/Node.js-20+-339933?style=flat-square&logo=node.js&logoColor=white)
  ![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)
  ![MySQL](https://img.shields.io/badge/MySQL-8.0+-4479A1?style=flat-square&logo=mysql&logoColor=white)
  ![License](https://img.shields.io/badge/License-AGPL--3.0-blue?style=flat-square)
  ![Version](https://img.shields.io/badge/Version-Community-blue?style=flat-square)

  [![Sitio web](https://img.shields.io/badge/Sitio_web-allsafe.com.ar%2Fgungnir--community-ff3131?style=for-the-badge&labelColor=1e324d)](https://allsafe.com.ar/gungnir-community/)
</div>

---

Gungnir Community es una plataforma de gestión de pentesting libre y open source que cubre todo el ciclo de vida del engagement - desde el onboarding del cliente hasta la entrega del informe PDF.

> El nombre proviene de Gungnir, la lanza de Odín en la mitología nórdica. Forjada por los enanos de Nidavellir, nunca falla su objetivo. Un símbolo de precisión y fuerza imparable.

---

## ¿Qué es Gungnir Community?

Gungnir Community incluye todo lo que un equipo de pentesting necesita para ejecutar engagements profesionales:

- **Ciclo de vida completo del engagement** - clientes, fases (Planificación → Reconocimiento → Escaneo → Explotación → Post-Explotación → Reporte), operation logs, gestión de scope, carga de evidencias, mapeo MITRE ATT&CK
- **Editor de hallazgos** con calculadora visual CVSS 3.1, clasificación CWE + OWASP y seguimiento de estado
- **Auto-populate por CVE** - ingresá un CVE ID y Gungnir completa automáticamente el vector CVSS, score, descripción y CWE desde la API de NVD
- **Reporte PDF de pentesting** - salida profesional con secciones ejecutiva y técnica
- **Importación XML** - importar hallazgos desde Nessus (.nessus), Burp Suite (.xml), OpenVAS (.xml) y Nmap (-oX .xml) directamente en cualquier fase del engagement
- **Arsenal de comandos** - 2.300+ comandos de pentesting buscables (Recon, Web, Network, Active Directory, Post-Explotación, Evasión y más) - incluye tshark, searchsploit, smbmap, wes-ng, técnicas SysNative Windows y más
- **Templates de hallazgos** - 15 templates preconfigurados (SQLi, XSS, CSRF, SSRF, XXE, RCE, path traversal, credenciales por defecto, open redirect, etc.) + biblioteca personalizada
- **OSINT / Recon** - Shodan, VirusTotal, Censys, crt.sh, RDAP, DNS usando tus propias API keys (sin vendor lock-in)
- **Notas** - notas personales en markdown con sistema de tags, pin y compartir entre usuarios
- **Auth** - JWT (12h), TOTP 2FA (RFC 6238), lockout de cuenta, control de acceso por rol
- **Internacionalización** - Español (por defecto) e Inglés, configurable por usuario

> ¿Buscás **feeds de scanners Nessus/OpenVAS en vivo**, **sincronización con CRM AllSafe**, el **dashboard de Operaciones ejecutivo** o el **browser de papers de investigación Exploit-DB**? Esas funcionalidades están disponibles en [Gungnir Pro](https://www.allsafe.com.ar).

---

## Community vs Pro

| Funcionalidad | Community | Pro |
|---|:---:|:---:|
| Gestión de clientes | ✅ | ✅ |
| Ciclo de vida del engagement (fases, logs, scope, evidencias) | ✅ | ✅ |
| Editor de hallazgos (CVSS 3.1, CWE, OWASP, MITRE) | ✅ | ✅ |
| Reporte PDF de pentesting | ✅ | ✅ |
| Importación XML (Nessus, Burp, OpenVAS, Nmap) | ✅ | ✅ |
| Arsenal de comandos (2.300+ comandos) | ✅ | ✅ |
| Templates de hallazgos (15 built-in + personalizados) | ✅ | ✅ |
| Notas con compartir | ✅ | ✅ |
| OSINT / Recon (Shodan, VirusTotal, Censys, crt.sh, DNS) | ✅ | ✅ |
| Auto-populate por CVE (NVD) | ✅ | ✅ |
| TOTP 2FA + lockout de cuenta | ✅ | ✅ |
| Roles: admin / auditor / pentester | ✅ | ✅ |
| i18n: Español + Inglés | ✅ | ✅ |
| Audit log | ✅ | ✅ |
| Feed de scans Nessus en vivo | ❌ | ✅ |
| Feed de tareas OpenVAS en vivo | ❌ | ✅ |
| Sync CRM AllSafe | ❌ | ✅ |
| Dashboard de Operaciones (métricas ejecutivas, gráficos) | ❌ | ✅ |
| Branding PDF personalizado + logo de organización | ❌ | ✅ |
| Browser de papers de investigación Exploit-DB | ❌ | ✅ |

> **Upgrade path**: Community y Pro comparten el mismo esquema de base de datos. Actualizar es un reemplazo de archivos - sin migraciones necesarias.

---

## Screenshots

<div align="center">

**Dashboard**
<br/>
<img src="screenshots/1-dashboard.png" alt="Dashboard" width="900"/>

<br/><br/>

| **Editor de Hallazgos** | **Reporte PDF** |
|:---:|:---:|
| <img src="screenshots/2-editor-hallazgos.png" alt="Editor de Hallazgos" width="440"/> | <img src="screenshots/4-reportes.png" alt="Reporte PDF" width="440"/> |

</div>

---

## Características principales

### Ciclo de vida del Engagement
- **Gestión de clientes** - empresa, industria, contacto, historial de engagements
- **Engagements** - ciclo de vida completo con fases estructuradas: Planificación → Reconocimiento → Escaneo → Explotación → Post-Explotación → Reporte
- **Operation logs** - registro con timestamp de comandos/herramientas por fase, con objetivo, herramienta, comando y notas
- **Gestión de scope** - activos en scope/out-of-scope con anotaciones
- **Carga de evidencias** - adjuntos de archivos por engagement
- **Mapeo MITRE ATT&CK** - técnicas vinculadas directamente al engagement

### Hallazgos
- **Editor completo de hallazgos** con severidad (Crítico/Alto/Medio/Bajo/Info), seguimiento de estado, activo afectado, descripción, pasos para reproducir y resumen ejecutivo
- **Calculadora visual CVSS 3.1** - constructor interactivo de vector (AV/AC/PR/UI/S/C/I/A), score calculado en tiempo real
- **Mapeo CWE + OWASP** - clasificación por hallazgo
- **Táctica + técnica MITRE** - mapeadas a nivel de hallazgo
- **Campos de riesgo de negocio y explotabilidad**
- **Auto-populate por CVE** - ingresá un CVE ID, Gungnir consulta la API de NVD y completa automáticamente el vector CVSS, score, descripción y CWE
- **Templates de hallazgos** - 15 templates preconfigurados + biblioteca personalizada

### Reportes
- **Generación de PDF** - reporte de pentesting con secciones ejecutiva y técnica
- **Logo por operador** - subible desde la configuración de perfil

### Arsenal & Referencia
- **Biblioteca de comandos** - 2.200+ comandos de pentesting categorizados y buscables
- **Gestor de scripts** - almacená y organizá scripts propios
- **Biblioteca** - recursos de referencia y documentación interna
- **Writeups** - gestión de writeups de vulnerabilidades
- **Técnicas** - browser de técnicas ofensivas con mapeo MITRE
- **Notas** - notas personales en markdown con sistema de tags, pin y visor read-only con renderizado formateado; vinculables a un engagement; compartibles entre usuarios

### Importación XML de Scanners
Importar hallazgos desde archivos de salida de scanners directamente en cualquier fase del engagement:

| Scanner | Formato | Mapeo de severidad |
|---------|---------|-------------------|
| Nessus | `.nessus` (XML) | Plugin severity 0–4 → info/low/medium/high/critical |
| Burp Suite | `.xml` | String de severidad → mapeado |
| OpenVAS | `.xml` | Score base CVSS → bucket de severidad |
| Nmap | `-oX .xml` | Heurística por puerto → info por defecto |

### OSINT / Recon
- **Shodan** - inteligencia de IPs, puertos abiertos, CVEs, geolocalización
- **VirusTotal** - reputación de dominios/IPs e inteligencia de amenazas
- **Censys** - datos de certificados e infraestructura
- **crt.sh** - enumeración de subdominios por certificate transparency
- **RDAP** - registro de dominio y datos de propietario
- **DNS** - resolución de registros A, MX, NS, TXT, CNAME

### Seguridad & Auth
- **JWT** - expiración 12h, revocación por `token_version` al cambiar contraseña o deshabilitar usuario
- **TOTP 2FA** - RFC 6238, setup via código QR, deshabilitable con confirmación
- **Lockout de cuenta** - 5 intentos fallidos → bloqueo de 15 minutos, persistido en DB (sobrevive reinicios)
- **Control de acceso por rol** - `admin` / `auditor` / `pentester` con guards de rutas granulares
- **Audit log** - todas las acciones de creación/modificación/eliminación/importación registradas con usuario, IP y timestamp
- **OWASP Top 10 2021** - completamente cumplido, 100% queries parametrizadas, sin vectores de inyección

---

## Stack tecnológico

| Capa | Tecnología |
|------|-----------|
| Backend | Node.js + Express (single-file, arranque rápido) |
| Frontend | React 18 + Vite + TanStack Router |
| UI | shadcn/ui + Tailwind CSS v4 |
| State | Zustand (auth) + TanStack Query (server state) |
| Gráficos | Recharts |
| Base de datos | MariaDB / MySQL 8.0+ |
| Auth | JWT + bcryptjs + TOTP puro JS (RFC 6238) |
| PDF | jsPDF + html2canvas |
| File upload | multer (evidencias, XML de scanners, logos) |
| i18n | react-i18next |

---

## Instalación

### Opción A - Script de instalación (recomendado para servidores Linux)

```bash
git clone https://github.com/allsafe-ar/gungnir-community.git
cd gungnir-community
chmod +x install.sh && sudo ./install.sh
```

Probado en Ubuntu 22.04 / 24.04 y Debian 12. Instala Node.js, MySQL, nginx y PM2 automáticamente.

### Opción B - Docker

```bash
git clone https://github.com/allsafe-ar/gungnir-community.git
cd gungnir-community
cp backend/.env.example backend/.env
# Editá backend/.env: configurá DB_PASSWORD y JWT_SECRET
docker compose up -d
```

### Opción C - Manual

```bash
# Backend
cd backend
npm install
cp .env.example .env
# Editá .env: credenciales de DB + JWT_SECRET fuerte (mín. 32 caracteres)
npm start

# Frontend
cd frontend-shadcn
npm install
npm run build   # Build de producción → dist/
```

Credenciales por defecto (primer arranque): `admin` / `admin123` - **cambiar inmediatamente**.

---

## Arquitectura

```
gungnir-community/
├── backend/
│   ├── server.js              # Backend Express single-file
│   ├── integrations/
│   │   ├── recon.js           # Integraciones OSINT (Shodan, VT, Censys, etc.)
│   │   └── http.js            # Helper HTTP
│   ├── package.json
│   └── .env.example
└── frontend-shadcn/
    ├── src/
    │   ├── features/          # Un directorio por dominio de feature
    │   ├── routes/            # Routing file-based con TanStack Router
    │   ├── components/        # Componentes UI compartidos + layout
    │   ├── stores/            # Zustand auth store
    │   ├── lib/               # API client, generación PDF, utilidades
    │   └── locales/           # es.json + en.json
    └── ...
```

---

## Roles

| Rol | Capacidades |
|-----|------------|
| `admin` | Acceso total - usuarios, configuración, todos los engagements, API keys |
| `auditor` | Crear y gestionar engagements y hallazgos, importar scans - sin gestión de usuarios |
| `pentester` | Operar dentro de los engagements asignados - crear hallazgos, logs, evidencias |

---

## Aviso Legal

Gungnir está diseñado exclusivamente para su uso en entornos autorizados: engagements de pentesting profesionales, ejercicios Red Team, auditorías de seguridad y competencias CTF - siempre con autorización escrita explícita del propietario del sistema.

El uso de herramientas de seguridad ofensiva contra sistemas sin autorización es ilegal en la mayoría de las jurisdicciones. AllSafe Security Solutions y los autores de esta plataforma no asumen ninguna responsabilidad por el uso no autorizado o ilícito. El operador es el único responsable de garantizar la autorización correspondiente antes de realizar cualquier evaluación de seguridad.

---

## Autor

Creado por **Eduardo Emiliano Alaniz** ([@h4wkby73](https://github.com/h4wkby73))
[AllSafe Security Solutions](https://www.allsafe.com.ar)

---

## Aviso de Marca Registrada

Los nombres "AllSafe", "AllSafe Security Solutions", "Gungnir" y todos los logos asociados son marcas comerciales de AllSafe Security Solutions. La licencia AGPL-3.0 que cubre este software no otorga ningun derecho sobre estas marcas o logos. No podés usarlos para identificar, respaldar ni promover productos derivados de este software sin autorización previa y por escrito de AllSafe Security Solutions.

---

## Licencia

GNU Affero General Public License v3.0 - ver archivo [LICENSE](LICENSE).

Si modificás y desplegás Gungnir Community como servicio, debés publicar tus modificaciones bajo la misma licencia.

---

## Seguridad

¿Encontraste una vulnerabilidad? Por favor reportala de forma privada - ver [SECURITY.md](SECURITY.md).

---

<div align="center">
  <sub>Powered by <a href="https://www.allsafe.com.ar">AllSafe Security Solutions</a></sub>
</div>
