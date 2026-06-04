# Community Engagements

Esta carpeta contiene engagements de ejemplo compartidos por la comunidad de Gungnir.

## Como importar?

1. Descarga el archivo `.zip` que te interese
2. Abri Gungnir y anda a **Engagements**
3. Hace click en **Importar**
4. Selecciona el `.zip` descargado

El sistema crea automaticamente el engagement con todos sus datos: hallazgos, fases, logs de operaciones, scope y tecnicas. El cliente se reutiliza si ya existe, o se crea uno nuevo.

## Como compartir el tuyo?

1. Desde cualquier engagement, hace click en **Exportar ZIP** en el sidebar
2. Revisa que el ZIP no contenga informacion sensible (credenciales reales, datos de clientes, IPs de produccion)
3. Abri un Pull Request agregando el `.zip` a esta carpeta con una descripcion breve en este README

## Engagements disponibles

| Archivo | Tipo | Descripcion | Findings | Scope | Autor |
|---------|------|-------------|----------|-------|-------|
| [Vulnhub_-_RickdiculouslyEasy_2026-06-04.zip](Vulnhub_-_RickdiculouslyEasy_2026-06-04.zip) | CTF - Pentesting externo | Walkthrough completo de RickdiculouslyEasy (VulnHub). 9 hallazgos, 17 tecnicas MITRE/PTES, 4 fases documentadas. | 9 | 1 host | AllSafe |
| [HTB_-_Bounty_2026-06-04.zip](HTB_-_Bounty_2026-06-04.zip) | Web App - Pentesting | Hack The Box - Bounty. Upload bypass + IIS XLST + Juicy Potato. 3 hallazgos, scope detallado. | 3 | 5 items | AllSafe |
| [HTB_-_Querier_2026-06-04.zip](HTB_-_Querier_2026-06-04.zip) | Red corporativa - Pentesting | Hack The Box - Querier. MSSQL creds en macro + hash capture + GPP password. 3 hallazgos, 4 fases. | 3 | 1 host | AllSafe |
| [HTB_-_ScriptKiddie_2026-06-04.zip](HTB_-_ScriptKiddie_2026-06-04.zip) | Web App - Pentesting | Hack The Box - ScriptKiddie. Metasploit APK template injection + sudo privesc. 3 hallazgos, 4 fases. | 3 | 2 items | AllSafe |
| [HTB_-_Optimum_2026-06-04.zip](HTB_-_Optimum_2026-06-04.zip) | Pentesting externo | Hack The Box - Optimum. HFS Remote Code Execution + MS16-098 privesc. 2 hallazgos. | 2 | 3 items | AllSafe |

---

> Antes de importar un engagement de un tercero, revisa el contenido del `.zip`. El archivo `engagement.json` es texto plano y podes inspeccionarlo antes de importar.
