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

| Archivo | Tipo | Descripcion | Findings | Autor |
|---------|------|-------------|----------|-------|
| [Vulnhub_-_RickdiculouslyEasy_2026-06-04.zip](Vulnhub_-_RickdiculouslyEasy_2026-06-04.zip) | CTF · VulnHub | Walkthrough completo de RickdiculouslyEasy. 9 hallazgos, 22 logs, 17 tecnicas MITRE. | 9 | AllSafe |
| [HTB_-_Blue_2026-06-04.zip](HTB_-_Blue_2026-06-04.zip) | CTF · HackTheBox | HTB Blue — EternalBlue (MS17-010) + shell SYSTEM + mimikatz. 3 hallazgos, 10 logs, 3 tecnicas MITRE. Incluye evidencia PDF oficial. | 3 | AllSafe |
| [HTB_-_Bounty_2026-06-04.zip](HTB_-_Bounty_2026-06-04.zip) | CTF · HackTheBox | HTB Bounty — IIS upload bypass + XLST RCE + Juicy Potato. 3 hallazgos, 11 logs. | 3 | AllSafe |
| [HTB_-_Optimum_2026-06-04.zip](HTB_-_Optimum_2026-06-04.zip) | CTF · HackTheBox | HTB Optimum — HFS Remote Code Execution + MS16-098 privesc. 2 hallazgos, 20 logs. | 2 | AllSafe |
| [HTB_-_Querier_2026-06-04.zip](HTB_-_Querier_2026-06-04.zip) | CTF · HackTheBox | HTB Querier — MSSQL creds en macro Excel + captura hash NTLM + GPP password. 3 hallazgos, 13 logs. | 3 | AllSafe |
| [HTB_-_ScriptKiddie_2026-06-04.zip](HTB_-_ScriptKiddie_2026-06-04.zip) | CTF · HackTheBox | HTB ScriptKiddie — Metasploit APK template injection + sudo PWD privesc. 3 hallazgos, 8 logs. | 3 | AllSafe |

---

> Antes de importar un engagement de un tercero, revisa el contenido del `.zip`. El archivo `engagement.json` es texto plano y podes inspeccionarlo antes de importar.
