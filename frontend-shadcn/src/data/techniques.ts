/**
 * Catálogo de técnicas MITRE ATT&CK — datos compartidos
 * Usado en: Técnicas, TecnicasSheet (engagements)
 */

export interface Technique {
  id: string
  name: string
  tactic: string
  phase: string
  description: string
  tools: string[]
  detection: string
  mitigation: string
}

export const TECHNIQUES: Technique[] = [
  // Reconnaissance
  { id:'T1595', name:'Active Scanning', tactic:'Reconnaissance', phase:'scanning',
    description:'Escaneo activo de la infraestructura objetivo. Incluye port scanning, banner grabbing y vulnerability scanning para identificar servicios expuestos y sus versiones.',
    tools:['nmap','masscan','zmap','rustscan'], detection:'Tráfico SYN inusual, múltiples conexiones a distintos puertos desde la misma fuente, IDS signatures.', mitigation:'Firewall perimetral, IDS/IPS con reglas de detección de escaneo, port knocking.' },
  { id:'T1592', name:'Gather Victim Host Info', tactic:'Reconnaissance', phase:'recon',
    description:'Recopilación de información sobre hosts: sistema operativo, software instalado, versiones, configuraciones expuestas en banners o metadatos de servicios.',
    tools:['nmap -sV','whatweb','wappalyzer','netcat','curl -I'], detection:'Conexiones de fingerprinting, consultas SNMP no autorizadas, solicitudes HTTP con user-agents inusuales.', mitigation:'Suprimir banners de servicios, hardening de headers HTTP, deshabilitar SNMP o usar SNMPv3.' },
  { id:'T1590', name:'Gather Victim Network Info', tactic:'Reconnaissance', phase:'recon',
    description:'OSINT sobre infraestructura de red: rangos IP, ASN, registros WHOIS, BGP routes, DNS records (A, MX, NS, TXT, SPF/DKIM/DMARC).',
    tools:['whois','amass','subfinder','dnsx','shodan','censys','theHarvester'], detection:'Consultas DNS masivas, WHOIS lookups frecuentes desde la misma IP.', mitigation:'Limitar información pública en WHOIS, usar privacy guards, monitorear exposición en Shodan/Censys.' },
  { id:'T1589', name:'Gather Victim Identity Info', tactic:'Reconnaissance', phase:'recon',
    description:'OSINT sobre usuarios: emails, credenciales en brechas previas (HIBP, Dehashed), perfiles LinkedIn, nombres de usuario, estructura organizacional.',
    tools:['theHarvester','hunter.io','linkedin2username','holehe','breach-parse'], detection:'Difícil de detectar desde fuentes externas. Monitoreo de dark web para credenciales filtradas.', mitigation:'Monitoreo de menciones en dark web, concienciación sobre exposición de información pública.' },
  { id:'T1593', name:'Search Open Websites/Domains', tactic:'Reconnaissance', phase:'recon',
    description:'Google Dorks, Wayback Machine, Pastebin, GitHub/GitLab search — buscando credenciales hardcodeadas, archivos de configuración y datos sensibles filtrados en repositorios públicos.',
    tools:['google dorks','github search','waybackurls','gau','gitdorker','trufflehog'], detection:'Difícil de detectar. Implementar monitoreo de GitHub/GitLab para secrets.', mitigation:'Secret scanning automático en CI/CD, auditorías de OSINT propio, rotación inmediata ante hallazgos.' },
  // Initial Access
  { id:'T1190', name:'Exploit Public-Facing Application', tactic:'Initial Access', phase:'exploitation',
    description:'Explotación de vulnerabilidades en aplicaciones expuestas: SQL Injection, LDAP Injection, OS Command Injection, Deserialization, SSRF, RCE en CMS/frameworks.',
    tools:['sqlmap','burpsuite','nuclei','metasploit','ffuf','commix'], detection:'WAF alerts, errores 500 inusuales en logs, payloads en parámetros, anomalías en tráfico de aplicación.', mitigation:'WAF, prepared statements, validación y sanitización de input, parches al día, SAST/DAST en CI/CD.' },
  { id:'T1133', name:'External Remote Services', tactic:'Initial Access', phase:'exploitation',
    description:'Abuso de servicios remotos expuestos: VPN, RDP, SSH, Citrix, VNC, Telnet. Contraseñas débiles, credenciales reutilizadas, o vulnerabilidades de autenticación.',
    tools:['hydra','medusa','crowbar','ncrack','metasploit','rdp-sec-check'], detection:'Múltiples intentos de login fallidos, GeoIP anomalías, horarios inusuales, MFA bypasses.', mitigation:'MFA obligatorio, whitelist de IPs, lockout de cuenta, Zero Trust Network Access.' },
  { id:'T1078', name:'Valid Accounts', tactic:'Initial Access', phase:'exploitation',
    description:'Uso de credenciales válidas obtenidas por phishing, brechas previas, credential stuffing o shoulder surfing.',
    tools:['credentialstuffing tools','firefox_decrypt','lazagne','impacket secretsdump'], detection:'Login desde ubicaciones o dispositivos inusuales, anomalías de comportamiento (UEBA), accesos fuera de horario.', mitigation:'MFA universal, monitoreo de credenciales en dark web, políticas de contraseña robustas, UEBA.' },
  { id:'T1566', name:'Phishing', tactic:'Initial Access', phase:'exploitation',
    description:'Spear phishing con links maliciosos, adjuntos weaponizados (macro Office, PDF, LNK), o vishing. Incluye Evilginx para captura de tokens MFA.',
    tools:['GoPhish','Evilginx2','SET','King Phisher','Modlishka','msfvenom'], detection:'Análisis de email gateway, sandboxing de adjuntos, entrenamiento de usuarios, marcado de emails externos.', mitigation:'SPF/DKIM/DMARC estricto, filtrado de email con sandbox, awareness training, MFA phishing-resistant (FIDO2).' },
  // Execution
  { id:'T1059', name:'Command and Scripting Interpreter', tactic:'Execution', phase:'exploitation',
    description:'Ejecución via intérpretes nativos: PowerShell, Bash, Python, cmd.exe, VBScript, JScript. Living-off-the-land usando herramientas del sistema para evadir AV/EDR.',
    tools:['powershell','bash','python','mshta','wscript','cscript','rundll32'], detection:'PowerShell Script Block Logging, auditd en Linux, AMSI, Command Line Auditing.', mitigation:'Constrained Language Mode en PowerShell, Application Whitelisting (AppLocker/WDAC), AMSI.' },
  { id:'T1203', name:'Exploitation for Client Execution', tactic:'Execution', phase:'exploitation',
    description:'Explotación de vulnerabilidades en software cliente (browser, Office, PDF reader) al abrir un archivo malicioso o visitar una URL.',
    tools:['metasploit','beef-xss','exploitdb','msfvenom','donut'], detection:'EDR/AV alerts, procesos hijos anómalos de Office/browser, spawning de cmd/powershell desde winword.', mitigation:'Patching agresivo de cliente, sandboxing de browser, Protected View en Office, disable macros.' },
  // Privilege Escalation
  { id:'T1068', name:'Exploitation for Privilege Escalation', tactic:'Privilege Escalation', phase:'post_exploitation',
    description:'Explotación de vulnerabilidades del kernel o del sistema para escalar privilegios. CVEs de kernel Linux, token impersonation en Windows, SUID/SGID mal configurados.',
    tools:['LinPEAS','WinPEAS','linux-exploit-suggester','wesng','BeRoot'], detection:'Syscalls anómalas, carga de módulos de kernel inusuales, eventos de escalación de privilegios.', mitigation:'Kernel hardening, seccomp, SELinux/AppArmor, parches de seguridad aplicados, RBAC estricto.' },
  { id:'T1548', name:'Abuse Elevation Control Mechanism', tactic:'Privilege Escalation', phase:'post_exploitation',
    description:'Bypass de UAC (Windows), sudo abuse (Linux), SUID binaries, capabilities mal asignadas.',
    tools:['UACME','gtfobins','sudo -l','find / -perm -4000 -type f','getcap'], detection:'Eventos UAC (Event ID 4688), entradas en sudo log, auditd en Linux.', mitigation:'UAC al nivel máximo, revisión de sudo rules, eliminación de SUID innecesarios, capabilities mínimas.' },
  { id:'T1134', name:'Access Token Manipulation', tactic:'Privilege Escalation', phase:'post_exploitation',
    description:'Token impersonation, token stealing, Make/Duplicate Token en Windows. Permite actuar con los privilegios de otro proceso (por ejemplo, SYSTEM).',
    tools:['incognito (meterpreter)','mimikatz','PowerSploit','meterpreter getsystem'], detection:'Event ID 4624 logon tipo 9, uso anómalo de CreateProcessWithTokenW, Seatbelt checks.', mitigation:'Privileged Access Workstations, restricción de SeImpersonatePrivilege, Protected Users group.' },
  // Credential Access
  { id:'T1003', name:'OS Credential Dumping', tactic:'Credential Access', phase:'post_exploitation',
    description:'Extracción de credenciales: LSASS dump, SAM, NTDS.dit, /etc/shadow, credential vaults, dpapi.',
    tools:['mimikatz','pypykatz','secretsdump (impacket)','lazagne','procdump'], detection:'Acceso a LSASS (Event ID 10 Sysmon), procdump desde procesos no autorizados, NTDS.dit reads.', mitigation:'Windows Credential Guard, Protected Users group, LAPS, LSA Protection, MDE/EDR.' },
  { id:'T1110', name:'Brute Force', tactic:'Credential Access', phase:'exploitation',
    description:'Ataques de contraseña: brute force, password spray, credential stuffing. Password spray evita lockouts. Kerbrute para Kerberoasting y AS-REP Roasting.',
    tools:['hydra','medusa','spray','kerbrute','crackmapexec','ruler'], detection:'Múltiples fallos de autenticación (Event ID 4625), lockouts frecuentes (Event ID 4740).', mitigation:'Lockout policies, MFA, smart lockout, password complexity, Kerberos AES enforcement.' },
  { id:'T1552', name:'Unsecured Credentials', tactic:'Credential Access', phase:'post_exploitation',
    description:'Credenciales expuestas en archivos de configuración, variables de entorno, scripts, historial bash/powershell, memoria de procesos, shares de red y bases de datos.',
    tools:['seatbelt','lazagne','linenum','grep -r "password"','snaffler','winpeas'], detection:'Acceso a archivos de configuración sensibles, lectura de variables de entorno de otros procesos.', mitigation:'Secret scanning en CI/CD, HashiCorp Vault / Azure Key Vault, rotación periódica, permisos mínimos en archivos.' },
  // Lateral Movement
  { id:'T1021', name:'Remote Services', tactic:'Lateral Movement', phase:'post_exploitation',
    description:'Movimiento lateral via servicios remotos: PSExec, WMI, SMB, RDP, SSH, WinRM. Pass-the-Hash y Pass-the-Ticket para autenticarse sin contraseña en texto claro.',
    tools:['crackmapexec','impacket (psexec/wmiexec/smbexec)','evil-winrm','metasploit'], detection:'Logins remotos inusuales, Event ID 4624 tipo 3, acceso a admin shares (IPC$, ADMIN$, C$).', mitigation:'LAPS, SMB signing obligatorio, restricción de WMI/WinRM, segmentación de red, host-based firewall.' },
  { id:'T1550', name:'Alternate Authentication Material', tactic:'Lateral Movement', phase:'post_exploitation',
    description:'Pass-the-Hash, Pass-the-Ticket (Kerberos), Overpass-the-Hash, Silver/Golden/Diamond Tickets.',
    tools:['mimikatz','impacket','rubeus','crackmapexec','kekeo'], detection:'Event ID 4768/4769 con anomalías, NTLM authentication desde cuentas inusuales, tickets con duración anómala.', mitigation:'Kerberos AES only, Protected Users group, Credential Guard, tiered admin model, PAC validation.' },
  // Persistence
  { id:'T1053', name:'Scheduled Task/Job', tactic:'Persistence', phase:'post_exploitation',
    description:'Tareas programadas para persistencia o ejecución recurrente: cron/at en Linux, Windows Task Scheduler.',
    tools:['schtasks /create','crontab -e','at','launchd (macOS)','systemd timers'], detection:'Event ID 4698/4702 (Task created/modified), nuevas entradas en crontab, Autoruns alerts.', mitigation:'Auditoría de tareas programadas, restricción de schtasks para no-admins, monitoring de crontab changes.' },
  { id:'T1547', name:'Boot or Logon Autostart', tactic:'Persistence', phase:'post_exploitation',
    description:'Persistencia via registro de Windows (Run/RunOnce/Services), módulos del kernel, init scripts Linux, startup folders.',
    tools:['reg add HKCU\\...\\Run','sc create','systemctl enable','autoruns (detección)'], detection:'Autoruns (Sysinternals), nuevos servicios (Event ID 7045), cambios en Run registry keys.', mitigation:'Monitoreo de Run keys, Secure Boot habilitado, Autoruns baseline comparison, EDR.' },
  // Defense Evasion
  { id:'T1070', name:'Indicator Removal', tactic:'Defense Evasion', phase:'post_exploitation',
    description:'Eliminación de evidencias post-ataque: limpieza de event logs, timestamps (timestomping), archivos temporales. Dificulta el análisis forense.',
    tools:['wevtutil cl Security','clear-eventlog','shred','timestomp (meterpreter)'], detection:'Event ID 1102 (audit log cleared), 1100 (logging stopped), ausencia de logs en períodos operativos.', mitigation:'SIEM con logs centralizados e inmutables, Log Analytics Workspace, alertas ante log clearing.' },
  { id:'T1027', name:'Obfuscated Files or Information', tactic:'Defense Evasion', phase:'exploitation',
    description:'Ofuscación de payloads para evadir AV/EDR: encoding (base64, XOR), packing, cifrado, polimorfismo, in-memory execution.',
    tools:['msfvenom','invoke-obfuscation','chameleon','sgn (shikata-no-gai)','donut'], detection:'Entropy analysis de binarios, AMSI (PowerShell), sandboxing de archivos, behavioral analysis en EDR.', mitigation:'EDR con behavioral detection, AMSI, PowerShell Constrained Language Mode, memory scanning.' },
  // Exfiltration
  { id:'T1041', name:'Exfiltration Over C2 Channel', tactic:'Exfiltration', phase:'post_exploitation',
    description:'Exfiltración usando el mismo canal de C2 (HTTP/S, DNS over HTTPS). Los datos se mezclan con las comunicaciones de control, dificultando la detección por volumen.',
    tools:['Cobalt Strike','Sliver','Havoc','Brute Ratel','Empire','Metasploit'], detection:'DLP, análisis de volumen/frecuencia del tráfico C2, beaconing patterns, anomalías en destinos.', mitigation:'Proxy con SSL/TLS inspection, DLP, Network Traffic Analysis (NTA), threat intel feeds para C2 IPs.' },
  { id:'T1048', name:'Exfiltration Over Alternative Protocol', tactic:'Exfiltration', phase:'post_exploitation',
    description:'Exfiltración por canales alternativos: DNS tunneling (iodine, dnscat2), ICMP, FTP, SMTP, Slack/Teams APIs.',
    tools:['dnscat2','iodine','icmpsh','ncat','powershell WebClient'], detection:'Análisis de DNS (volumen, longitud de subdominios, frecuencia), ICMP payload inspection, egress monitoring.', mitigation:'DNS filtering (Umbrella/Cloudflare), bloqueo de protocolos no autorizados, egress filtering estricto.' },
]

export const TACTICS_ORDER = [
  'Reconnaissance', 'Initial Access', 'Execution',
  'Privilege Escalation', 'Credential Access', 'Lateral Movement',
  'Persistence', 'Defense Evasion', 'Exfiltration',
]

export const TACTIC_PHASE_LABEL: Record<string, string> = {
  recon:             'Reconocimiento',
  scanning:          'Escaneo',
  exploitation:      'Explotación',
  post_exploitation: 'Post-explotación',
}
