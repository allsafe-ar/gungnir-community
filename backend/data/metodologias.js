"use strict";
/**
 * Catálogos de metodología para el checklist de cobertura por engagement.
 *
 * Cada ítem es { key, category, name }. `key` es estable (se guarda en methodology_checks) y se
 * toma de la nomenclatura oficial del framework (WSTG-xxx-nn, PTES-fase-nn). El catálogo vive en
 * código (no en base) porque es la definición del estándar, no dato del cliente; el estado por
 * engagement (pending/tested/not_applicable) sí vive en base.
 *
 * WSTG: OWASP Web Security Testing Guide v4.2 (lista oficial de pruebas).
 * PTES: Penetration Testing Execution Standard (fases y actividades principales).
 */

const owasp_wstg = [
  // Information Gathering
  { key: "WSTG-INFO-01", category: "Information Gathering", name: "Conduct Search Engine Discovery Reconnaissance for Information Leakage" },
  { key: "WSTG-INFO-02", category: "Information Gathering", name: "Fingerprint Web Server" },
  { key: "WSTG-INFO-03", category: "Information Gathering", name: "Review Webserver Metafiles for Information Leakage" },
  { key: "WSTG-INFO-04", category: "Information Gathering", name: "Enumerate Applications on Webserver" },
  { key: "WSTG-INFO-05", category: "Information Gathering", name: "Review Webpage Content for Information Leakage" },
  { key: "WSTG-INFO-06", category: "Information Gathering", name: "Identify Application Entry Points" },
  { key: "WSTG-INFO-07", category: "Information Gathering", name: "Map Execution Paths Through Application" },
  { key: "WSTG-INFO-08", category: "Information Gathering", name: "Fingerprint Web Application Framework" },
  { key: "WSTG-INFO-09", category: "Information Gathering", name: "Fingerprint Web Application" },
  { key: "WSTG-INFO-10", category: "Information Gathering", name: "Map Application Architecture" },
  // Configuration and Deployment Management
  { key: "WSTG-CONF-01", category: "Configuration and Deployment", name: "Test Network Infrastructure Configuration" },
  { key: "WSTG-CONF-02", category: "Configuration and Deployment", name: "Test Application Platform Configuration" },
  { key: "WSTG-CONF-03", category: "Configuration and Deployment", name: "Test File Extensions Handling for Sensitive Information" },
  { key: "WSTG-CONF-04", category: "Configuration and Deployment", name: "Review Old Backup and Unreferenced Files for Sensitive Information" },
  { key: "WSTG-CONF-05", category: "Configuration and Deployment", name: "Enumerate Infrastructure and Application Admin Interfaces" },
  { key: "WSTG-CONF-06", category: "Configuration and Deployment", name: "Test HTTP Methods" },
  { key: "WSTG-CONF-07", category: "Configuration and Deployment", name: "Test HTTP Strict Transport Security" },
  { key: "WSTG-CONF-08", category: "Configuration and Deployment", name: "Test RIA Cross Domain Policy" },
  { key: "WSTG-CONF-09", category: "Configuration and Deployment", name: "Test File Permission" },
  { key: "WSTG-CONF-10", category: "Configuration and Deployment", name: "Test for Subdomain Takeover" },
  { key: "WSTG-CONF-11", category: "Configuration and Deployment", name: "Test Cloud Storage" },
  // Identity Management
  { key: "WSTG-IDNT-01", category: "Identity Management", name: "Test Role Definitions" },
  { key: "WSTG-IDNT-02", category: "Identity Management", name: "Test User Registration Process" },
  { key: "WSTG-IDNT-03", category: "Identity Management", name: "Test Account Provisioning Process" },
  { key: "WSTG-IDNT-04", category: "Identity Management", name: "Testing for Account Enumeration and Guessable User Account" },
  { key: "WSTG-IDNT-05", category: "Identity Management", name: "Testing for Weak or Unenforced Username Policy" },
  // Authentication
  { key: "WSTG-ATHN-01", category: "Authentication", name: "Testing for Credentials Transported over an Encrypted Channel" },
  { key: "WSTG-ATHN-02", category: "Authentication", name: "Testing for Default Credentials" },
  { key: "WSTG-ATHN-03", category: "Authentication", name: "Testing for Weak Lock Out Mechanism" },
  { key: "WSTG-ATHN-04", category: "Authentication", name: "Testing for Bypassing Authentication Schema" },
  { key: "WSTG-ATHN-05", category: "Authentication", name: "Testing for Vulnerable Remember Password" },
  { key: "WSTG-ATHN-06", category: "Authentication", name: "Testing for Browser Cache Weaknesses" },
  { key: "WSTG-ATHN-07", category: "Authentication", name: "Testing for Weak Password Policy" },
  { key: "WSTG-ATHN-08", category: "Authentication", name: "Testing for Weak Security Question Answer" },
  { key: "WSTG-ATHN-09", category: "Authentication", name: "Testing for Weak Password Change or Reset Functionalities" },
  { key: "WSTG-ATHN-10", category: "Authentication", name: "Testing for Weaker Authentication in Alternative Channel" },
  // Authorization
  { key: "WSTG-ATHZ-01", category: "Authorization", name: "Testing Directory Traversal File Include" },
  { key: "WSTG-ATHZ-02", category: "Authorization", name: "Testing for Bypassing Authorization Schema" },
  { key: "WSTG-ATHZ-03", category: "Authorization", name: "Testing for Privilege Escalation" },
  { key: "WSTG-ATHZ-04", category: "Authorization", name: "Testing for Insecure Direct Object References" },
  // Session Management
  { key: "WSTG-SESS-01", category: "Session Management", name: "Testing for Session Management Schema" },
  { key: "WSTG-SESS-02", category: "Session Management", name: "Testing for Cookies Attributes" },
  { key: "WSTG-SESS-03", category: "Session Management", name: "Testing for Session Fixation" },
  { key: "WSTG-SESS-04", category: "Session Management", name: "Testing for Exposed Session Variables" },
  { key: "WSTG-SESS-05", category: "Session Management", name: "Testing for Cross Site Request Forgery" },
  { key: "WSTG-SESS-06", category: "Session Management", name: "Testing for Logout Functionality" },
  { key: "WSTG-SESS-07", category: "Session Management", name: "Testing Session Timeout" },
  { key: "WSTG-SESS-08", category: "Session Management", name: "Testing for Session Puzzling" },
  { key: "WSTG-SESS-09", category: "Session Management", name: "Testing for Session Hijacking" },
  // Input Validation
  { key: "WSTG-INPV-01", category: "Input Validation", name: "Testing for Reflected Cross Site Scripting" },
  { key: "WSTG-INPV-02", category: "Input Validation", name: "Testing for Stored Cross Site Scripting" },
  { key: "WSTG-INPV-03", category: "Input Validation", name: "Testing for HTTP Verb Tampering" },
  { key: "WSTG-INPV-04", category: "Input Validation", name: "Testing for HTTP Parameter Pollution" },
  { key: "WSTG-INPV-05", category: "Input Validation", name: "Testing for SQL Injection" },
  { key: "WSTG-INPV-06", category: "Input Validation", name: "Testing for LDAP Injection" },
  { key: "WSTG-INPV-07", category: "Input Validation", name: "Testing for XML Injection" },
  { key: "WSTG-INPV-08", category: "Input Validation", name: "Testing for SSI Injection" },
  { key: "WSTG-INPV-09", category: "Input Validation", name: "Testing for XPath Injection" },
  { key: "WSTG-INPV-10", category: "Input Validation", name: "Testing for IMAP SMTP Injection" },
  { key: "WSTG-INPV-11", category: "Input Validation", name: "Testing for Code Injection" },
  { key: "WSTG-INPV-12", category: "Input Validation", name: "Testing for Command Injection" },
  { key: "WSTG-INPV-13", category: "Input Validation", name: "Testing for Format String Injection" },
  { key: "WSTG-INPV-14", category: "Input Validation", name: "Testing for Incubated Vulnerability" },
  { key: "WSTG-INPV-15", category: "Input Validation", name: "Testing for HTTP Splitting Smuggling" },
  { key: "WSTG-INPV-16", category: "Input Validation", name: "Testing for HTTP Incoming Requests" },
  { key: "WSTG-INPV-17", category: "Input Validation", name: "Testing for Host Header Injection" },
  { key: "WSTG-INPV-18", category: "Input Validation", name: "Testing for Server-side Template Injection" },
  { key: "WSTG-INPV-19", category: "Input Validation", name: "Testing for Server-Side Request Forgery" },
  // Error Handling
  { key: "WSTG-ERRH-01", category: "Error Handling", name: "Testing for Improper Error Handling" },
  { key: "WSTG-ERRH-02", category: "Error Handling", name: "Testing for Stack Traces" },
  // Cryptography
  { key: "WSTG-CRYP-01", category: "Cryptography", name: "Testing for Weak Transport Layer Security" },
  { key: "WSTG-CRYP-02", category: "Cryptography", name: "Testing for Padding Oracle" },
  { key: "WSTG-CRYP-03", category: "Cryptography", name: "Testing for Sensitive Information Sent via Unencrypted Channels" },
  { key: "WSTG-CRYP-04", category: "Cryptography", name: "Testing for Weak Encryption" },
  // Business Logic
  { key: "WSTG-BUSL-01", category: "Business Logic", name: "Test Business Logic Data Validation" },
  { key: "WSTG-BUSL-02", category: "Business Logic", name: "Test Ability to Forge Requests" },
  { key: "WSTG-BUSL-03", category: "Business Logic", name: "Test Integrity Checks" },
  { key: "WSTG-BUSL-04", category: "Business Logic", name: "Test for Process Timing" },
  { key: "WSTG-BUSL-05", category: "Business Logic", name: "Test Number of Times a Function Can Be Used Limits" },
  { key: "WSTG-BUSL-06", category: "Business Logic", name: "Testing for the Circumvention of Work Flows" },
  { key: "WSTG-BUSL-07", category: "Business Logic", name: "Test Defenses Against Application Misuse" },
  { key: "WSTG-BUSL-08", category: "Business Logic", name: "Test Upload of Unexpected File Types" },
  { key: "WSTG-BUSL-09", category: "Business Logic", name: "Test Upload of Malicious Files" },
  // Client-side
  { key: "WSTG-CLNT-01", category: "Client-side", name: "Testing for DOM-Based Cross Site Scripting" },
  { key: "WSTG-CLNT-02", category: "Client-side", name: "Testing for JavaScript Execution" },
  { key: "WSTG-CLNT-03", category: "Client-side", name: "Testing for HTML Injection" },
  { key: "WSTG-CLNT-04", category: "Client-side", name: "Testing for Client-side URL Redirect" },
  { key: "WSTG-CLNT-05", category: "Client-side", name: "Testing for CSS Injection" },
  { key: "WSTG-CLNT-06", category: "Client-side", name: "Testing for Client-side Resource Manipulation" },
  { key: "WSTG-CLNT-07", category: "Client-side", name: "Testing Cross Origin Resource Sharing" },
  { key: "WSTG-CLNT-08", category: "Client-side", name: "Testing for Cross Site Flashing" },
  { key: "WSTG-CLNT-09", category: "Client-side", name: "Testing for Clickjacking" },
  { key: "WSTG-CLNT-10", category: "Client-side", name: "Testing WebSockets" },
  { key: "WSTG-CLNT-11", category: "Client-side", name: "Testing Web Messaging" },
  { key: "WSTG-CLNT-12", category: "Client-side", name: "Testing Browser Storage" },
  { key: "WSTG-CLNT-13", category: "Client-side", name: "Testing for Cross Site Script Inclusion" },
  // API
  { key: "WSTG-APIT-01", category: "API", name: "Testing GraphQL" },
];

const ptes = [
  { key: "PTES-PRE-01", category: "Pre-engagement", name: "Alcance, reglas de enfrentamiento y ventanas de prueba acordadas" },
  { key: "PTES-PRE-02", category: "Pre-engagement", name: "Autorización por escrito y contactos de emergencia" },
  { key: "PTES-INT-01", category: "Intelligence Gathering", name: "OSINT y footprinting del objetivo" },
  { key: "PTES-INT-02", category: "Intelligence Gathering", name: "Enumeración de infraestructura, servicios y personas" },
  { key: "PTES-THR-01", category: "Threat Modeling", name: "Modelado de amenazas y activos de negocio" },
  { key: "PTES-THR-02", category: "Threat Modeling", name: "Identificación de rutas de ataque prioritarias" },
  { key: "PTES-VUL-01", category: "Vulnerability Analysis", name: "Escaneo y validación de vulnerabilidades" },
  { key: "PTES-VUL-02", category: "Vulnerability Analysis", name: "Análisis manual y descarte de falsos positivos" },
  { key: "PTES-EXP-01", category: "Exploitation", name: "Explotación controlada dentro del alcance" },
  { key: "PTES-EXP-02", category: "Exploitation", name: "Evasión de controles y prueba de defensas" },
  { key: "PTES-POS-01", category: "Post-Exploitation", name: "Persistencia, pivoteo y recolección (con límites acordados)" },
  { key: "PTES-POS-02", category: "Post-Exploitation", name: "Evaluación del impacto y valor de negocio comprometido" },
  { key: "PTES-POS-03", category: "Post-Exploitation", name: "Limpieza de artefactos y cuentas de prueba" },
  { key: "PTES-REP-01", category: "Reporting", name: "Informe ejecutivo y técnico con evidencias" },
  { key: "PTES-REP-02", category: "Reporting", name: "Recomendaciones de remediación y plan de reprueba" },
];

const CATALOGOS = { owasp_wstg, ptes };

module.exports = { CATALOGOS };
