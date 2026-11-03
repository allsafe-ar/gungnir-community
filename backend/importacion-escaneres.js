"use strict";
/**
 * Parsers de escáneres para el seguimiento continuo de Vulnerabilidades (Nessus, OpenVAS, Nmap, ZAP
 * y Burp).
 *
 * 🔑 Son una copia textual de los parsers de Gungnir Pro que usa el seguimiento continuo (`importacion-escaneres.js`): los campos con
 * guion bajo (`_ip`, `_regla`, `_cves`...) alimentan la clave de deduplicación, y tienen que salir
 * iguales en las dos ediciones para que una instalación pase de Community a Pro sin duplicar nada.
 * Si cambia un parser en Pro, se copia acá.
 *
 * La importación de un escaneo a un engagement sigue usando sus propios parsers en `server.js`: este
 * módulo no monta rutas.
 */

// 🔴 Era cuadrática con etiquetas sin cerrar: `([\s\S]*?)<\/tag>` recorría hasta el final del
// texto en cada intento fallido. Ahora el cierre se busca una sola vez desde la apertura, y
// ninguna clase de caracteres cruza un "<" (así cada intento termina en la etiqueta siguiente).
function xmlGetTag(xml, tag) {
  const ab = new RegExp(`<${tag}(?:\\s[^<>]*)?>`, 'i');
  const m = ab.exec(xml); if (!m) return '';
  const ini = m.index + m[0].length;
  const ci = new RegExp(`<\\/${tag}>`, 'gi'); ci.lastIndex = ini;
  const c = ci.exec(xml); if (!c) return '';
  return xml.slice(ini, c.index).replace(/<!\[CDATA\[|\]\]>/g, '').replace(/<[^<>]+>/g, ' ').replace(/\s+/g,' ').trim();
}
function xmlGetAttr(xml, tag, attr) {
  const re = new RegExp(`<${tag}[^>]*\\s${attr}="([^"]*)"`, 'i');
  const m = re.exec(xml); return m ? m[1] : '';
}
const ES_IP = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*$/i;
/** Separa lo que un escáner llama "host" en IP o nombre, que es como lo reconoce el inventario. */
function ipONombre(h) {
  const v = String(h || '').trim();
  if (!v) return { ip: '', hostname: '' };
  return ES_IP.test(v) ? { ip: v, hostname: '' } : { ip: '', hostname: v };
}
/** Todos los CVE de un texto, en mayúsculas y sin repetir. */
function cvesDe(texto) {
  return [...new Set((String(texto || '').match(/CVE-\d{4}-\d{4,}/gi) || []).map((c) => c.toUpperCase()))];
}
/** Host, puerto y protocolo de una URL (lo que reportan ZAP y Burp). */
function partesDeUrl(u) {
  try {
    const x = new URL(/^[a-z]+:\/\//i.test(u) ? u : `http://${u}`);
    const puerto = x.port || (x.protocol === 'https:' ? '443' : x.protocol === 'http:' ? '80' : '');
    return { ...ipONombre(x.hostname.replace(/^\[|\]$/g, '')), puerto, protocolo: puerto ? 'tcp' : '' };
  } catch { return { ip: '', hostname: '', puerto: '', protocolo: '' }; }
}

function nessusToSeverity(s) { return {4:'critical',3:'high',2:'medium',1:'low',0:'info'}[s]||'medium'; }
function burpToSeverity(s) {
  const m = {high:'high',medium:'medium',low:'low',information:'info',informational:'info',critical:'critical'};
  return m[(s||'').toLowerCase()]||'medium';
}
function openvasToSeverity(score) {
  const n = parseFloat(score)||0;
  if (n>=9) return 'critical'; if(n>=7) return 'high'; if(n>=4) return 'medium'; if(n>0) return 'low'; return 'info';
}

function parseNessus(xml) {
  const findings = [];
  // 🔴 Por cada ReportItem se recortaba el XML desde el principio (substring + regex) para buscar
  // el host: cuadrático en el tamaño del archivo, un .nessus grande dejaba el proceso trabado.
  // Ahora se recorre una sola vez: los hosts se indexan antes y los ítems se buscan con indexOf
  // (la regex perezosa sin cierre también era cuadrática). De paso, el host es el que contiene al
  // ítem; antes se tomaba siempre el primero del archivo.
  const hosts = [];
  const reHost = /<ReportHost name="([^"]*)"/g;
  let h;
  while ((h = reHost.exec(xml)) !== null) hosts.push({ pos: h.index, name: h[1] });
  // Las propiedades de cada host (IP y nombre) también en una sola pasada: se indexan los bloques y
  // se reparten por posición, sin volver a buscar desde cada host.
  const bloques = [];
  for (let desde = 0; ;) {
    const ab = xml.indexOf("<HostProperties>", desde);
    if (ab < 0) break;
    const ci = xml.indexOf("</HostProperties>", ab);
    if (ci < 0) break;                 // sin cierre no hay más bloques completos: no se sigue buscando
    bloques.push({ pos: ab, cuerpo: xml.slice(ab + 16, ci) });
    desde = ci + 17;
  }
  for (let i = 0, j = 0; i < hosts.length; i++) {
    const hasta = i + 1 < hosts.length ? hosts[i + 1].pos : Infinity;
    while (j < bloques.length && bloques[j].pos < hosts[i].pos) j++;
    const b = j < bloques.length && bloques[j].pos < hasta ? bloques[j].cuerpo : '';
    const tag = (n) => { const m = new RegExp(`<tag name="${n}">([^<]*)</tag>`).exec(b); return m ? m[1].trim() : ''; };
    const base = ipONombre(hosts[i].name);
    hosts[i].ip = tag('host-ip') || base.ip;
    hosts[i].hostname = tag('host-fqdn') || tag('netbios-name') || base.hostname;
  }
  let hi = -1, pos = 0;
  for (;;) {
    const ini = xml.indexOf("<ReportItem", pos);
    if (ini < 0) break;
    const finAbre = xml.indexOf(">", ini);
    if (finAbre < 0) break;
    const attrs = xml.slice(ini + 11, finAbre);
    if (!/^\s/.test(attrs)) { pos = ini + 11; continue; }
    const cierre = xml.indexOf("</ReportItem>", finAbre);
    if (cierre < 0) break;
    const body = xml.slice(finAbre + 1, cierre);
    pos = cierre + 13;
    while (hi + 1 < hosts.length && hosts[hi + 1].pos < ini) hi++;
    // Los atributos del ítem en una sola pasada (xmlGetAttr reintenta en cada "<x" del texto).
    const at = {};
    for (const [, k, v] of attrs.matchAll(/\s([A-Za-z_]+)="([^"]*)"/g)) if (!(k in at)) at[k] = v;
    const pluginName = at.pluginName || xmlGetTag(body,'pluginName');
    const port       = at.port || '';
    const protocol   = at.protocol || '';
    const severityN  = at.severity || '';
    const svcName    = at.svc_name || '';
    const host       = hi >= 0 ? hosts[hi].name : '';
    if (!pluginName || pluginName==='Nessus SYN scanner' || pluginName==='Nessus TCP scanner') continue;
    findings.push({
      title: pluginName,
      severity: nessusToSeverity(parseInt(severityN)||0),
      affected_asset: [host,svcName,port,protocol].filter(Boolean).join(' '),
      description: xmlGetTag(body,'description'),
      steps_to_reproduce: xmlGetTag(body,'plugin_output'),
      recommendation: xmlGetTag(body,'solution'),
      cvss_vector_31: xmlGetTag(body,'cvss3_vector'),
      cvss_score_31: parseFloat(xmlGetTag(body,'cvss3_base_score'))||null,
      cwe_id: xmlGetTag(body,'cwe'),
      owasp_category: '',
      _ip: hi >= 0 ? hosts[hi].ip : '',
      _hostname: hi >= 0 ? hosts[hi].hostname : '',
      _puerto: port && port !== '0' ? port : '',
      _protocolo: port && port !== '0' ? protocol : '',
      _servicio: svcName,
      _regla: at.pluginID ? `nessus:${at.pluginID}` : '',
      _cves: cvesDe([...body.matchAll(/<cve>([^<]*)<\/cve>/gi)].map((x) => x[1]).join(' ')),
      _cvss: parseFloat(xmlGetTag(body,'cvss3_base_score')) || parseFloat(xmlGetTag(body,'cvss_base_score')) || null,
    });
  }
  return findings;
}

function parseBurpEnhanced(xml) {
  // Igual que parseBurp pero extrae IP y URL para linkear targets
  const findings = [];
  const re = /<issue>([\s\S]*?)<\/issue>/gi;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const body = m[1];
    // <host ip="1.2.3.4">https://host.com</host>
    const hostEl = /<host([^>]*)>([\s\S]*?)<\/host>/i.exec(body);
    const hostIpAttr = hostEl ? /ip="([^"]+)"/.exec(hostEl[1]) : null;
    const hostIp  = hostIpAttr ? hostIpAttr[1] : null;
    const hostUrl = hostEl ? hostEl[2].trim() : (xmlGetTag(body,'host')||'');
    const path    = xmlGetTag(body,'path') || '';
    // Decodificar request/response base64
    const reqEl = xmlGetTag(body,'request');
    const resEl = xmlGetTag(body,'response');
    const reqDec = reqEl ? (() => { try { return Buffer.from(reqEl,'base64').toString('utf8'); } catch(e) { return reqEl; } })() : '';
    const resDec = resEl ? (() => { try { return Buffer.from(resEl,'base64').toString('utf8').slice(0,500); } catch(e) { return resEl.slice(0,500); } })() : '';
    const stepsRaw = [reqDec ? `Request:\n${reqDec}` : '', resDec ? `Response (truncated):\n${resDec}` : ''].filter(Boolean).join('\n\n');
    const desc = [xmlGetTag(body,'issueBackground'), xmlGetTag(body,'issueDetail')].filter(Boolean).join('\n\n').replace(/<[^>]+>/g,' ').trim();
    const rec  = [xmlGetTag(body,'remediationBackground'), xmlGetTag(body,'remediationDetail')].filter(Boolean).join('\n').replace(/<[^>]+>/g,' ').trim();
    findings.push({
      title: xmlGetTag(body,'name') || '',
      severity: burpToSeverity(xmlGetTag(body,'severity')),
      affected_asset: (hostUrl||'') + path,
      description: desc,
      steps_to_reproduce: stepsRaw.slice(0,3000),
      recommendation: rec,
      cvss_vector_31: null, cvss_score_31: null, cwe_id: '', owasp_category: '',
      _host_ip:  hostIp,
      _host_url: hostUrl || null,
      ...(() => { const u = partesDeUrl(hostUrl); return { _ip: hostIp || u.ip, _hostname: u.hostname, _puerto: u.puerto, _protocolo: u.protocolo }; })(),
      _regla: xmlGetTag(body,'type') ? `burp:${xmlGetTag(body,'type')}` : '',
      _cves: cvesDe(desc),
    });
  }
  return findings;
}

function parseOpenVAS(xml) {
  const findings = [];
  const re = /<result\s[^>]*>([\s\S]*?)<\/result>/gi;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const body = m[1];
    const score = xmlGetTag(body,'severity') || xmlGetTag(body,'cvss_base');
    if (parseFloat(score) === 0) continue; // skip informational
    const hostCrudo = /<host>\s*([^<\s]+)/i.exec(body);
    const nombreHost = /<hostname>([^<]*)<\/hostname>/i.exec(body);
    const puertoTxt = xmlGetTag(body,'port');            // "443/tcp" o "general/tcp"
    const [pNum, pProto] = puertoTxt.split('/');
    const oid = /<nvt\s[^>]*oid="([^"]+)"/i.exec(body);
    // Los CVE vienen como <ref type="cve" id="..."/> (GMP nuevo) o en <cve> (viejo); NOCVE no cuenta.
    const refsCve = [...body.matchAll(/<ref\s[^>]*type="cve"[^>]*id="([^"]+)"/gi)].map((x) => x[1]);
    findings.push({
      title: xmlGetTag(body,'name') || xmlGetTag(xmlGetTag(body,'nvt'),'name'),
      severity: openvasToSeverity(score),
      affected_asset: [xmlGetTag(body,'host'),xmlGetTag(body,'port')].filter(Boolean).join(':'),
      description: xmlGetTag(body,'description'),
      steps_to_reproduce: '',
      recommendation: xmlGetTag(body,'solution') || xmlGetTag(body,'tags'),
      cvss_vector_31: null,
      cvss_score_31: parseFloat(score)||null,
      cwe_id: '',
      owasp_category: '',
      ...(() => { const b = ipONombre(hostCrudo ? hostCrudo[1] : ''); return { _ip: b.ip, _hostname: (nombreHost && nombreHost[1].trim()) || b.hostname }; })(),
      _puerto: /^\d+$/.test(pNum || '') ? pNum : '',
      _protocolo: /^\d+$/.test(pNum || '') ? (pProto || 'tcp') : '',
      _regla: oid ? `openvas:${oid[1]}` : '',
      _cves: cvesDe([...refsCve, xmlGetTag(body,'cve')].join(' ')),
      _cvss: parseFloat(score) || null,
    });
  }
  return findings;
}

function parseNmap(xml) {
  const findings = [];
  // Ports that warrant elevated severity
  const RISKY_PORTS = {
    21: 'low', 23: 'high', 25: 'low', 53: 'low',
    111: 'low', 135: 'medium', 137: 'low', 139: 'medium',
    445: 'medium', 512: 'high', 513: 'high', 514: 'high',
    1433: 'medium', 1521: 'medium', 3306: 'medium',
    3389: 'medium', 5900: 'medium', 6379: 'medium',
    27017: 'medium', 5432: 'medium',
  };
  const hostRe = /<host[\s>]([\s\S]*?)<\/host>/gi;
  let hm;
  while ((hm = hostRe.exec(xml)) !== null) {
    const hostBody = hm[1];
    // Extract IP/hostname
    const addrMatch = /address[^>]*addr="([^"]+)"[^>]*addrtype="ipv4"/.exec(hostBody)
      || /address[^>]*addrtype="ipv4"[^>]*addr="([^"]+)"/.exec(hostBody);
    const ip = addrMatch ? addrMatch[1] : '';
    const hostnameMatch = /<hostname[^>]*name="([^"]+)"/.exec(hostBody);
    const hostname = hostnameMatch ? hostnameMatch[1] : '';
    const host = hostname || ip;
    // Check host is up
    const stateMatch = /<status[^>]*state="([^"]+)"/.exec(hostBody);
    if (stateMatch && stateMatch[1] !== 'up') continue;
    // Parse open ports
    const portRe = /<port\s+protocol="([^"]+)"\s+portid="([^"]+)">([\s\S]*?)<\/port>/gi;
    let pm;
    while ((pm = portRe.exec(hostBody)) !== null) {
      const proto = pm[1]; const portId = parseInt(pm[2]); const portBody = pm[3];
      // Only open ports
      const portState = /<state\s+state="([^"]+)"/.exec(portBody);
      if (!portState || portState[1] !== 'open') continue;
      // Service info
      const svcMatch = /<service([^>]*)>/.exec(portBody);
      const svcName    = svcMatch ? (xmlGetAttr(svcMatch[0],'service','name')||'') : '';
      const svcProduct = svcMatch ? (xmlGetAttr(svcMatch[0],'service','product')||'') : '';
      const svcVersion = svcMatch ? (xmlGetAttr(svcMatch[0],'service','version')||'') : '';
      const extraInfo  = svcMatch ? (xmlGetAttr(svcMatch[0],'service','extrainfo')||'') : '';
      const svcLabel = [svcName.toUpperCase(), svcProduct, svcVersion].filter(Boolean).join(' ');
      const title = `Open Port ${portId}/${proto}${svcLabel ? ' - ' + svcLabel : ''}`;
      const descParts = [];
      if (svcProduct || svcVersion) descParts.push(`Service: ${[svcProduct,svcVersion].filter(Boolean).join(' ')}`);
      if (extraInfo) descParts.push(`Details: ${extraInfo}`);
      if (hostname && ip && hostname !== ip) descParts.push(`Host: ${hostname} (${ip})`);
      else if (host) descParts.push(`Host: ${host}`);
      const severity = RISKY_PORTS[portId] || 'info';
      findings.push({
        title,
        severity,
        affected_asset: `${host}:${portId}/${proto}`,
        description: descParts.join('\n'),
        steps_to_reproduce: `nmap -sV -p ${portId} ${ip || host}`,
        recommendation: 'Verify that this service is intentionally exposed. Ensure firewall rules restrict access to authorized sources only. Review the service version for known vulnerabilities.',
        cvss_vector_31: null,
        cvss_score_31: null,
        cwe_id: '',
        owasp_category: '',
        _ip: ip,
        _hostname: hostname,
        _puerto: String(portId),
        _protocolo: proto,
        _servicio: svcName,
        // Un puerto abierto se sigue por puerto, no por el título: el título lleva la versión del
        // servicio y cambiaría con cada actualización.
        _regla: 'nmap:puerto-abierto',
      });
    }
  }
  return findings;
}

// ── ZAP XML parser ────────────────────────────────────────────────────────────
function parseZAP(xml) {
  const findings = [];
  const riskMap = { '3':'high', '2':'medium', '1':'low', '0':'info' };
  // ZAP puede usar <alertitem> o <OWASPZAPReport><site><alerts><alertitem>
  const alertRe = /<alertitem>([\s\S]*?)<\/alertitem>/gi;
  // site host para el affected_asset
  const siteMatch = /site[^>]+host="([^"]+)"[^>]*port="([^"]+)"/.exec(xml);
  const siteHost = siteMatch ? siteMatch[1] : '';
  const sitePort = siteMatch ? siteMatch[2] : '';
  let m;
  while ((m = alertRe.exec(xml)) !== null) {
    const body = m[1];
    const name      = xmlGetTag(body, 'alert') || xmlGetTag(body, 'name') || '';
    const riskCode  = xmlGetTag(body, 'riskcode') || '0';
    const severity  = riskMap[riskCode] || 'info';
    const desc      = xmlGetTag(body, 'desc') || '';
    const solution  = xmlGetTag(body, 'solution') || '';
    const cweId     = xmlGetTag(body, 'cweid') || '';
    const wascId    = xmlGetTag(body, 'wascid') || '';
    const refs      = xmlGetTag(body, 'reference') || '';
    // Instancias: se toma la primera URI como affected_asset
    const uriMatch  = /<uri>([\s\S]*?)<\/uri>/i.exec(body);
    const uri       = uriMatch ? uriMatch[1].trim() : (siteHost ? `${siteHost}:${sitePort}` : '');
    const evidMatch = /<evidence>([\s\S]*?)<\/evidence>/i.exec(body);
    const evidence  = evidMatch ? evidMatch[1].trim() : '';
    if (!name) continue;
    // Contar instancias
    const count = (body.match(/<instance>/g) || []).length;
    const u = partesDeUrl(uri || (siteHost ? `${siteHost}:${sitePort}` : ''));
    const pluginId = xmlGetTag(body, 'pluginid');
    findings.push({
      title:               name,
      severity,
      affected_asset:      uri,
      description:         desc.replace(/<[^>]+>/g,' ').trim(),
      steps_to_reproduce:  evidence ? `Evidence: ${evidence}` : '',
      recommendation:      solution.replace(/<[^>]+>/g,' ').trim(),
      cvss_vector_31:      null,
      cvss_score_31:       null,
      cwe_id:              cweId || '',
      owasp_category:      wascId ? `WASC-${wascId}` : '',
      references:          refs.replace(/<[^>]+>/g,' ').trim(),
      _ip: u.ip, _hostname: u.hostname, _puerto: u.puerto, _protocolo: u.protocolo,
      _regla: pluginId ? `zap:${pluginId}` : '',
      _instancias: count,
    });
  }
  return findings;
}

/**
 * Hosts que cubrió el escaneo, tengan o no hallazgos. Es el alcance de la importación: un equipo que
 * se escaneó y salió limpio cierra lo que tenía abierto; uno que no se escaneó, no.
 */
function hostsEscaneados(tipo, xml, items = []) {
  const vistos = [];
  const sumar = (ip, hostname) => { if (ip || hostname) vistos.push({ ip: ip || '', hostname: hostname || '' }); };
  if (tipo === 'nessus') {
    for (const h of xml.matchAll(/<ReportHost name="([^"]*)"/g)) { const b = ipONombre(h[1]); sumar(b.ip, b.hostname); }
  } else if (tipo === 'openvas') {
    // El informe trae un <host> por equipo escaneado, con su <ip>, aunque no tenga resultados.
    for (const h of xml.matchAll(/<host>\s*<ip>([^<]+)<\/ip>/gi)) sumar(h[1].trim(), '');
  } else if (tipo === 'nmap') {
    for (const h of xml.matchAll(/<host[\s>]([\s\S]*?)<\/host>/gi)) {
      const st = /<status[^>]*state="([^"]+)"/.exec(h[1]);
      if (st && st[1] !== 'up') continue;
      const a = /address[^>]*addr="([^"]+)"[^>]*addrtype="ipv4"/.exec(h[1]) || /address[^>]*addrtype="ipv4"[^>]*addr="([^"]+)"/.exec(h[1]);
      const n = /<hostname[^>]*name="([^"]+)"/.exec(h[1]);
      sumar(a ? a[1] : '', n ? n[1] : '');
    }
  } else if (tipo === 'zap') {
    for (const s of xml.matchAll(/<site\s[^>]*host="([^"]+)"/gi)) { const b = ipONombre(s[1]); sumar(b.ip, b.hostname); }
  }
  for (const f of items) sumar(f._ip, f._hostname);
  return vistos;
}

/** Parser por herramienta. Nmap devuelve un hallazgo por puerto abierto. */
const PARSERS = { nessus: parseNessus, openvas: parseOpenVAS, nmap: parseNmap, zap: parseZAP, burp: parseBurpEnhanced };

module.exports = { PARSERS, hostsEscaneados, parseNessus, parseOpenVAS, parseNmap, parseZAP, parseBurpEnhanced };
