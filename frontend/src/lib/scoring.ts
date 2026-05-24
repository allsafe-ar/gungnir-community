export interface ScoreResult {
  sections: Record<string, { sum: number; count: number; avg: number | null }>
  total: number | null
}

export function calcScore(respuestas: Record<string, string | string[]>): ScoreResult {
  const sections: Record<string, { sum: number; count: number; avg: number | null }> = {}
  let totalSum = 0
  let totalCount = 0

  for (const [secKey, preguntas] of Object.entries(SCORING_DATA)) {
    let secSum = 0, secCount = 0
    for (const p of preguntas) {
      const resp = respuestas[p.id]
      if (!resp) continue
      let score = 0
      if (p.tipo === 'checkbox' && Array.isArray(resp) && resp.length > 0) {
        let s = 0
        for (const sel of resp) {
          const opt = p.opciones.find((o) => o.r === sel)
          if (opt) s += opt.prob * opt.imp
        }
        score = Math.round(s / resp.length)
      } else if (p.tipo === 'radio') {
        const opt = p.opciones.find((o) => o.r === resp)
        if (opt) score = opt.prob * opt.imp
      }
      if (score > 0) { secSum += score; secCount++ }
    }
    const avg = secCount > 0 ? Math.round((secSum / secCount) * 10) / 10 : null
    sections[secKey] = { sum: secSum, count: secCount, avg }
    if (avg !== null) { totalSum += avg; totalCount++ }
  }

  const total = totalCount > 0 ? Math.round((totalSum / totalCount) * 10) / 10 : null
  return { sections, total }
}

export function riskLevel(score: number | null | undefined) {
  if (score === null || score === undefined)
    return { label: 'Sin datos', color: '#71717a', key: 'none' as const }
  if (score >= 20) return { label: 'CRÍTICO', color: '#e8192c', key: 'critico' as const }
  if (score >= 12) return { label: 'ALTO', color: '#c2410c', key: 'alto' as const }
  if (score >= 6)  return { label: 'MEDIO', color: '#a16207', key: 'medio' as const }
  return              { label: 'BAJO', color: '#15803d', key: 'bajo' as const }
}

interface Opcion { r: string; prob: number; imp: number; c?: string }
interface Pregunta { id: string; cf7: string; tipo: 'radio' | 'checkbox'; pregunta: string; opciones: Opcion[] }

export const SCORING_DATA: Record<string, Pregunta[]> = {
  TECNOLOGIA: [
    { id:'T01', cf7:'tec-01', tipo:'radio', pregunta:'¿Cómo mantienes tus sistemas informáticos y programas para que funcionen bien?', opciones:[
      { r:'Lo hacemos nosotros mismos',                           prob:1, imp:5, c:'Alta probabilidad de fallas' },
      { r:'Un amigo o familiar nos ayuda',                        prob:2, imp:4, c:'Soporte informal sin continuidad' },
      { r:'Pagamos a una empresa o profesional para que lo haga', prob:4, imp:2, c:'Soporte confiable, menor riesgo' },
      { r:'Tenemos a alguien contratado para eso',                prob:5, imp:1, c:'Gestión profesional, mínimo riesgo' },
    ]},
    { id:'T02', cf7:'tec-02', tipo:'radio', pregunta:'¿Cómo proteges tus equipos de posibles amenazas?', opciones:[
      { r:'No estoy seguro',              prob:1, imp:5, c:'Exposición total' },
      { r:'No tengo sistema de seguridad', prob:1, imp:5, c:'Altísima vulnerabilidad' },
      { r:'Antivirus corporativo',         prob:3, imp:3, c:'Protección media' },
      { r:'Solución empresarial completa', prob:4, imp:2, c:'Defensa avanzada' },
      { r:'Seguridad en capas',            prob:5, imp:1, c:'Protección integral' },
    ]},
    { id:'T03', cf7:'tec-03', tipo:'radio', pregunta:'¿En dónde están ubicados los servidores y routers de tu empresa?', opciones:[
      { r:'Zona de paso',               prob:1, imp:5, c:'Riesgo físico alto' },
      { r:'Espacio compartido',          prob:2, imp:4, c:'Acceso no controlado' },
      { r:'Ubicación segura',            prob:4, imp:2, c:'Acceso limitado' },
      { r:'Instalaciones del proveedor', prob:5, imp:1, c:'Infraestructura profesional' },
    ]},
    { id:'T04', cf7:'tec-04', tipo:'radio', pregunta:'¿Con qué frecuencia actualizas el software de tus ordenadores y programas?', opciones:[
      { r:'Casi nunca',                                     prob:1, imp:5, c:'Vulnerabilidades críticas' },
      { r:'De vez en cuando',                               prob:2, imp:4, c:'Parches atrasados' },
      { r:'Cuando se avisa',                                prob:3, imp:3, c:'Riesgo moderado' },
      { r:'Siempre actualizado conociendo vulnerabilidades', prob:5, imp:1, c:'Mínimo riesgo' },
    ]},
    { id:'T05', cf7:'tec-05', tipo:'radio', pregunta:'¿Están protegidos tus sistemas con un sistema perimetral?', opciones:[
      { r:'No tenemos firewall',                   prob:1, imp:5, c:'Sin protección perimetral' },
      { r:'Firewall básico',                       prob:3, imp:3, c:'Protección básica' },
      { r:'Firewall con control de amenazas',      prob:4, imp:2, c:'Buena protección' },
      { r:'Otros sistemas de seguridad perimetral', prob:5, imp:1, c:'Protección avanzada' },
    ]},
    { id:'T06', cf7:'tec-06', tipo:'radio', pregunta:'¿Se utiliza software de control remoto como AnyDesk o TeamViewer?', opciones:[
      { r:'Sí', prob:2, imp:4, c:'Superficie de ataque ampliada' },
      { r:'No', prob:5, imp:1, c:'Sin exposición remota' },
    ]},
    { id:'T07', cf7:'tec-07', tipo:'radio', pregunta:'¿Tu red está segmentada y controlada con políticas de acceso?', opciones:[
      { r:'Una red para todos los servicios',        prob:1, imp:5, c:'Sin segmentación' },
      { r:'Distintas redes conectadas entre sí',     prob:2, imp:4, c:'Segmentación básica' },
      { r:'Distintas redes con reglas de firewall',  prob:4, imp:2, c:'Buena segmentación' },
      { r:'Arquitectura Zero Trust',                 prob:5, imp:1, c:'Máxima seguridad' },
    ]},
    { id:'T08', cf7:'tec-08', tipo:'radio', pregunta:'¿Permites que dispositivos personales se conecten a tu red wifi?', opciones:[
      { r:'Sí, todos usan el mismo wifi', prob:1, imp:5, c:'Red totalmente expuesta' },
      { r:'Solo empleados',               prob:3, imp:3, c:'Acceso controlado' },
      { r:'Hay wifi para invitados',       prob:4, imp:2, c:'Separación adecuada' },
    ]},
    { id:'T09', cf7:'tec-09', tipo:'radio', pregunta:'¿Tienes algún tipo de sistema para la protección de tus aplicaciones?', opciones:[
      { r:'No lo necesitamos',                        prob:1, imp:5, c:'Sin protección de apps' },
      { r:'Acceso con usuario y contraseña',           prob:3, imp:3, c:'Protección básica' },
      { r:'Acceso con doble factor de autenticación',  prob:5, imp:1, c:'Acceso seguro' },
    ]},
    { id:'T10', cf7:'tec-10', tipo:'radio', pregunta:'¿Tienes identificados cuáles son tus datos/sistemas críticos?', opciones:[
      { r:'No, los datos están en los equipos',         prob:1, imp:5, c:'Sin inventario crítico' },
      { r:'Servidor sin protección especial',           prob:2, imp:4, c:'Datos expuestos' },
      { r:'Servidor protegido con medidas específicas', prob:4, imp:2, c:'Buena protección' },
      { r:'DMZ controlada para sistemas críticos',      prob:5, imp:1, c:'Máxima protección' },
    ]},
  ],
  PERSONAS: [
    { id:'P01', cf7:'personas-01', tipo:'checkbox', pregunta:'¿Qué tecnologías utiliza en su empresa?', opciones:[
      { r:'Correo electrónico',                  prob:2, imp:4, c:'Phishing/malware por email' },
      { r:'Página web',                          prob:3, imp:3, c:'Exposición pública web' },
      { r:'Dispositivos (PC, móviles, tablets)', prob:3, imp:3, c:'Endpoints vulnerables' },
      { r:'Servidor propio',                     prob:2, imp:5, c:'Infraestructura crítica propia' },
      { r:'Otros equipos conectados a Internet', prob:3, imp:3, c:'IoT y otros dispositivos' },
      { r:'Trabajo remoto',                      prob:3, imp:3, c:'Acceso remoto sin control' },
      { r:'Redes sociales',                      prob:4, imp:2, c:'Exposición de información' },
    ]},
    { id:'P02', cf7:'personas-02', tipo:'radio', pregunta:'¿Has recibido formación en Ciberseguridad?', opciones:[
      { r:'No he recibido ninguna',           prob:1, imp:5, c:'Sin conciencia de seguridad' },
      { r:'He recibido información por correo', prob:2, imp:4, c:'Conocimiento mínimo' },
      { r:'He asistido a charlas',            prob:3, imp:3, c:'Conciencia básica' },
      { r:'He realizado cursos',              prob:5, imp:1, c:'Formación sólida' },
    ]},
    { id:'P03', cf7:'personas-03', tipo:'radio', pregunta:'¿Los empleados usan el mismo dispositivo personal y laboral?', opciones:[
      { r:'Sí, todos',                          prob:1, imp:5, c:'BYOD sin control' },
      { r:'Algunos',                            prob:2, imp:4, c:'BYOD parcial' },
      { r:'Solo directivos',                    prob:3, imp:3, c:'BYOD limitado' },
      { r:'No, solo dispositivos de la empresa', prob:5, imp:1, c:'Seguridad garantizada' },
    ]},
    { id:'P04', cf7:'personas-04', tipo:'radio', pregunta:'¿Los dispositivos móviles están actualizados?', opciones:[
      { r:'No lo sé',                    prob:1, imp:5, c:'Desconocimiento total' },
      { r:'De vez en cuando',            prob:2, imp:4, c:'Actualizaciones irregulares' },
      { r:'Cuando lo indica el fabricante', prob:3, imp:3, c:'Actualizaciones moderadas' },
      { r:'Siempre actualizados',         prob:5, imp:1, c:'Máxima protección' },
    ]},
    { id:'P05', cf7:'personas-05', tipo:'radio', pregunta:'¿Con qué frecuencia realiza copias de seguridad?', opciones:[
      { r:'Nunca',          prob:1, imp:5, c:'Sin backups' },
      { r:'Una vez al mes', prob:2, imp:4, c:'Backups mensuales' },
      { r:'Cada semana',    prob:3, imp:3, c:'Backups semanales' },
      { r:'Todos los días', prob:5, imp:1, c:'Backups diarios' },
    ]},
    { id:'P06', cf7:'personas-06', tipo:'radio', pregunta:'¿El personal informático tiene conocimientos de ciberseguridad?', opciones:[
      { r:'No estoy seguro',             prob:1, imp:5, c:'Sin conocimientos' },
      { r:'Sí, básicos',                 prob:2, imp:4, c:'Conocimientos básicos' },
      { r:'Formación técnica',           prob:4, imp:2, c:'Formación técnica avanzada' },
      { r:'Certificación en ciberseguridad', prob:5, imp:1, c:'Certificación profesional' },
    ]},
    { id:'P07', cf7:'personas-07', tipo:'radio', pregunta:'¿Qué servicio de correo electrónico utiliza?', opciones:[
      { r:'Gratuito (Gmail, Yahoo)',                prob:1, imp:5, c:'Sin control corporativo' },
      { r:'Servidor propio',                        prob:3, imp:3, c:'Control propio' },
      { r:'Servidor propio mantenido externamente', prob:4, imp:2, c:'Soporte profesional' },
      { r:'Contratado a una empresa de servicios',  prob:5, imp:1, c:'Servicio gestionado' },
    ]},
    { id:'P08', cf7:'personas-08', tipo:'radio', pregunta:'¿Quién crea y elimina las cuentas de correo?', opciones:[
      { r:'Todos los usuarios',   prob:1, imp:5, c:'Sin control de identidades' },
      { r:'Algunos autorizados',  prob:3, imp:3, c:'Control parcial' },
      { r:'Informático interno',  prob:4, imp:2, c:'Control centralizado interno' },
      { r:'Empresa externa',      prob:5, imp:1, c:'Control profesional externo' },
    ]},
    { id:'P09', cf7:'personas-09', tipo:'radio', pregunta:'¿Quién administra las aplicaciones internas?', opciones:[
      { r:'Todos los usuarios',   prob:1, imp:5, c:'Sin administración centralizada' },
      { r:'Algunos autorizados',  prob:2, imp:4, c:'Administración parcial' },
      { r:'Solo yo',              prob:3, imp:3, c:'Administración individual' },
      { r:'Personal informático', prob:4, imp:2, c:'Administración técnica interna' },
      { r:'Empresa externa',      prob:5, imp:1, c:'Administración profesional' },
    ]},
    { id:'P10', cf7:'personas-10', tipo:'radio', pregunta:'¿Quién define qué aplicaciones pueden usar los empleados remotos?', opciones:[
      { r:'Todos los usuarios',   prob:1, imp:5, c:'Sin política de apps' },
      { r:'Algunos autorizados',  prob:2, imp:4, c:'Política parcial' },
      { r:'Solo yo',              prob:3, imp:3, c:'Política individual' },
      { r:'Personal informático', prob:4, imp:2, c:'Política técnica interna' },
      { r:'Empresa externa',      prob:5, imp:1, c:'Política gestionada' },
    ]},
  ],
  PROCESOS: [
    { id:'PR01', cf7:'proc-01', tipo:'radio', pregunta:'¿Tienen política de gestión de contraseñas?', opciones:[
      { r:'No',                           prob:1, imp:5, c:'Sin política' },
      { r:'El usuario elige su contraseña', prob:2, imp:4, c:'Sin estándar' },
      { r:'Servidor obliga al cambio',     prob:4, imp:2, c:'Política básica' },
      { r:'Política formal y obligatoria', prob:5, imp:1, c:'Política completa' },
    ]},
    { id:'PR02', cf7:'proc-02', tipo:'radio', pregunta:'¿Cumple su empresa con todas las leyes de seguridad?', opciones:[
      { r:'No',             prob:1, imp:5, c:'Incumplimiento total' },
      { r:'No estoy seguro', prob:2, imp:4, c:'Cumplimiento incierto' },
      { r:'Casi todo',      prob:4, imp:2, c:'Cumplimiento parcial' },
      { r:'Por completo',   prob:5, imp:1, c:'Cumplimiento total' },
    ]},
    { id:'PR03', cf7:'proc-03', tipo:'radio', pregunta:'¿Quién se conecta a sus sistemas de forma remota?', opciones:[
      { r:'Empleados sin HTTPS',          prob:1, imp:5, c:'Tráfico sin cifrar' },
      { r:'Empleados con HTTPS',          prob:3, imp:3, c:'Cifrado básico' },
      { r:'Acceso remoto a aplicaciones', prob:4, imp:2, c:'Acceso controlado' },
      { r:'Solo yo de forma segura',      prob:4, imp:2, c:'Acceso mínimo seguro' },
      { r:'Nadie',                        prob:5, imp:1, c:'Sin acceso remoto' },
    ]},
    { id:'PR04', cf7:'proc-04', tipo:'radio', pregunta:'¿Cuánto tiempo podría funcionar sin correo electrónico?', opciones:[
      { r:'Menos de 4h',  prob:1, imp:5, c:'Dependencia crítica' },
      { r:'4h a 1 día',   prob:2, imp:4, c:'Alta dependencia' },
      { r:'1-5 días',     prob:3, imp:3, c:'Dependencia moderada' },
      { r:'Más de 5 días', prob:5, imp:1, c:'Baja dependencia' },
    ]},
    { id:'PR05', cf7:'proc-05', tipo:'radio', pregunta:'¿Cuánto tiempo podría estar su web caída sin perjuicio?', opciones:[
      { r:'Menos de 4h',  prob:1, imp:5, c:'Web crítica' },
      { r:'4h a 1 día',   prob:2, imp:4, c:'Alta dependencia web' },
      { r:'1-5 días',     prob:3, imp:3, c:'Dependencia moderada' },
      { r:'Más de 5 días', prob:5, imp:1, c:'Baja dependencia' },
    ]},
    { id:'PR06', cf7:'proc-06', tipo:'radio', pregunta:'¿Cuánto tiempo podría operar sin trabajo remoto?', opciones:[
      { r:'Menos de 4h',  prob:1, imp:5, c:'Trabajo remoto crítico' },
      { r:'4h a 1 día',   prob:2, imp:4, c:'Alta dependencia remota' },
      { r:'1-5 días',     prob:3, imp:3, c:'Dependencia moderada' },
      { r:'Más de 5 días', prob:5, imp:1, c:'Baja dependencia' },
    ]},
    { id:'PR07', cf7:'proc-07', tipo:'radio', pregunta:'¿Se realizan conexiones remotas?', opciones:[
      { r:'Empleados y clientes web',      prob:1, imp:5, c:'Exposición amplia' },
      { r:'Empleados con intranet',        prob:2, imp:4, c:'Acceso interno' },
      { r:'Solo yo',                       prob:3, imp:3, c:'Acceso mínimo' },
      { r:'Empleados con escritorio remoto', prob:2, imp:4, c:'RDP expuesto' },
      { r:'No',                            prob:5, imp:1, c:'Sin exposición remota' },
    ]},
    { id:'PR08', cf7:'proc-08', tipo:'radio', pregunta:'¿Cuenta con plan de contingencia?', opciones:[
      { r:'No',                                  prob:1, imp:5, c:'Sin plan' },
      { r:'Algo pero sin probar',                prob:2, imp:4, c:'Plan informal' },
      { r:'Definido sin comprobar',              prob:3, imp:3, c:'Plan sin validar' },
      { r:'Definido y probado (copias locales)',  prob:4, imp:2, c:'Plan probado local' },
      { r:'Definido con copias externas',        prob:4, imp:2, c:'Plan con backup externo' },
      { r:'Servidores redundantes',              prob:5, imp:1, c:'Máxima resiliencia' },
    ]},
    { id:'PR09', cf7:'proc-09', tipo:'radio', pregunta:'¿Tiene plan alternativo para trabajadores remotos?', opciones:[
      { r:'No trabajan',                        prob:5, imp:1, c:'Sin trabajo remoto' },
      { r:'Acuden a la empresa',                prob:3, imp:3, c:'Alternativa presencial' },
      { r:'Sí, segunda línea de comunicaciones', prob:5, imp:1, c:'Plan alternativo completo' },
    ]},
  ],
  DATOS: [
    { id:'D01', cf7:'datos-01', tipo:'radio', pregunta:'Actividad principal', opciones:[
      { r:'Industria',              prob:3, imp:3, c:'Exposición técnica moderada' },
      { r:'Construcción',           prob:3, imp:3, c:'Exposición moderada' },
      { r:'Salud',                  prob:2, imp:5, c:'Datos sensibles' },
      { r:'Comercio mayorista',     prob:3, imp:3, c:'Transacciones y pagos' },
      { r:'Comercio minorista',     prob:3, imp:3, c:'Transacciones y pagos' },
      { r:'Turismo',                prob:4, imp:2, c:'Datos comerciales' },
      { r:'Logística',              prob:3, imp:3, c:'Cadena de suministro' },
      { r:'Educación',              prob:3, imp:4, c:'Datos personales y menores' },
      { r:'Asociaciones',           prob:3, imp:3, c:'Datos de miembros' },
      { r:'Servicios profesionales', prob:4, imp:2, c:'Datos de clientes críticos' },
    ]},
    { id:'D02', cf7:'datos-02', tipo:'radio', pregunta:'Sectores Estratégicos', opciones:[
      { r:'Agua potable',                prob:1, imp:5, c:'Infraestructura crítica' },
      { r:'Banco',                       prob:1, imp:5, c:'Riesgo financiero alto' },
      { r:'Energía',                     prob:1, imp:5, c:'Infraestructura crítica nacional' },
      { r:'Administración pública',      prob:2, imp:5, c:'Datos ciudadanos' },
      { r:'Fabricación de electrónicos', prob:2, imp:4, c:'Propiedad intelectual' },
      { r:'Gestión de residuos',         prob:3, imp:3, c:'Infraestructura pública' },
      { r:'Infraestructura digital',     prob:2, imp:5, c:'Sistema crítico digital' },
      { r:'Sanitario',                   prob:2, imp:5, c:'Datos de salud' },
      { r:'Transporte',                  prob:2, imp:4, c:'Logística crítica' },
      { r:'Turismo',                     prob:4, imp:2, c:'Datos comerciales' },
      { r:'Servicios digitales',         prob:3, imp:3, c:'Servicios online' },
    ]},
    { id:'D03', cf7:'datos-03', tipo:'radio', pregunta:'Número de empleados', opciones:[
      { r:'No contesta',        prob:1, imp:4, c:'Falta de información' },
      { r:'Gran empresa (>250)', prob:3, imp:3, c:'Mayor exposición' },
      { r:'Mediana (50-249)',   prob:4, imp:2, c:'Gestión controlada' },
      { r:'Pequeña (10-49)',    prob:5, imp:1, c:'Estructura manejable' },
      { r:'Micropyme (1-9)',    prob:5, imp:1, c:'Estructura mínima' },
    ]},
    { id:'D04', cf7:'datos-04', tipo:'radio', pregunta:'Provincia (Argentina)', opciones:[
      'Buenos Aires','CABA','Catamarca','Chaco','Chubut','Córdoba','Corrientes',
      'Entre Ríos','Formosa','Jujuy','La Pampa','La Rioja','Mendoza','Misiones',
      'Neuquén','Río Negro','Salta','San Juan','San Luis','Santa Cruz','Santa Fe',
      'Santiago del Estero','Tierra del Fuego','Tucumán',
    ].map(r => ({ r, prob:3, imp:1, c:'' }))},
    { id:'D05', cf7:'datos-05', tipo:'radio', pregunta:'¿Contratas servicios externos en ciberseguridad?', opciones:[
      { r:'No contesta', prob:2, imp:3, c:'Información insuficiente' },
      { r:'Sí',          prob:5, imp:1, c:'Monitoreo profesional' },
      { r:'No',          prob:1, imp:5, c:'Ausencia de expertos' },
    ]},
  ],
}

// ── CF7 email parser ──────────────────────────────────────────────────────────

const CTRL_MAP: Record<number, string[]> = {
  1: ['T01','T02','T03','T04','T05','T06','T07','T08','T09','T10'],
  2: ['P01','P02','P03','P04','P05','P06','P07','P08','P09','P10'],
  3: ['PR01','PR02','PR03','PR04','PR05','PR06','PR07','PR08','PR09'],
}

function findOption(pregId: string, rawVal: string): string | string[] | null {
  for (const pregs of Object.values(SCORING_DATA)) {
    const p = pregs.find((x) => x.id === pregId)
    if (!p) continue
    const v = rawVal.trim()
    const vl = v.toLowerCase()
    if (p.tipo === 'checkbox') {
      const parts: string[] = []
      let depth = 0, cur = ''
      for (const ch of v) {
        if (ch === '(') { depth++; cur += ch }
        else if (ch === ')') { depth--; cur += ch }
        else if (ch === ',' && depth === 0) { if (cur.trim()) parts.push(cur.trim()); cur = '' }
        else cur += ch
      }
      if (cur.trim()) parts.push(cur.trim())
      const matched: string[] = []
      for (const pt of parts) {
        const ptl = pt.toLowerCase()
        const opt = p.opciones.find((o) => o.r === pt)
          ?? p.opciones.find((o) => o.r.toLowerCase() === ptl)
          ?? p.opciones.find((o) => o.r.toLowerCase().includes(ptl))
          ?? p.opciones.find((o) => ptl.includes(o.r.toLowerCase()))
        if (opt && !matched.includes(opt.r)) matched.push(opt.r)
      }
      return matched.length > 0 ? matched : null
    } else {
      const opt = p.opciones.find((o) => o.r === v)
        ?? p.opciones.find((o) => o.r.toLowerCase() === vl)
        ?? p.opciones.find((o) => o.r.toLowerCase().includes(vl))
        ?? p.opciones.find((o) => vl.includes(o.r.toLowerCase()))
      return opt ? opt.r : null
    }
  }
  return null
}

export interface ParsedCF7 {
  meta: Record<string, string | boolean>
  respuestas: Record<string, string | string[]>
}

function extractEmail(raw: string): string {
  const angle = raw.match(/<([^@>\s]+@[^@>\s]+)>/)
  if (angle) return angle[1].trim()
  const plain = raw.match(/([^\s<>"]+@[^\s<>",]+)/)
  return plain ? plain[1].trim() : ''
}

export function parseCF7Email(raw: string): ParsedCF7 {
  const meta: Record<string, string | boolean> = {}
  const respuestas: Record<string, string | string[]> = {}
  const lines = raw.replace(/\r\n/g, '\n').split('\n').map((l) => l.trim())

  let currentCtrl: number | null = null
  let inBody = false
  const bodyLines: string[] = []
  let bodyDone = false

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (!line) continue

    // ── De: / From: ───────────────────────────────────────────────────────────
    const fromMatch = line.match(/^(?:De|From):\s*(.+)/i)
    if (fromMatch) {
      const e = extractEmail(fromMatch[1])
      if (e && !meta.email) meta.email = e
      continue
    }

    // ── Reply-To: / Responder a: (overrides De:) ──────────────────────────────
    const replyMatch = line.match(/^(?:Reply-To|Responder a|Responder-a):\s*(.+)/i)
    if (replyMatch) {
      const e = extractEmail(replyMatch[1])
      if (e) meta.email = e
      continue
    }

    // ── Inicio del cuerpo del mensaje ─────────────────────────────────────────
    if (/^Cuerpo del mensaje:/i.test(line)) {
      inBody = true
      const inline = line.replace(/^Cuerpo del mensaje:\s*/i, '').trim()
      if (inline) bodyLines.push(inline)
      continue
    }

    // ── Cuerpo ────────────────────────────────────────────────────────────────
    if (inBody && !bodyDone) {
      if (/^===/.test(line) || /^Aceptaci/i.test(line) || /^Desea/i.test(line) || /^--$/.test(line)) {
        inBody = false; bodyDone = true
        processBodyLines(bodyLines, meta)
        i--; continue
      }
      bodyLines.push(line); continue
    }

    // ── Campos etiquetados fuera del cuerpo (Nombre:, Email:, Empresa:, etc.) ─
    if (!inBody && !bodyDone && currentCtrl === null) {
      const colon = line.indexOf(':')
      if (colon > 0) {
        const key = line.slice(0, colon).trim().toLowerCase()
        const val = line.slice(colon + 1).trim()
        if (val) {
          if (/^(?:nombre.*apellido|nombre|name)$/.test(key) && !meta.contacto) {
            meta.contacto = val; continue
          }
          if (/^(?:email|correo.*electr[oó]nico|correo|e-?mail|mail)$/.test(key) && val.includes('@')) {
            meta.email = val; continue
          }
          if (/^(?:empresa|nombre.*empresa|organizaci[oó]n|company)$/.test(key) && !meta.empresa) {
            meta.empresa = val; continue
          }
          if (/^(?:tel[eé]fono|tel[eé]f\.?|phone|whatsapp)$/.test(key) && !meta.telefono) {
            meta.telefono = val; continue
          }
        }
      }
    }

    // ── Detectar sección CONTROL ───────────────────────────────────────────────
    const ctrlMatch = line.match(/===\s*CONTROL\s+(\d+)\s*[-–]/i)
    if (ctrlMatch) { currentCtrl = parseInt(ctrlMatch[1]); continue }

    // ── Preguntas CONTROL 1-3 ─────────────────────────────────────────────────
    if (currentCtrl && currentCtrl <= 3) {
      const numMatch = line.match(/^(\d{2}):\s*(.+)/)
      if (numMatch) {
        const pregId = CTRL_MAP[currentCtrl]?.[parseInt(numMatch[1]) - 1]
        if (pregId) {
          const matched = findOption(pregId, numMatch[2].trim())
          if (matched !== null) respuestas[pregId] = matched
        }
        continue
      }
    }

    if (/aceptaci[oó]n de privacidad/i.test(line)) {
      meta.aceptaPrivacidad = /acepto|he le[íi]do/i.test(line); continue
    }
    if (/desea informaci[oó]n comercial/i.test(line)) {
      meta.recibeComercial = /dese[oa] recibir|s[íi],/i.test(line); continue
    }

    // ── CONTROL 4 - DATOS ─────────────────────────────────────────────────────
    if (currentCtrl === 4) {
      const colon = line.indexOf(':')
      if (colon < 0) continue
      const key = line.slice(0, colon).trim().toLowerCase()
      const val = line.slice(colon + 1).trim()
      if (!val) continue
      if (key === 'actividad principal') {
        meta.sector = val
        const m = findOption('D01', val); if (m) respuestas['D01'] = m
      } else if (key === 'sector estratégico' || key === 'sector estrategico') {
        const m = findOption('D02', val); if (m) respuestas['D02'] = m
      } else if (key === 'empleados') {
        meta.empleados = val
        const m = findOption('D03', val); if (m) respuestas['D03'] = m
      } else if (key === 'provincia') {
        meta.provincia = val
        const m = findOption('D04', val); if (m) respuestas['D04'] = m
      } else if (key === 'servicios externos') {
        const m = findOption('D05', val); if (m) respuestas['D05'] = m
      }
      continue
    }
  }

  if (inBody && bodyLines.length > 0) processBodyLines(bodyLines, meta)

  return { meta, respuestas }
}

function processBodyLines(bodyLines: string[], meta: Record<string, string | boolean>) {
  const labeled = bodyLines.filter((l) => /^[A-Za-záéíóúñÁÉÍÓÚÑ ]{2,30}:\s*.+/.test(l))
  if (labeled.length >= 2) {
    for (const l of bodyLines) {
      const colon = l.indexOf(':')
      if (colon < 0) continue
      const key = l.slice(0, colon).trim().toLowerCase()
      const val = l.slice(colon + 1).trim()
      if (!val) continue
      if (/^(?:nombre.*apellido|nombre|name)$/.test(key) && !meta.contacto) meta.contacto = val
      else if (/^(?:email|correo.*electr[oó]nico|correo|e-?mail|mail)$/.test(key) && val.includes('@')) meta.email = val
      else if (/^(?:empresa|nombre.*empresa|organizaci[oó]n|company)$/.test(key) && !meta.empresa) meta.empresa = val
      else if (/^(?:tel[eé]fono|tel[eé]f\.?|phone|whatsapp)$/.test(key) && !meta.telefono) meta.telefono = val
      else if (/^(?:mensaje|message|consulta|comentarios?)$/.test(key)) { /* skip */ }
    }
  } else {
    const nonEmpty = bodyLines.filter((l) => l.trim())
    const telIdx = nonEmpty.findIndex((l) => /^[+]?\d[\d\s\-]{5,}$/.test(l.trim()))
    if (telIdx > 0) {
      if (!meta.contacto) meta.contacto = nonEmpty.slice(0, telIdx).join(' ').trim()
      if (!meta.telefono) meta.telefono = nonEmpty[telIdx].trim()
    } else if (telIdx === 0) {
      if (!meta.telefono) meta.telefono = nonEmpty[0].trim()
    } else {
      const last = nonEmpty[nonEmpty.length - 1] ?? ''
      if (/^[+]\d/.test(last)) {
        if (!meta.telefono) meta.telefono = last.trim()
        if (!meta.contacto) meta.contacto = nonEmpty.slice(0, -1).join(' ').trim()
      } else {
        if (!meta.contacto) meta.contacto = nonEmpty.join(' ').trim()
      }
    }
  }
  if (!meta.empresa && meta.contacto) {
    meta.empresa = (meta.contacto as string).toLowerCase().replace(/\s+/g, '')
  }
}
