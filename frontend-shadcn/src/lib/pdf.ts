import jsPDF from 'jspdf'
import autoTable from 'jspdf-autotable'
import type { ScoreResult } from './scoring'

export const LOGO_B64 = "data:image/png;base64,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"

type RGB = [number, number, number]

const NAVY:   RGB = [15, 25, 55]
const BLUE:   RGB = [37, 99, 235]
const LBLUE:  RGB = [240, 245, 255]
const GRAY:   RGB = [100, 110, 130]
const LGRAY:  RGB = [245, 247, 252]
const WHITE:  RGB = [255, 255, 255]
const GREEN:  RGB = [34, 197, 94]
const YELLOW: RGB = [234, 179, 8]
const ORANGE: RGB = [249, 115, 22]
const RED:    RGB = [239, 68, 68]

function riskColor(score: number | null | undefined): RGB {
  if (score === null || score === undefined) return GRAY
  if (score >= 20) return RED
  if (score >= 12) return ORANGE
  if (score >= 6)  return YELLOW
  return GREEN
}

function riskLabel(score: number | null | undefined): string {
  if (score === null || score === undefined) return 'Sin datos'
  if (score >= 20) return 'CRÍTICO'
  if (score >= 12) return 'ALTO'
  if (score >= 6)  return 'MEDIO'
  return 'BAJO'
}

interface LeadForPdf {
  meta: Record<string, string>
  scores: ScoreResult
}

export function generatePDF(lead: LeadForPdf) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' }) as any
  const { meta, scores } = lead
  const PW = 210, PH = 297, M = 14
  const W = PW - M * 2

  const setColor = (rgb: RGB) => doc.setTextColor(rgb[0], rgb[1], rgb[2])
  const setFill  = (rgb: RGB) => doc.setFillColor(rgb[0], rgb[1], rgb[2])
  const setDraw  = (rgb: RGB) => doc.setDrawColor(rgb[0], rgb[1], rgb[2])

  const wrapText = (text: string, x: number, y: number, maxW: number, lineH = 5) => {
    const lines = doc.splitTextToSize(text, maxW)
    doc.text(lines, x, y)
    return y + lines.length * lineH
  }

  const drawBar = (x: number, y: number, w: number, h: number, score: number | null, maxScore = 25) => {
    const pct = Math.min((score || 0) / maxScore, 1)
    const color = riskColor(score)
    setFill([230, 234, 245] as RGB); doc.rect(x, y, w, h, 'F')
    setFill(color); doc.rect(x, y, w * pct, h, 'F')
  }

  let pageNum = 1
  const addPageNumber = () => {
    doc.setPage(pageNum)
    doc.setFontSize(8); setColor(GRAY)
    doc.text(`Página ${pageNum}`, PW - M, PH - 8, { align: 'right' })
    doc.text('Confidencial — Uso exclusivo del cliente', M, PH - 8)
    pageNum++
  }

  // ── PÁGINA 1: PORTADA ──
  setFill(NAVY); doc.rect(0, 0, PW, 60, 'F')
  setFill(BLUE); doc.rect(0, 55, PW, 4, 'F')

  try { doc.addImage(LOGO_B64, 'JPEG', M, 10, 38, 14) } catch {}

  doc.setFontSize(22); doc.setFont('helvetica', 'bold'); setColor(WHITE)
  doc.text('Análisis de Riesgo Preliminar', M, 40)
  doc.setFontSize(11); doc.setFont('helvetica', 'normal'); setColor([150, 170, 210] as RGB)
  doc.text('en Ciberseguridad', M, 48)

  setFill(LBLUE); doc.roundedRect(M, 70, W, 36, 3, 3, 'F')
  setDraw([200, 210, 235] as RGB); doc.setLineWidth(0.3)
  doc.roundedRect(M, 70, W, 36, 3, 3, 'S')

  doc.setFontSize(9); doc.setFont('helvetica', 'bold'); setColor(BLUE)
  doc.text('PREPARADO PARA', M + 6, 79)
  doc.setFontSize(16); doc.setFont('helvetica', 'bold'); setColor(NAVY)
  doc.text((meta?.empresa || '—').toUpperCase(), M + 6, 90)
  doc.setFontSize(9); doc.setFont('helvetica', 'normal'); setColor(GRAY)
  const dateParts = new Date().toLocaleDateString('es-AR', { year: 'numeric', month: 'long', day: 'numeric' })
  doc.text(`Fecha de análisis: ${dateParts}`, M + 6, 99)
  if (meta?.contacto) doc.text(`Contacto: ${meta.contacto}`, M + 100, 99)

  let y = 120
  doc.setFontSize(13); doc.setFont('helvetica', 'bold'); setColor(NAVY)
  doc.text('Estimado/a cliente,', M, y); y += 10

  doc.setFontSize(10); doc.setFont('helvetica', 'normal'); setColor([40, 55, 90] as RGB)
  const intro = 'Gracias por confiar en AllSafe Security Solutions. En un entorno digital cada vez más complejo y expuesto a amenazas crecientes, contar con una evaluación objetiva del estado de su seguridad informática es el primer paso para proteger lo que más importa: su negocio, su información y la continuidad de sus operaciones.'
  y = wrapText(intro, M, y, W, 5.5); y += 6

  const quienes = 'AllSafe es una empresa especializada en ciberseguridad para organizaciones de todos los tamaños. Nuestro enfoque combina tecnología de vanguardia con un acompañamiento cercano, ayudando a nuestros clientes a identificar riesgos, implementar controles y construir una cultura de seguridad sólida y sostenible.'
  y = wrapText(quienes, M, y, W, 5.5); y += 6

  setFill(LGRAY); doc.roundedRect(M, y, W, 42, 3, 3, 'F')
  setDraw([210, 218, 235] as RGB); doc.setLineWidth(0.3)
  doc.roundedRect(M, y, W, 42, 3, 3, 'S')
  setFill(BLUE); doc.roundedRect(M, y, 3, 42, 1.5, 1.5, 'F')

  doc.setFontSize(10); doc.setFont('helvetica', 'bold'); setColor(NAVY)
  doc.text('¿Qué es este análisis?', M + 8, y + 8); y += 12
  doc.setFont('helvetica', 'normal'); setColor([40, 55, 90] as RGB); doc.setFontSize(9.5)
  const what1 = 'Este Análisis de Riesgo Preliminar es una evaluación inicial basada en un cuestionario estructurado que abarca cuatro áreas críticas de la seguridad organizacional: Tecnología, Personas, Procesos y Datos.'
  y = wrapText(what1, M + 8, y, W - 10, 5.2); y += 3
  const what2 = 'Su objetivo es ofrecer una fotografía rápida del nivel de exposición al riesgo de su organización, identificar las áreas de mayor vulnerabilidad y orientar las prioridades de mejora. No reemplaza a una auditoría técnica exhaustiva, sino que constituye el punto de partida ideal para una estrategia de seguridad efectiva.'
  wrapText(what2, M + 8, y, W - 10, 5.2)

  addPageNumber()

  // ── PÁGINA 2: RESULTADOS ──
  doc.addPage()

  setFill(NAVY); doc.rect(0, 0, PW, 18, 'F')
  doc.setFontSize(11); doc.setFont('helvetica', 'bold'); setColor(WHITE)
  doc.text('Resultados del Análisis de Riesgo', M, 12)
  doc.setFontSize(8); doc.setFont('helvetica', 'normal'); setColor([150, 170, 210] as RGB)
  doc.text(meta?.empresa || '', PW - M, 12, { align: 'right' })

  y = 28
  const totalScore = scores?.total ?? null
  const totalColor = riskColor(totalScore)
  const totalLabel = riskLabel(totalScore)

  setFill(NAVY); doc.roundedRect(M, y, W, 32, 4, 4, 'F')
  doc.setFontSize(32); doc.setFont('helvetica', 'bold')
  doc.setTextColor(totalColor[0], totalColor[1], totalColor[2])
  doc.text(totalScore !== null ? totalScore.toString() : '—', M + 22, y + 21, { align: 'center' })

  setDraw([50, 60, 90] as RGB); doc.setLineWidth(0.3)
  doc.line(M + 44, y + 6, M + 44, y + 26)

  doc.setFontSize(9); setColor([150, 170, 210] as RGB); doc.setFont('helvetica', 'normal')
  doc.text('SCORE GLOBAL', M + 52, y + 10)
  doc.setFontSize(18); doc.setFont('helvetica', 'bold')
  doc.setTextColor(totalColor[0], totalColor[1], totalColor[2])
  doc.text(totalLabel, M + 52, y + 22)

  doc.setFontSize(7.5); setColor([120, 140, 180] as RGB); doc.setFont('helvetica', 'normal')
  doc.text('Escala: BAJO (0-5)  ·  MEDIO (6-11)  ·  ALTO (12-19)  ·  CRÍTICO (20+)', PW - M - 2, y + 29, { align: 'right' })

  y += 40
  doc.setFontSize(11); doc.setFont('helvetica', 'bold'); setColor(NAVY)
  doc.text('Desglose por área de análisis', M, y); y += 8

  const sections = [
    { key: 'TECNOLOGIA', label: 'Tecnología', icon: 'T' },
    { key: 'PERSONAS',   label: 'Personas',   icon: 'P' },
    { key: 'PROCESOS',   label: 'Procesos',   icon: 'PR' },
    { key: 'DATOS',      label: 'Datos',      icon: 'D' },
  ]

  for (const s of sections) {
    const avg = scores?.sections?.[s.key]?.avg ?? null
    const col = riskColor(avg)
    const lbl = riskLabel(avg)
    const pct = avg !== null ? Math.min(avg / 25, 1) : 0

    setFill(LGRAY); doc.roundedRect(M, y, W, 16, 2, 2, 'F')
    setFill(BLUE); doc.circle(M + 8, y + 8, 5, 'F')
    doc.setFontSize(7); doc.setFont('helvetica', 'bold'); setColor(WHITE)
    doc.text(s.icon, M + 8, y + 9.5, { align: 'center' })

    doc.setFontSize(10); doc.setFont('helvetica', 'bold'); setColor(NAVY)
    doc.text(s.label, M + 16, y + 7)

    doc.setFontSize(8); doc.setFont('helvetica', 'bold')
    doc.setTextColor(col[0], col[1], col[2])
    doc.text(lbl, M + 16, y + 13)

    doc.setFontSize(13); doc.setFont('helvetica', 'bold')
    doc.setTextColor(col[0], col[1], col[2])
    doc.text(avg !== null ? avg.toString() : '—', M + 62, y + 11, { align: 'center' })

    const barX = M + 70, barW = W - 70 - 5
    drawBar(barX, y + 5, barW, 6, avg, 25)
    doc.setFontSize(7.5); setColor(GRAY); doc.setFont('helvetica', 'normal')
    doc.text(`${Math.round(pct * 100)}%`, barX + barW + 2, y + 10)

    y += 20
  }

  y += 4
  doc.setFontSize(11); doc.setFont('helvetica', 'bold'); setColor(NAVY)
  doc.text('Interpretación del resultado', M, y); y += 7

  const interpretaciones: Record<string, string> = {
    BAJO:    'Su organización muestra una postura de seguridad relativamente sólida. Se recomienda mantener y formalizar las prácticas actuales, y avanzar hacia controles más maduros para consolidar la protección.',
    MEDIO:   'Se detectan áreas de mejora importantes. Su organización tiene controles básicos implementados, pero existen brechas que podrían ser aprovechadas por amenazas. Es el momento ideal para estructurar un plan de acción.',
    ALTO:    'El nivel de riesgo es significativo. Existen vulnerabilidades concretas que requieren atención prioritaria. Se recomienda iniciar con urgencia la implementación de controles correctivos en las áreas más comprometidas.',
    CRÍTICO: 'Se han detectado riesgos críticos que exponen seriamente a su organización. Es indispensable tomar medidas inmediatas. Un incidente en este contexto podría tener consecuencias graves para la operación, los datos y la reputación.',
  }
  const interp = interpretaciones[totalLabel] || interpretaciones['MEDIO']

  setFill(LGRAY); doc.roundedRect(M, y, W, 26, 3, 3, 'F')
  setFill(totalColor); doc.roundedRect(M, y, 3, 26, 1.5, 1.5, 'F')
  doc.setFontSize(9.5); doc.setFont('helvetica', 'normal'); setColor([40, 55, 90] as RGB)
  wrapText(interp, M + 8, y + 7, W - 12, 5.2)
  y += 32

  doc.setFontSize(11); doc.setFont('helvetica', 'bold'); setColor(NAVY)
  doc.text('¿Cuáles son los próximos pasos?', M, y); y += 8

  const pasos: [string, string, string][] = [
    ['1', 'Revisión detallada con un especialista', 'Un consultor de AllSafe analizará en profundidad las áreas críticas identificadas y propondrá un plan de acción personalizado.'],
    ['2', 'Plan de mejora priorizado',              'Definiremos juntos un roadmap de seguridad realista, ajustado a su presupuesto y necesidades operativas.'],
    ['3', 'Implementación y seguimiento',           'Acompañamos la ejecución de los controles y realizamos seguimientos periódicos para asegurar la mejora continua.'],
  ]

  for (const [num, titulo, desc] of pasos) {
    setFill(BLUE); doc.circle(M + 5, y + 3, 4, 'F')
    doc.setFontSize(9); doc.setFont('helvetica', 'bold'); setColor(WHITE)
    doc.text(num, M + 5, y + 4.5, { align: 'center' })

    doc.setFontSize(9.5); doc.setFont('helvetica', 'bold'); setColor(NAVY)
    doc.text(titulo, M + 13, y + 4)
    doc.setFont('helvetica', 'normal'); setColor(GRAY); doc.setFontSize(9)
    y = wrapText(desc, M + 13, y + 9, W - 15, 4.8)
    y += 5
  }

  if (y < PH - 40) {
    y = PH - 40
    setFill([230, 236, 250] as RGB); doc.rect(M, y, W, 0.3, 'F')
    y += 6
    doc.setFontSize(9); doc.setFont('helvetica', 'bold'); setColor(NAVY)
    doc.text('AllSafe Security Solutions', M, y)
    doc.setFont('helvetica', 'normal'); setColor(GRAY); doc.setFontSize(8.5)
    doc.text('info@allsafe.com.ar  ·  www.allsafe.com.ar', M, y + 6)
    doc.setFontSize(8); setColor([150, 160, 180] as RGB)
    doc.text('Este informe es de carácter preliminar y confidencial. Su contenido está destinado exclusivamente al destinatario indicado.', M, y + 13)
  }

  addPageNumber()

  doc.save(`AllSafe_ARP_${(meta?.empresa || 'contacto').replace(/\s+/g, '_')}_${new Date().toISOString().slice(0, 10)}.pdf`)
}

// ─── Budget PDF ───────────────────────────────────────────────────────────────

function fmtN(v: number | string | undefined | null): string {
  if (v == null || v === '') return '—'
  const n = Number(v)
  if (isNaN(n)) return '—'
  return `$ ${n.toLocaleString('es-AR', { minimumFractionDigits: 0, maximumFractionDigits: 0 })}`
}

export interface BudgetForPDF {
  number: string
  title: string
  typeLabel: string
  currency: string
  exchange_rate_usd?: number | null
  exchange_rate_type?: string | null
  paymentTermsLabel: string
  duration_months?: number | null
  discount_pct: number
  exclusions_text?: string | null
  costs_subject_to_review?: number | boolean | null
  valid_until?: string | null
  description?: string | null
  client_nombre?: string | null
  preparer?: string | null
  items: {
    group_name?: string | null
    description: string
    unit: string
    quantity: number
    unit_price_ars: number
    is_optional?: boolean | null
    is_estimated?: boolean | null
  }[]
  total: number
}

export function generateBudgetPDF(b: BudgetForPDF) {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' }) as any
  const PW = 210, PH = 297, M = 13
  const W = PW - M * 2

  const setColor = (rgb: RGB) => doc.setTextColor(rgb[0], rgb[1], rgb[2])
  const setFill  = (rgb: RGB) => doc.setFillColor(rgb[0], rgb[1], rgb[2])
  const setDraw  = (rgb: RGB) => doc.setDrawColor(rgb[0], rgb[1], rgb[2])
  const wrapText = (text: string, x: number, y: number, maxW: number, lineH = 4.8) => {
    const lines = doc.splitTextToSize(text, maxW)
    doc.text(lines, x, y)
    return y + lines.length * lineH
  }

  // ── HEADER (navy background) ──
  const HDR = 34
  setFill(NAVY); doc.rect(0, 0, PW, HDR, 'F')
  setFill(BLUE); doc.rect(0, HDR, PW, 2, 'F')

  try { doc.addImage(LOGO_B64, 'JPEG', PW - M - 36, 4, 36, 14) } catch {}

  doc.setFontSize(20); doc.setFont('helvetica', 'bold'); setColor(WHITE)
  doc.text('PROPUESTA ECONÓMICA', M, 14)

  doc.setFontSize(8.5); doc.setFont('helvetica', 'bold'); setColor([200, 215, 255] as RGB)
  doc.text(b.number, M, 21)
  const numW = doc.getTextWidth(b.number)
  doc.setFont('helvetica', 'normal'); setColor([150, 170, 210] as RGB)
  if (b.title) doc.text(` — ${b.title}`, M + numW, 21)

  doc.setFontSize(7.5); doc.setFont('helvetica', 'normal'); setColor([120, 145, 190] as RGB)
  doc.text(b.preparer ? `AllSafe Security Solutions — ${b.preparer}` : 'AllSafe Security Solutions', M, 28)

  let y = HDR + 8

  // ── INTRO (compact, 1 paragraph) ──
  const intro = 'AllSafe Security Solutions es una empresa especializada en ciberseguridad con foco en la protección de la información y la continuidad operativa. La presente propuesta fue preparada en base a los requerimientos específicos relevados con su organización.'
  const iLines = doc.splitTextToSize(intro, W - 10)
  const introH = iLines.length * 4.6 + 9
  setFill(LGRAY); doc.roundedRect(M, y, W, introH, 2, 2, 'F')
  setFill(BLUE);  doc.roundedRect(M, y, 3, introH, 1.5, 1.5, 'F')
  doc.setFontSize(8.5); doc.setFont('helvetica', 'normal'); setColor([40, 55, 90] as RGB)
  wrapText(intro, M + 7, y + 6, W - 11, 4.6)
  y += introH + 5

  // ── METADATA (2-column text, compact) ──
  const tcLabel = b.exchange_rate_type ? `TC ${b.exchange_rate_type.toUpperCase()} REF.` : 'TC OFICIAL REF.'
  const tcValue = b.exchange_rate_usd ? `$ ${b.exchange_rate_usd.toLocaleString('es-AR')}` : '—'
  const colR = M + W / 2 + 2
  const halfW = W / 2 - 6

  const metaRows: [string, string, string, string][] = [
    ['CLIENTE',        b.client_nombre || '—',                             'MODALIDAD',          b.typeLabel],
    ['FORMA DE PAGO',  b.paymentTermsLabel,                                'DURACIÓN',           b.duration_months ? `${b.duration_months} meses` : '—'],
    ['MONEDA',         b.currency,                                         'VIGENCIA PROPUESTA', b.valid_until ? b.valid_until.slice(0, 10) : '—'],
    [tcLabel,          tcValue,                                            '',                   ''],
  ]

  for (const [lbl1, val1, lbl2, val2] of metaRows) {
    const rowY = y
    doc.setFontSize(6.5); doc.setFont('helvetica', 'bold'); setColor(BLUE)
    doc.text(lbl1, M, rowY)
    doc.setFontSize(9); doc.setFont('helvetica', 'normal'); setColor(NAVY)
    const l1 = doc.splitTextToSize(val1, halfW)
    doc.text(l1, M, rowY + 4)

    let rightH = 0
    if (lbl2) {
      doc.setFontSize(6.5); doc.setFont('helvetica', 'bold'); setColor(BLUE)
      doc.text(lbl2, colR, rowY)
      doc.setFontSize(9); doc.setFont('helvetica', 'normal'); setColor(NAVY)
      const l2 = doc.splitTextToSize(val2, halfW)
      doc.text(l2, colR, rowY + 4)
      rightH = l2.length * 4.2
    }

    y = rowY + Math.max(l1.length * 4.2, rightH) + 8
  }
  y += 1

  // ── DESCRIPTION ──
  if (b.description) {
    const descLines = doc.splitTextToSize(b.description, W - 10)
    const descH = descLines.length * 4.6 + 9
    setFill(LGRAY); doc.roundedRect(M, y, W, descH, 2, 2, 'F')
    setFill(BLUE);  doc.roundedRect(M, y, 3, descH, 1.5, 1.5, 'F')
    doc.setFontSize(8.5); doc.setFont('helvetica', 'normal'); setColor([40, 55, 90] as RGB)
    wrapText(b.description, M + 7, y + 6, W - 10, 4.6)
    y += descH + 4
  }

  // ── DESGLOSE DE SERVICIOS ──
  doc.setFontSize(10); doc.setFont('helvetica', 'bold'); setColor(NAVY)
  doc.text('Desglose de Servicios', M, y); y += 4

  const tableRows = b.items.map(it => [
    it.description + (it.is_optional ? ' (Opc.)' : '') + (it.is_estimated ? ' (Est.)' : ''),
    it.unit,
    fmtN(it.unit_price_ars),
    Number(it.quantity).toLocaleString('es-AR'),
    it.is_optional ? '—' : fmtN(Number(it.quantity) * Number(it.unit_price_ars)),
  ])

  autoTable(doc, {
    startY: y,
    margin: { left: M, right: M },
    head: [['Descripción', 'Unidad', 'Precio unitario', 'Cant.', 'Total']],
    body: tableRows,
    foot: [['', '', '', 'INVERSIÓN TOTAL', fmtN(b.total)]],
    theme: 'grid',
    styles: { fontSize: 8, cellPadding: 2, lineColor: [220, 225, 235] as RGB, lineWidth: 0.3 },
    headStyles: { fillColor: NAVY as RGB, textColor: WHITE as RGB, fontStyle: 'bold', fontSize: 8 },
    footStyles: { fillColor: NAVY as RGB, textColor: WHITE as RGB, fontStyle: 'bold', halign: 'right', fontSize: 8 },
    columnStyles: {
      0: { cellWidth: 'auto' as const },
      1: { cellWidth: 18, halign: 'center' as const, textColor: GRAY as RGB },
      2: { cellWidth: 32, halign: 'right' as const },
      3: { cellWidth: 14, halign: 'right' as const },
      4: { cellWidth: 32, halign: 'right' as const, fontStyle: 'bold', textColor: NAVY as RGB },
    },
    didParseCell: (data: any) => {
      if (data.section === 'body' && b.items[data.row.index]?.is_optional) {
        data.cell.styles.textColor = [100, 110, 130]
      }
    },
  })

  y = (doc.lastAutoTable?.finalY ?? y) + 5

  // ── CRONOGRAMA + NOTAS (inline, compact) ──
  if (b.duration_months && b.duration_months > 1 && b.total > 0) {
    const monthly = fmtN(Math.round(b.total / b.duration_months))
    setFill([237, 242, 255] as RGB); doc.roundedRect(M, y, W, 10, 2, 2, 'F')
    setDraw(BLUE); doc.setLineWidth(0.4)
    doc.roundedRect(M, y, W, 10, 2, 2, 'S')
    doc.setFontSize(8); doc.setFont('helvetica', 'bold'); setColor(NAVY)
    doc.text('Cronograma de pago mensual:', M + 4, y + 6.5)
    doc.setFont('helvetica', 'normal'); setColor(BLUE)
    doc.text(`${monthly} × ${b.duration_months} meses`, M + 60, y + 6.5)
    y += 13
  }

  if (b.discount_pct > 0) {
    doc.setFontSize(7.5); doc.setFont('helvetica', 'italic'); setColor(GRAY)
    doc.text(`* Descuento aplicado: ${b.discount_pct}%`, M, y); y += 5
  }

  // ── EL PRESUPUESTO NO INCLUYE ──
  if (b.exclusions_text) {
    const excLines = doc.splitTextToSize(b.exclusions_text, W - 10)
    const excH = excLines.length * 4.6 + 12
    setFill(LGRAY); doc.roundedRect(M, y, W, excH, 2, 2, 'F')
    doc.setFontSize(8.5); doc.setFont('helvetica', 'bold'); setColor(NAVY)
    doc.text('El presupuesto no incluye:', M + 4, y + 6)
    doc.setFontSize(8); doc.setFont('helvetica', 'normal'); setColor(GRAY)
    wrapText(b.exclusions_text, M + 4, y + 11, W - 8, 4.6)
    y += excH + 4
  }

  if (b.costs_subject_to_review) {
    doc.setFontSize(7.5); doc.setFont('helvetica', 'italic'); setColor(GRAY)
    doc.text('* Costos sujetos a confirmación post-Fase 1 de diagnóstico.', M, y)
    y += 5
  }

  // ── FOOTER ──
  const footY = Math.max(y + 3, PH - 28)
  setFill([220, 226, 240] as RGB); doc.rect(M, footY - 2, W, 0.3, 'F')
  doc.setFontSize(7.5); doc.setFont('helvetica', 'italic'); setColor([60, 75, 105] as RGB)
  let fy = wrapText('Los servicios y valores indicados están sujetos a las condiciones vigentes de AllSafe Security Solutions. Ante cualquier consulta no dude en contactarnos.', M, footY + 2, W, 4.3)
  doc.setFontSize(7); setColor([130, 140, 160] as RGB)
  wrapText('Esta propuesta es de carácter estrictamente confidencial, destinada exclusivamente a la organización indicada y no debe ser reproducida sin autorización.', M, fy + 1, W, 4.2)

  doc.save(`AllSafe_${b.number}_${(b.client_nombre || 'propuesta').replace(/[^a-zA-Z0-9]/g, '_')}.pdf`)
}
