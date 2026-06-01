/**
 * Writeup PDF Generator — Gungnir
 * Genera writeups estructurados para plataformas de práctica:
 * HackTheBox, TryHackMe, OSCP Lab, Bug Bounty (VDP/BBP)
 * Writeups para plataformas de práctica — Gungnir.
 */

import jsPDF from 'jspdf'
import { LOGO_B64 } from './pdf'

type RGB = [number, number, number]

// ─── Tipos ────────────────────────────────────────────────────────────────────
export type WriteupPlatform = 'htb' | 'thm' | 'oscp' | 'bugbounty'

export interface WriteupData {
  platform: WriteupPlatform
  // Common
  title: string
  author: string
  date: string
  difficulty?: string
  os?: string
  ip?: string
  // HTB / THM
  machine_name?: string
  user_flag?: string
  root_flag?: string
  points?: string
  // OSCP
  hostname?: string
  local_proof?: string
  proof?: string
  // Bug Bounty
  program?: string
  severity?: string
  cvss?: string
  bounty?: string
  affected_url?: string
  // Content sections
  summary?: string
  enumeration?: string
  foothold?: string
  privilege_escalation?: string
  post_exploitation?: string
  flags?: string
  // Bug bounty specific
  description?: string
  steps_to_reproduce?: string
  impact?: string
  remediation?: string
  // OSCP
  service_enum?: string
  exploitation?: string
  screenshots?: string
  // General
  tools_used?: string
  lessons_learned?: string
}

// ─── Paletas por plataforma ───────────────────────────────────────────────────
const PLATFORM_STYLES: Record<WriteupPlatform, {
  label: string; headerBg: RGB; headerText: RGB; accent: RGB; badge: RGB
}> = {
  htb: {
    label: 'HackTheBox',
    headerBg: [15, 20, 30],
    headerText: [159, 239, 0],
    accent: [159, 239, 0],
    badge: [26, 36, 56],
  },
  thm: {
    label: 'TryHackMe',
    headerBg: [20, 20, 50],
    headerText: [212, 6, 140],
    accent: [212, 6, 140],
    badge: [30, 20, 50],
  },
  oscp: {
    label: 'OSCP Lab Report',
    headerBg: [193, 41, 46],
    headerText: [255, 255, 255],
    accent: [193, 41, 46],
    badge: [60, 10, 10],
  },
  bugbounty: {
    label: 'Bug Bounty Report',
    headerBg: [15, 50, 100],
    headerText: [255, 255, 255],
    accent: [37, 99, 235],
    badge: [10, 30, 80],
  },
}

const SEV_COLOR: Record<string, RGB> = {
  critical: [220, 38, 38], high: [234, 88, 12], medium: [161, 98, 7], low: [37, 99, 235], info: [100, 116, 139],
}

// ─── Generador ────────────────────────────────────────────────────────────────
export function generateWriteup(data: WriteupData) {
  const style = PLATFORM_STYLES[data.platform]
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' }) as any

  const PW = 210, PH = 297, M = 15
  const W = PW - M * 2
  const WHITE: RGB = [255, 255, 255]
  const GRAY: RGB = [120, 130, 150]
  const DARK: RGB = [30, 35, 50]
  const LGRAY: RGB = [245, 247, 252]

  const setColor = (rgb: RGB) => doc.setTextColor(rgb[0], rgb[1], rgb[2])
  const setFill  = (rgb: RGB) => doc.setFillColor(rgb[0], rgb[1], rgb[2])
  const setDraw  = (rgb: RGB) => doc.setDrawColor(rgb[0], rgb[1], rgb[2])

  let currentPage = 0
  const newPage = () => {
    if (currentPage > 0) {
      // Footer on previous page
      doc.setFontSize(7); setColor(GRAY)
      doc.setFont('helvetica', 'normal')
      doc.text(`${style.label} — ${data.machine_name || data.title || 'Writeup'}`, M, PH - 7)
      doc.text(String(currentPage), PW - M, PH - 7, { align: 'right' })
      setFill(style.accent); doc.rect(M, PH - 10, W, 0.4, 'F')
      doc.addPage()
    }
    currentPage++

    // Page header bar
    setFill(style.headerBg); doc.rect(0, 0, PW, 14, 'F')
    doc.setFontSize(8); doc.setFont('helvetica', 'bold'); setColor(style.headerText)
    doc.text(style.label.toUpperCase(), M, 9)
    doc.setFont('helvetica', 'normal'); setColor(GRAY)
    doc.text(data.machine_name || data.title || '', PW - M, 9, { align: 'right' })

    return 20
  }

  const section = (title: string, content: string, y: number): number => {
    if (!content?.trim()) return y
    // Check if we need a new page
    const estimatedLines = doc.splitTextToSize(content, W).length
    if (y + estimatedLines * 5 + 15 > PH - 20) {
      y = newPage()
    }

    doc.setFontSize(10); doc.setFont('helvetica', 'bold')
    setFill(style.accent)
    doc.rect(M, y - 1, 2.5, 6.5, 'F')
    setColor(DARK)
    doc.text(title, M + 5, y + 4)
    y += 10

    doc.setFontSize(9); doc.setFont('helvetica', 'normal'); setColor([50, 60, 80] as RGB)
    const lines = doc.splitTextToSize(content, W)
    // Check again after calculating actual lines
    if (y + lines.length * 5 > PH - 20) {
      y = newPage()
    }
    doc.text(lines, M, y)
    y += lines.length * 5 + 8

    return y
  }

  const infoRow = (label: string, value: string, x: number, y: number, colW: number): void => {
    doc.setFontSize(7.5); doc.setFont('helvetica', 'bold'); setColor(GRAY)
    doc.text(label.toUpperCase(), x, y)
    doc.setFont('helvetica', 'normal'); setColor(DARK)
    doc.text(value || '—', x, y + 5)
  }

  // ─────────────────────────────────────────────────────────────────────────
  // PORTADA
  // ─────────────────────────────────────────────────────────────────────────
  currentPage = 1

  // Cover header — full height dark block
  setFill(style.headerBg); doc.rect(0, 0, PW, 90, 'F')

  // Platform logo / label
  try { doc.addImage(LOGO_B64, 'JPEG', M, 10, 35, 13) } catch {}

  const platY = 18
  doc.setFontSize(9); doc.setFont('helvetica', 'bold')
  setColor(style.headerText)
  doc.text(style.label.toUpperCase() + ' WRITEUP', PW - M, platY, { align: 'right' })

  // Machine / target name
  doc.setFontSize(28); doc.setFont('helvetica', 'bold')
  setColor(WHITE)
  const titleStr = data.machine_name || data.title || 'Writeup'
  const titleLines = doc.splitTextToSize(titleStr, W)
  doc.text(titleLines, M, 48)

  // Difficulty / OS badge
  if (data.difficulty || data.os) {
    doc.setFontSize(9); doc.setFont('helvetica', 'normal')
    setColor(style.headerText)
    doc.text([data.os, data.difficulty].filter(Boolean).join('  ·  '), M, 48 + titleLines.length * 10)
  }

  // Accent bar
  setFill(style.accent); doc.rect(0, 88, PW, 2, 'F')

  // Info card
  let y = 100
  setFill(LGRAY); doc.roundedRect(M, y, W, 35, 3, 3, 'F')
  setDraw([220, 225, 235] as RGB); doc.setLineWidth(0.3)
  doc.roundedRect(M, y, W, 35, 3, 3, 'S')

  const cW = W / 4
  if (data.platform === 'htb' || data.platform === 'thm') {
    infoRow('IP / Objetivo', data.ip || '', M + 5, y + 8, cW)
    infoRow('Sistema operativo', data.os || '', M + 5 + cW, y + 8, cW)
    infoRow('Dificultad', data.difficulty || '', M + 5 + cW * 2, y + 8, cW)
    infoRow('Puntos', data.points || '', M + 5 + cW * 3, y + 8, cW)
    infoRow('User flag', data.user_flag ? data.user_flag.slice(0, 20) + '...' : '—', M + 5, y + 22, cW * 2)
    infoRow('Root flag', data.root_flag ? data.root_flag.slice(0, 20) + '...' : '—', M + 5 + cW * 2, y + 22, cW * 2)
  } else if (data.platform === 'oscp') {
    infoRow('Hostname', data.hostname || '', M + 5, y + 8, cW)
    infoRow('IP', data.ip || '', M + 5 + cW, y + 8, cW)
    infoRow('OS', data.os || '', M + 5 + cW * 2, y + 8, cW)
    infoRow('Dificultad', data.difficulty || '', M + 5 + cW * 3, y + 8, cW)
    infoRow('Local proof', data.local_proof ? data.local_proof.slice(0, 25) + '...' : '—', M + 5, y + 22, cW * 2)
    infoRow('Proof', data.proof ? data.proof.slice(0, 25) + '...' : '—', M + 5 + cW * 2, y + 22, cW * 2)
  } else if (data.platform === 'bugbounty') {
    infoRow('Programa', data.program || '', M + 5, y + 8, cW * 2)
    infoRow('Severidad', data.severity || '', M + 5 + cW * 2, y + 8, cW)
    infoRow('CVSS', data.cvss || '', M + 5 + cW * 3, y + 8, cW)
    infoRow('URL afectada', data.affected_url ? data.affected_url.slice(0, 40) : '—', M + 5, y + 22, W - 10)
  }

  y += 45

  // Author + date
  doc.setFontSize(9); doc.setFont('helvetica', 'normal'); setColor(GRAY)
  const dateStr = data.date || new Date().toLocaleDateString('es-AR')
  doc.text(`Autor: ${data.author || 'Anónimo'}  ·  Fecha: ${dateStr}`, M, y)

  // Severity badge for bug bounty
  if (data.platform === 'bugbounty' && data.severity) {
    const sevCol = SEV_COLOR[(data.severity || '').toLowerCase()] || SEV_COLOR.info
    setFill(sevCol); doc.roundedRect(PW - M - 28, y - 5, 28, 11, 2, 2, 'F')
    doc.setFontSize(9); doc.setFont('helvetica', 'bold'); setColor(WHITE)
    doc.text((data.severity || '').toUpperCase(), PW - M - 14, y + 2, { align: 'center' })
  }

  // Footer on cover
  setFill(style.accent); doc.rect(M, PH - 10, W, 0.4, 'F')
  doc.setFontSize(7); doc.setFont('helvetica', 'normal'); setColor(GRAY)
  doc.text('Generado con Gungnir', M, PH - 5)
  doc.text('1', PW - M, PH - 5, { align: 'right' })

  // ─────────────────────────────────────────────────────────────────────────
  // CONTENIDO
  // ─────────────────────────────────────────────────────────────────────────
  y = newPage()

  if (data.platform === 'htb' || data.platform === 'thm') {
    y = section('Resumen', data.summary || '', y)
    y = section('Enumeración', data.enumeration || '', y)
    y = section('Foothold / Acceso inicial', data.foothold || '', y)
    y = section('Escalada de privilegios', data.privilege_escalation || '', y)
    if (data.post_exploitation) y = section('Post-explotación', data.post_exploitation, y)
    if (data.flags) {
      // Flags box
      if (y + 30 > PH - 20) y = newPage()
      setFill([12, 20, 30] as RGB); doc.roundedRect(M, y, W, 28, 3, 3, 'F')
      setFill(style.accent); doc.roundedRect(M, y, 3, 28, 2, 2, 'F')
      doc.setFontSize(9); doc.setFont('helvetica', 'bold'); setColor(style.headerText)
      doc.text('FLAGS', M + 7, y + 8)
      doc.setFont('helvetica', 'normal'); setColor(WHITE)
      doc.setFontSize(8.5)
      if (data.user_flag) doc.text(`User: ${data.user_flag}`, M + 7, y + 16)
      if (data.root_flag)  doc.text(`Root: ${data.root_flag}`, M + 7, y + 22)
      y += 36
    }
  } else if (data.platform === 'oscp') {
    // OSCP format follows the official template structure
    y = section('Resumen del laboratorio', data.summary || '', y)
    y = section('Enumeración de servicios', data.service_enum || data.enumeration || '', y)
    y = section('Explotación', data.exploitation || data.foothold || '', y)
    y = section('Escalada de privilegios', data.privilege_escalation || '', y)
    if (data.post_exploitation) y = section('Post-explotación', data.post_exploitation, y)
    if (data.local_proof || data.proof) {
      if (y + 30 > PH - 20) y = newPage()
      setFill([20, 10, 10] as RGB); doc.roundedRect(M, y, W, 24, 3, 3, 'F')
      setFill(style.accent); doc.roundedRect(M, y, 3, 24, 2, 2, 'F')
      doc.setFontSize(9); doc.setFont('helvetica', 'bold'); setColor(WHITE)
      doc.text('PROOF HASHES', M + 7, y + 8)
      doc.setFont('helvetica', 'normal'); doc.setFontSize(8)
      if (data.local_proof) doc.text(`local.txt: ${data.local_proof}`, M + 7, y + 16)
      if (data.proof) doc.text(`proof.txt: ${data.proof}`, M + 7 + (data.local_proof ? 100 : 0), y + 16)
      y += 32
    }
  } else if (data.platform === 'bugbounty') {
    y = section('Descripción de la vulnerabilidad', data.description || data.summary || '', y)
    y = section('Pasos para reproducir', data.steps_to_reproduce || '', y)
    y = section('Impacto', data.impact || '', y)
    y = section('Recomendación de remediación', data.remediation || '', y)
  }

  if (data.tools_used) y = section('Herramientas utilizadas', data.tools_used, y)
  if (data.lessons_learned) y = section('Lecciones aprendidas', data.lessons_learned, y)

  // Last page footer
  doc.setFontSize(7); setColor(GRAY)
  doc.setFont('helvetica', 'normal')
  const nameStr = data.machine_name || data.title || 'Writeup'
  doc.text(`${style.label} — ${nameStr}`, M, PH - 7)
  doc.text(String(currentPage), PW - M, PH - 7, { align: 'right' })
  setFill(style.accent); doc.rect(M, PH - 10, W, 0.4, 'F')

  // Save
  const safeName = (data.machine_name || data.title || 'writeup').replace(/[^a-zA-Z0-9_-]/g, '_')
  const fname = `Writeup_${style.label.replace(/[^a-zA-Z]/g,'_')}_${safeName}_${data.date || new Date().toISOString().slice(0,10)}.pdf`
  doc.save(fname)
}
