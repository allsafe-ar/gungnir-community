/**
 * Gungnir - Security Research Paper PDF generator
 * Envía datos al backend (Puppeteer) y descarga el PDF.
 */

export interface PaperData {
  title:               string
  template?:           string   // usenix | ndss | ieee_sp | acm_ccs | blackhat | defcon | ekoparty | bsides | exploitdb | neutral
  category?:           string   // vuln_research | attack_technique | threat_intel | malware_analysis | tool_analysis | ctf_research | general
  tags?:               string
  authors?:            string
  date?:               string
  cve_id?:             string
  advisory_url?:       string
  cvss_vector?:        string
  cvss_score?:         number
  // Sections (16)
  abstract_text?:      string
  introduction?:       string
  background?:         string
  threat_model?:       string
  methodology?:        string
  vuln_description?:   string
  root_cause?:         string
  impact?:             string
  evidence?:           string
  severity_section?:   string
  mitigations?:        string
  ethics?:             string
  conclusions?:        string
  references_text?:    string
  disclosure_timeline?:string
  appendices?:         string
  status?:             string
}

export async function generatePaperPDF(data: PaperData): Promise<void> {
  const res = await fetch('/api/reports/paper', {
    method: 'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${localStorage.getItem('gungnir_token') ?? ''}`,
    },
    body: JSON.stringify(data),
  })

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Error desconocido' }))
    throw new Error(err.error ?? `HTTP ${res.status}`)
  }

  const blob  = await res.blob()
  const url   = URL.createObjectURL(blob)
  const cd    = res.headers.get('Content-Disposition') ?? ''
  const match = cd.match(/filename="([^"]+)"/)
  const fname = match?.[1] ?? `Gungnir_Paper_${new Date().toISOString().slice(0, 10)}.pdf`

  const a    = document.createElement('a')
  a.href     = url
  a.download = fname
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 5000)
}
