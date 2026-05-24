/**
 * HallazgoSheet — Create/edit a finding within the engagement workspace.
 * Slides in from the right as a Sheet. Integrates CvssEditor.
 */

import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { Save, Trash2, X, BookMarked, ChevronDown, Search, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Separator } from '@/components/ui/separator'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { CvssEditor, DEFAULT_VECTOR, vectorToString, stringToVector, calcCvss31, type CvssVector } from './cvss-editor'
import { apiFetch } from '@/lib/api'
import { cn } from '@/lib/utils'

// ─── Tipos ────────────────────────────────────────────────────────────────────
interface HallazgoSheetProps {
  open: boolean
  onOpenChange: (v: boolean) => void
  engagementId: string
  defaultPhase?: string
  hallazgoId?: string          // si hay id → edición
  onSaved?: () => void
}

interface HallazgoData {
  title: string
  phase_type: string
  severity: string
  status: string
  affected_asset: string
  description: string
  steps_to_reproduce: string
  recommendation: string
  executive_summary: string
  cwe_id: string
  cwe_name: string
  owasp_category: string
  mitre_tactic: string
  mitre_technique_id: string
  mitre_technique_name: string
  business_risk: string
  exploitability: string
  cvss_vector_31: string
  cvss_score_31: number
}

const PHASES = [
  { value: 'planning',          label: 'Planificación' },
  { value: 'recon',             label: 'Reconocimiento' },
  { value: 'scanning',          label: 'Escaneo' },
  { value: 'exploitation',      label: 'Explotación' },
  { value: 'post_exploitation', label: 'Post-explotación' },
  { value: 'reporting',         label: 'Reporting' },
]

const SEVERITIES = [
  { value: 'critical', label: 'Crítico',  cls: 'bg-red-500/10 text-red-500 border-red-500/30' },
  { value: 'high',     label: 'Alto',     cls: 'bg-orange-500/10 text-orange-500 border-orange-500/30' },
  { value: 'medium',   label: 'Medio',    cls: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/30' },
  { value: 'low',      label: 'Bajo',     cls: 'bg-blue-500/10 text-blue-500 border-blue-500/30' },
  { value: 'info',     label: 'Info',     cls: 'bg-muted text-muted-foreground border-border' },
]

const STATUSES = [
  { value: 'open',           label: 'Abierto' },
  { value: 'in_remediation', label: 'En remediación' },
  { value: 'fixed',          label: 'Corregido' },
  { value: 'accepted',       label: 'Aceptado (riesgo)' },
]

const EXPLOITABILITIES = [
  { value: 'proven',      label: 'Comprobado' },
  { value: 'functional',  label: 'Funcional' },
  { value: 'poc',         label: 'PoC' },
  { value: 'theoretical', label: 'Teórico' },
]

function empty(defaultPhase = 'scanning'): HallazgoData {
  const v = DEFAULT_VECTOR
  return {
    title: '',
    phase_type: defaultPhase,
    severity: 'medium',
    status: 'open',
    affected_asset: '',
    description: '',
    steps_to_reproduce: '',
    recommendation: '',
    executive_summary: '',
    cwe_id: '',
    cwe_name: '',
    owasp_category: '',
    mitre_tactic: '',
    mitre_technique_id: '',
    mitre_technique_name: '',
    business_risk: 'medium',
    exploitability: 'theoretical',
    cvss_vector_31: vectorToString(v),
    cvss_score_31: 9.8,
  }
}

// ─── Componente ───────────────────────────────────────────────────────────────
export function HallazgoSheet({
  open, onOpenChange, engagementId, defaultPhase, hallazgoId, onSaved,
}: HallazgoSheetProps) {
  const isEdit = !!hallazgoId
  const [form, setForm] = useState<HallazgoData>(() => empty(defaultPhase))
  const [cvssVec, setCvssVec] = useState<CvssVector>(DEFAULT_VECTOR)
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [activeTab, setActiveTab] = useState<'basico' | 'cvss' | 'clasificacion' | 'remediacion'>('basico')
  const [templateSearch, setTemplateSearch] = useState('')
  const [templates, setTemplates] = useState<Record<string, unknown>[]>([])
  const [templateOpen, setTemplateOpen] = useState(false)
  const [cveId, setCveId] = useState('')
  const [cveLoading, setCveLoading] = useState(false)

  // Cargar hallazgo si es edición
  useEffect(() => {
    if (!open) return
    if (isEdit && hallazgoId) {
      apiFetch<Record<string, unknown>>(`/engagements/${engagementId}/findings/${hallazgoId}`)
        .then(d => {
          const f = d as Record<string, unknown>
          setForm({
            title:                String(f.title ?? ''),
            phase_type:           String(f.phase_type ?? defaultPhase ?? 'scanning'),
            severity:             String(f.severity ?? 'medium'),
            status:               String(f.status ?? 'open'),
            affected_asset:       String(f.affected_asset ?? ''),
            description:          String(f.description ?? ''),
            steps_to_reproduce:   String(f.steps_to_reproduce ?? ''),
            recommendation:       String(f.recommendation ?? ''),
            executive_summary:    String(f.executive_summary ?? ''),
            cwe_id:               String(f.cwe_id ?? ''),
            cwe_name:             String(f.cwe_name ?? ''),
            owasp_category:       String(f.owasp_category ?? ''),
            mitre_tactic:         String(f.mitre_tactic ?? ''),
            mitre_technique_id:   String(f.mitre_technique_id ?? ''),
            mitre_technique_name: String(f.mitre_technique_name ?? ''),
            business_risk:        String(f.business_risk ?? 'medium'),
            exploitability:       String(f.exploitability ?? 'theoretical'),
            cvss_vector_31:       String(f.cvss_vector_31 ?? vectorToString(DEFAULT_VECTOR)),
            cvss_score_31:        Number(f.cvss_score_31 ?? 0),
          })
          const parsed = stringToVector(String(f.cvss_vector_31 ?? ''))
          if (parsed) setCvssVec(parsed)
        })
        .catch(() => {})
    } else {
      setForm(empty(defaultPhase))
      setCvssVec(DEFAULT_VECTOR)
    }
    setActiveTab('basico')
  }, [open, hallazgoId, engagementId])

  const set = (k: keyof HallazgoData) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm(p => ({ ...p, [k]: e.target.value }))
  const setVal = (k: keyof HallazgoData) => (v: string) => setForm(p => ({ ...p, [k]: v }))

  function loadTemplates() {
    const q = templateSearch ? `?q=${encodeURIComponent(templateSearch)}` : ''
    apiFetch<Record<string, unknown>[]>(`/templates/findings${q}`)
      .then(d => setTemplates(d))
      .catch(() => {})
  }

  function applyTemplate(t: Record<string, unknown>) {
    setForm(prev => ({
      ...prev,
      title:                prev.title || String(t.title ?? ''),
      description:          String(t.description ?? prev.description ?? ''),
      steps_to_reproduce:   String(t.steps_to_reproduce ?? prev.steps_to_reproduce ?? ''),
      recommendation:       String(t.recommendation ?? prev.recommendation ?? ''),
      severity:             String(t.severity ?? prev.severity),
      cwe_id:               String(t.cwe_id ?? prev.cwe_id ?? ''),
      cwe_name:             String(t.cwe_name ?? prev.cwe_name ?? ''),
      owasp_category:       String(t.owasp_category ?? prev.owasp_category ?? ''),
      cvss_vector_31:       t.cvss_vector_31 ? String(t.cvss_vector_31) : prev.cvss_vector_31,
      cvss_score_31:        t.cvss_score_31 ? Number(t.cvss_score_31) : prev.cvss_score_31,
    }))
    if (t.cvss_vector_31) {
      const v = stringToVector(String(t.cvss_vector_31))
      if (v) setCvssVec(v)
    }
    setTemplateOpen(false)
    toast.success(`Template "${t.title}" aplicado`)
  }

  // ── CVE NVD lookup ────────────────────────────────────────────────────────────
  async function lookupCve() {
    const id = cveId.trim().toUpperCase()
    if (!id.match(/^CVE-\d{4}-\d{4,}$/)) {
      toast.error('Formato inválido. Usá CVE-YYYY-NNNNN')
      return
    }
    setCveLoading(true)
    try {
      const resp = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`,
        { headers: { Accept: 'application/json' } }
      )
      if (!resp.ok) throw new Error(`NVD respondió ${resp.status}`)
      const data = await resp.json()
      const vuln = data?.vulnerabilities?.[0]?.cve
      if (!vuln) { toast.error(`${id} no encontrado en NVD`); return }

      // Description (english preferred)
      const desc = (vuln.descriptions ?? []).find((d: {lang:string}) => d.lang === 'en')?.value ?? ''

      // CVSS 3.1 (prefer v31, fallback v30)
      const cvssMetric = (vuln.metrics?.cvssMetricV31 ?? vuln.metrics?.cvssMetricV30 ?? [])[0]
      const cvssData   = cvssMetric?.cvssData
      const vectorStr  = cvssData?.vectorString ?? null
      const score      = cvssData?.baseScore ?? null

      // CWE
      const cweRaw = (vuln.weaknesses ?? [])
        .flatMap((w: {description:{value:string}[]}) => w.description)
        .find((d: {value:string}) => d.value?.startsWith('CWE-'))?.value ?? ''

      // Apply to form
      setForm(prev => ({
        ...prev,
        description: prev.description || desc,
        cwe_id: prev.cwe_id || cweRaw,
        cvss_vector_31: vectorStr ? vectorStr.replace(/^CVSS:3\.\d\//, '') : prev.cvss_vector_31,
        cvss_score_31:  score ?? prev.cvss_score_31,
      }))

      // Sync CVSS editor
      if (vectorStr) {
        const cleanVec = vectorStr.replace(/^CVSS:3\.\d\//, '')
        const parsed = stringToVector(cleanVec)
        if (parsed) setCvssVec(parsed)
      }

      const scoreLabel = score ? ` — Score ${score}` : ''
      toast.success(`${id} cargado${scoreLabel}`)
      if (vectorStr || cweRaw) setActiveTab('clasificacion')
    } catch(e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Error al consultar NVD')
    } finally {
      setCveLoading(false)
    }
  }

  const handleCvssChange = (v: CvssVector) => {
    setCvssVec(v)
    // Calculate score on client — we import calcCvss31 logic via vectorToString
    // Score will be recalculated by CvssEditor internally; we sync vector string
    setForm(p => ({ ...p, cvss_vector_31: vectorToString(v) }))
  }

  const handleSubmit = async () => {
    if (!form.title.trim()) { toast.error('El título es requerido'); return }
    setSaving(true)
    try {
      const score = calcCvss31(cvssVec)
      const payload = {
        ...form,
        cvss_vector_31: vectorToString(cvssVec),
        cvss_score_31:  Math.round(score * 10) / 10,
      }
      if (isEdit) {
        await apiFetch(`/engagements/${engagementId}/findings/${hallazgoId}`, { method: 'PUT', body: JSON.stringify(payload) })
        toast.success('Hallazgo actualizado')
      } else {
        await apiFetch(`/engagements/${engagementId}/findings`, { method: 'POST', body: JSON.stringify(payload) })
        toast.success('Hallazgo registrado')
        setForm(empty(defaultPhase))
        setCvssVec(DEFAULT_VECTOR)
      }
      onSaved?.()
      onOpenChange(false)
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Error al guardar')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!isEdit || !hallazgoId) return
    if (!confirm('¿Eliminar este hallazgo? Esta acción no se puede deshacer.')) return
    setDeleting(true)
    try {
      await apiFetch(`/engagements/${engagementId}/findings/${hallazgoId}`, { method: 'DELETE' })
      toast.success('Hallazgo eliminado')
      onSaved?.()
      onOpenChange(false)
    } catch {
      toast.error('Error al eliminar')
    } finally {
      setDeleting(false)
    }
  }

  const TABS = [
    { id: 'basico',        label: 'Básico' },
    { id: 'cvss',          label: 'CVSS 3.1' },
    { id: 'clasificacion', label: 'Clasificación' },
    { id: 'remediacion',   label: 'Remediación' },
  ] as const

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side='right'
        className='w-full sm:max-w-2xl flex flex-col p-0 gap-0'
        hideCloseButton
      >
        {/* Header */}
        <SheetHeader className='px-6 py-4 border-b border-border flex-row items-center justify-between space-y-0'>
          <SheetTitle className='text-base font-semibold'>
            {isEdit ? 'Editar hallazgo' : 'Nuevo hallazgo'}
          </SheetTitle>
          <div className='flex items-center gap-2'>
            {/* Template selector */}
            <div className='relative'>
              <Button
                variant='outline' size='sm' className='h-7 gap-1.5 text-xs'
                onClick={() => { setTemplateOpen(o => !o); if (!templateOpen) loadTemplates() }}
              >
                <BookMarked className='size-3' />
                Template
                <ChevronDown className='size-3' />
              </Button>
              {templateOpen && (
                <div className='absolute right-0 top-full mt-1 w-72 z-50 rounded-md border border-border bg-popover shadow-lg'>
                  <div className='p-2 border-b border-border'>
                    <input
                      value={templateSearch}
                      onChange={e => { setTemplateSearch(e.target.value); loadTemplates() }}
                      placeholder='Buscar template...'
                      className='w-full rounded border border-border bg-background px-2 py-1 text-xs outline-none'
                      autoFocus
                    />
                  </div>
                  <div className='max-h-64 overflow-y-auto'>
                    {templates.length === 0 ? (
                      <p className='text-xs text-muted-foreground text-center py-4'>Sin templates</p>
                    ) : templates.map((t, i) => (
                      <button
                        key={String(t.id ?? i)}
                        onClick={() => applyTemplate(t)}
                        className='w-full text-left px-3 py-2 text-xs hover:bg-accent transition-colors flex items-center gap-2 border-b border-border/40 last:border-0'
                      >
                        <span className={cn('h-2 w-2 rounded-full shrink-0', {
                          'bg-red-500': t.severity === 'critical',
                          'bg-orange-500': t.severity === 'high',
                          'bg-yellow-500': t.severity === 'medium',
                          'bg-blue-500': t.severity === 'low',
                          'bg-muted-foreground': t.severity === 'info',
                        })} />
                        <span className='truncate'>{String(t.title ?? '')}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
            <Button variant='ghost' size='icon' className='h-7 w-7' onClick={() => { setTemplateOpen(false); onOpenChange(false) }}>
              <X className='size-4' />
            </Button>
          </div>
        </SheetHeader>

        {/* Tabs nav */}
        <div className='flex border-b border-border px-6'>
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'px-3 py-2.5 text-xs font-medium border-b-2 transition-colors -mb-px',
                activeTab === tab.id
                  ? 'border-primary text-foreground'
                  : 'border-transparent text-muted-foreground hover:text-foreground'
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Body (scrollable) */}
        <div className='flex-1 overflow-y-auto px-6 py-5'>
          {/* ── Tab: Básico ─────────────────────────────────── */}
          {activeTab === 'basico' && (
            <div className='space-y-4'>
              <div className='space-y-1.5'>
                <Label>Título <span className='text-destructive'>*</span></Label>
                <Input value={form.title} onChange={set('title')}
                  placeholder='SQL Injection en endpoint /api/login' autoFocus />
              </div>

              <div className='grid grid-cols-2 gap-4'>
                <div className='space-y-1.5'>
                  <Label>Fase</Label>
                  <Select value={form.phase_type} onValueChange={setVal('phase_type')}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {PHASES.map(p => <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className='space-y-1.5'>
                  <Label>Estado</Label>
                  <Select value={form.status} onValueChange={setVal('status')}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {STATUSES.map(s => <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Severity selector visual */}
              <div className='space-y-1.5'>
                <Label>Severidad</Label>
                <div className='flex gap-2 flex-wrap'>
                  {SEVERITIES.map(s => (
                    <button
                      key={s.value}
                      type='button'
                      onClick={() => setForm(p => ({ ...p, severity: s.value }))}
                      className={cn(
                        'rounded border px-3 py-1.5 text-xs font-bold transition-all',
                        form.severity === s.value
                          ? s.cls
                          : 'border-border text-muted-foreground hover:border-primary/40'
                      )}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className='space-y-1.5'>
                <Label>Activo afectado</Label>
                <Input value={form.affected_asset} onChange={set('affected_asset')}
                  placeholder='192.168.1.10, https://app.ejemplo.com/login, etc.' />
              </div>

              <div className='space-y-1.5'>
                <Label>Descripción</Label>
                <Textarea value={form.description} onChange={set('description')} rows={4}
                  placeholder='Descripción técnica detallada de la vulnerabilidad...' />
              </div>

              <div className='space-y-1.5'>
                <Label>Pasos para reproducir</Label>
                <Textarea value={form.steps_to_reproduce} onChange={set('steps_to_reproduce')} rows={4}
                  placeholder={'1. Enviar petición POST a /api/login\n2. Modificar el parámetro username con: \' OR 1=1--\n3. Observar respuesta 200 con acceso concedido'} />
              </div>

              <div className='space-y-1.5'>
                <Label>
                  Resumen ejecutivo
                  <span className='ml-1.5 text-xs text-muted-foreground'>(para el informe, sin tecnicismos)</span>
                </Label>
                <Textarea value={form.executive_summary} onChange={set('executive_summary')} rows={3}
                  placeholder='Se identificó una vulnerabilidad que permite a un atacante acceder al sistema sin credenciales válidas...' />
              </div>
            </div>
          )}

          {/* ── Tab: CVSS 3.1 ───────────────────────────────── */}
          {activeTab === 'cvss' && (
            <div className='space-y-4'>
              <p className='text-xs text-muted-foreground'>
                Seleccioná los valores de cada métrica para calcular el score base CVSS 3.1.
                El vector se sincroniza automáticamente al guardar.
              </p>
              <CvssEditor value={cvssVec} onChange={handleCvssChange} />
            </div>
          )}

          {/* ── Tab: Clasificación ──────────────────────────── */}
          {activeTab === 'clasificacion' && (
            <div className='space-y-5'>
              <div className='grid grid-cols-2 gap-4'>
                <div className='space-y-1.5'>
                  <Label>Explotabilidad</Label>
                  <Select value={form.exploitability} onValueChange={setVal('exploitability')}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {EXPLOITABILITIES.map(e => <SelectItem key={e.value} value={e.value}>{e.label}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className='space-y-1.5'>
                  <Label>Riesgo negocio</Label>
                  <Select value={form.business_risk} onValueChange={setVal('business_risk')}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value='high'>Alto</SelectItem>
                      <SelectItem value='medium'>Medio</SelectItem>
                      <SelectItem value='low'>Bajo</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <Separator />
              <div className='space-y-2'>
                <p className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>CVE — Auto-populate desde NVD</p>
                <div className='flex gap-2'>
                  <Input
                    value={cveId}
                    onChange={e => setCveId(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && lookupCve()}
                    placeholder='CVE-2024-12345'
                    className='font-mono text-sm flex-1'
                  />
                  <Button
                    type='button'
                    size='sm'
                    variant='outline'
                    onClick={lookupCve}
                    disabled={cveLoading}
                    className='shrink-0'
                  >
                    {cveLoading
                      ? <Loader2 className='size-3.5 animate-spin' />
                      : <Search className='size-3.5' />}
                    <span className='ml-1.5'>{cveLoading ? 'Buscando...' : 'Buscar'}</span>
                  </Button>
                </div>
                <p className='text-[10px] text-muted-foreground'>
                  Auto-completa CVSS 3.1, CWE y descripción desde la base NVD (NIST).
                </p>
              </div>

              <Separator />
              <p className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>CWE</p>
              <div className='grid grid-cols-2 gap-4'>
                <div className='space-y-1.5'>
                  <Label>CWE ID</Label>
                  <Input value={form.cwe_id} onChange={set('cwe_id')} placeholder='CWE-89' className='font-mono' />
                </div>
                <div className='space-y-1.5'>
                  <Label>Nombre</Label>
                  <Input value={form.cwe_name} onChange={set('cwe_name')} placeholder='SQL Injection' />
                </div>
              </div>

              <Separator />
              <p className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>OWASP</p>
              <div className='space-y-1.5'>
                <Label>Categoría OWASP</Label>
                <Input value={form.owasp_category} onChange={set('owasp_category')}
                  placeholder='A03:2021 - Injection' />
              </div>

              <Separator />
              <p className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>MITRE ATT&amp;CK</p>
              <div className='grid grid-cols-2 gap-4'>
                <div className='space-y-1.5'>
                  <Label>Táctica</Label>
                  <Input value={form.mitre_tactic} onChange={set('mitre_tactic')}
                    placeholder='Initial Access' />
                </div>
                <div className='space-y-1.5'>
                  <Label>ID Técnica</Label>
                  <Input value={form.mitre_technique_id} onChange={set('mitre_technique_id')}
                    placeholder='T1190' className='font-mono' />
                </div>
              </div>
              <div className='space-y-1.5'>
                <Label>Nombre de la técnica</Label>
                <Input value={form.mitre_technique_name} onChange={set('mitre_technique_name')}
                  placeholder='Exploit Public-Facing Application' />
              </div>
            </div>
          )}

          {/* ── Tab: Remediación ────────────────────────────── */}
          {activeTab === 'remediacion' && (
            <div className='space-y-4'>
              <div className='space-y-1.5'>
                <Label>Recomendación técnica</Label>
                <Textarea value={form.recommendation} onChange={set('recommendation')} rows={6}
                  placeholder={'• Implementar prepared statements / ORM en todas las consultas\n• Validar y sanitizar inputs del lado del servidor\n• Aplicar principio de menor privilegio en cuentas de BD'} />
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className='border-t border-border px-6 py-4 flex items-center gap-3'>
          <Button onClick={handleSubmit} disabled={saving} size='sm'>
            <Save className='mr-2 size-3.5' />
            {saving ? 'Guardando...' : isEdit ? 'Actualizar' : 'Guardar hallazgo'}
          </Button>
          {isEdit && (
            <Button variant='outline' size='sm' onClick={handleDelete} disabled={deleting}
              className='text-destructive hover:text-destructive border-destructive/30 hover:bg-destructive/10'>
              <Trash2 className='mr-2 size-3.5' />
              {deleting ? 'Eliminando...' : 'Eliminar'}
            </Button>
          )}
          <Button variant='ghost' size='sm' onClick={() => onOpenChange(false)} className='ml-auto text-muted-foreground'>
            Cancelar
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  )
}
