/**
 * HallazgoSheet — Create/edit a finding within the engagement workspace.
 * Slides in from the right as a Sheet. Integrates CvssEditor.
 */

import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { Save, Trash2, X, BookMarked, ChevronDown, Search, Loader2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
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
  const { t } = useTranslation()
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

  const PHASES = [
    { value: 'planning',          label: t('phase.planning') },
    { value: 'recon',             label: t('phase.recon') },
    { value: 'scanning',          label: t('phase.scanning') },
    { value: 'exploitation',      label: t('phase.exploitation') },
    { value: 'post_exploitation', label: t('phase.post_exploitation') },
    { value: 'reporting',         label: t('phase.reporting') },
  ]

  const SEVERITIES = [
    { value: 'critical', label: t('finding.sev_critical'),  cls: 'bg-red-500/10 text-red-500 border-red-500/30' },
    { value: 'high',     label: t('finding.sev_high'),      cls: 'bg-orange-500/10 text-orange-500 border-orange-500/30' },
    { value: 'medium',   label: t('finding.sev_medium'),    cls: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/30' },
    { value: 'low',      label: t('finding.sev_low'),       cls: 'bg-blue-500/10 text-blue-500 border-blue-500/30' },
    { value: 'info',     label: t('finding.sev_info'),      cls: 'bg-muted text-muted-foreground border-border' },
  ]

  const STATUSES = [
    { value: 'open',           label: t('finding.status_open') },
    { value: 'in_remediation', label: t('finding.status_in_remediation') },
    { value: 'fixed',          label: t('finding.status_fixed') },
    { value: 'accepted',       label: t('finding.status_accepted') },
  ]

  const EXPLOITABILITIES = [
    { value: 'proven',      label: t('finding.exploit_proven') },
    { value: 'functional',  label: t('finding.exploit_functional') },
    { value: 'poc',         label: t('finding.exploit_poc') },
    { value: 'theoretical', label: t('finding.exploit_theoretical') },
  ]

  const TABS = [
    { id: 'basico',        label: t('finding.tab_basic') },
    { id: 'cvss',          label: t('finding.tab_cvss') },
    { id: 'clasificacion', label: t('finding.tab_classification') },
    { id: 'remediacion',   label: t('finding.tab_remediation') },
  ] as const

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

  function applyTemplate(tmpl: Record<string, unknown>) {
    setForm(prev => ({
      ...prev,
      title:                prev.title || String(tmpl.title ?? ''),
      description:          String(tmpl.description ?? prev.description ?? ''),
      steps_to_reproduce:   String(tmpl.steps_to_reproduce ?? prev.steps_to_reproduce ?? ''),
      recommendation:       String(tmpl.recommendation ?? prev.recommendation ?? ''),
      severity:             String(tmpl.severity ?? prev.severity),
      cwe_id:               String(tmpl.cwe_id ?? prev.cwe_id ?? ''),
      cwe_name:             String(tmpl.cwe_name ?? prev.cwe_name ?? ''),
      owasp_category:       String(tmpl.owasp_category ?? prev.owasp_category ?? ''),
      cvss_vector_31:       tmpl.cvss_vector_31 ? String(tmpl.cvss_vector_31) : prev.cvss_vector_31,
      cvss_score_31:        tmpl.cvss_score_31 ? Number(tmpl.cvss_score_31) : prev.cvss_score_31,
    }))
    if (tmpl.cvss_vector_31) {
      const v = stringToVector(String(tmpl.cvss_vector_31))
      if (v) setCvssVec(v)
    }
    setTemplateOpen(false)
    toast.success(t('finding.toast_template', { name: String(tmpl.title ?? '') }))
  }

  // ── CVE NVD lookup ────────────────────────────────────────────────────────────
  async function lookupCve() {
    const id = cveId.trim().toUpperCase()
    if (!id.match(/^CVE-\d{4}-\d{4,}$/)) {
      toast.error(t('finding.cve_format_error'))
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
      if (!vuln) { toast.error(t('finding.cve_not_found', { id })); return }

      const desc = (vuln.descriptions ?? []).find((d: {lang:string}) => d.lang === 'en')?.value ?? ''

      const cvssMetric = (vuln.metrics?.cvssMetricV31 ?? vuln.metrics?.cvssMetricV30 ?? [])[0]
      const cvssData   = cvssMetric?.cvssData
      const vectorStr  = cvssData?.vectorString ?? null
      const score      = cvssData?.baseScore ?? null

      const cweRaw = (vuln.weaknesses ?? [])
        .flatMap((w: {description:{value:string}[]}) => w.description)
        .find((d: {value:string}) => d.value?.startsWith('CWE-'))?.value ?? ''

      setForm(prev => ({
        ...prev,
        description: prev.description || desc,
        cwe_id: prev.cwe_id || cweRaw,
        cvss_vector_31: vectorStr ? vectorStr.replace(/^CVSS:3\.\d\//, '') : prev.cvss_vector_31,
        cvss_score_31:  score ?? prev.cvss_score_31,
      }))

      if (vectorStr) {
        const cleanVec = vectorStr.replace(/^CVSS:3\.\d\//, '')
        const parsed = stringToVector(cleanVec)
        if (parsed) setCvssVec(parsed)
      }

      const scoreLabel = score ? t('finding.cve_score_suffix', { score }) : ''
      toast.success(t('finding.cve_loaded', { id, score: scoreLabel }))
      if (vectorStr || cweRaw) setActiveTab('clasificacion')
    } catch(e: unknown) {
      toast.error(e instanceof Error ? e.message : t('common.error'))
    } finally {
      setCveLoading(false)
    }
  }

  const handleCvssChange = (v: CvssVector) => {
    setCvssVec(v)
    setForm(p => ({ ...p, cvss_vector_31: vectorToString(v) }))
  }

  const handleSubmit = async () => {
    if (!form.title.trim()) { toast.error(t('finding.title_required')); return }
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
        toast.success(t('finding.toast_updated'))
      } else {
        await apiFetch(`/engagements/${engagementId}/findings`, { method: 'POST', body: JSON.stringify(payload) })
        toast.success(t('finding.toast_saved'))
        setForm(empty(defaultPhase))
        setCvssVec(DEFAULT_VECTOR)
      }
      onSaved?.()
      onOpenChange(false)
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : t('common.error'))
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!isEdit || !hallazgoId) return
    if (!confirm(t('finding.delete_confirm'))) return
    setDeleting(true)
    try {
      await apiFetch(`/engagements/${engagementId}/findings/${hallazgoId}`, { method: 'DELETE' })
      toast.success(t('finding.toast_deleted'))
      onSaved?.()
      onOpenChange(false)
    } catch {
      toast.error(t('common.error'))
    } finally {
      setDeleting(false)
    }
  }

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
            {isEdit ? t('finding.sheet_title_edit') : t('finding.sheet_title_new')}
          </SheetTitle>
          <div className='flex items-center gap-2'>
            {/* Template selector */}
            <div className='relative'>
              <Button
                variant='outline' size='sm' className='h-7 gap-1.5 text-xs'
                onClick={() => { setTemplateOpen(o => !o); if (!templateOpen) loadTemplates() }}
              >
                <BookMarked className='size-3' />
                {t('finding.template_btn')}
                <ChevronDown className='size-3' />
              </Button>
              {templateOpen && (
                <div className='absolute right-0 top-full mt-1 w-72 z-50 rounded-md border border-border bg-popover shadow-lg'>
                  <div className='p-2 border-b border-border'>
                    <input
                      value={templateSearch}
                      onChange={e => { setTemplateSearch(e.target.value); loadTemplates() }}
                      placeholder={t('finding.template_search')}
                      className='w-full rounded border border-border bg-background px-2 py-1 text-xs outline-none'
                      autoFocus
                    />
                  </div>
                  <div className='max-h-64 overflow-y-auto'>
                    {templates.length === 0 ? (
                      <p className='text-xs text-muted-foreground text-center py-4'>{t('finding.no_templates')}</p>
                    ) : templates.map((tmpl, i) => (
                      <button
                        key={String(tmpl.id ?? i)}
                        onClick={() => applyTemplate(tmpl)}
                        className='w-full text-left px-3 py-2 text-xs hover:bg-accent transition-colors flex items-center gap-2 border-b border-border/40 last:border-0'
                      >
                        <span className={cn('h-2 w-2 rounded-full shrink-0', {
                          'bg-red-500': tmpl.severity === 'critical',
                          'bg-orange-500': tmpl.severity === 'high',
                          'bg-yellow-500': tmpl.severity === 'medium',
                          'bg-blue-500': tmpl.severity === 'low',
                          'bg-muted-foreground': tmpl.severity === 'info',
                        })} />
                        <span className='truncate'>{String(tmpl.title ?? '')}</span>
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
                <Label>{t('finding.label_title')} <span className='text-destructive'>*</span></Label>
                <Input value={form.title} onChange={set('title')}
                  placeholder='SQL Injection en endpoint /api/login' autoFocus />
              </div>

              <div className='grid grid-cols-2 gap-4'>
                <div className='space-y-1.5'>
                  <Label>{t('finding.label_phase')}</Label>
                  <Select value={form.phase_type} onValueChange={setVal('phase_type')}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {PHASES.map(p => <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className='space-y-1.5'>
                  <Label>{t('finding.label_status')}</Label>
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
                <Label>{t('finding.label_severity')}</Label>
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
                <Label>{t('finding.label_asset')}</Label>
                <Input value={form.affected_asset} onChange={set('affected_asset')}
                  placeholder='192.168.1.10, https://app.ejemplo.com/login, etc.' />
              </div>

              <div className='space-y-1.5'>
                <Label>{t('finding.label_description')}</Label>
                <Textarea value={form.description} onChange={set('description')} rows={4}
                  placeholder='Descripción técnica detallada de la vulnerabilidad...' />
              </div>

              <div className='space-y-1.5'>
                <Label>{t('finding.label_steps')}</Label>
                <Textarea value={form.steps_to_reproduce} onChange={set('steps_to_reproduce')} rows={4}
                  placeholder={'1. Enviar petición POST a /api/login\n2. Modificar el parámetro username con: \' OR 1=1--\n3. Observar respuesta 200 con acceso concedido'} />
              </div>

              <div className='space-y-1.5'>
                <Label>
                  {t('finding.label_executive')}
                  <span className='ml-1.5 text-xs text-muted-foreground'>{t('finding.label_executive_hint')}</span>
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
                {t('finding.cvss_hint')}
              </p>
              <CvssEditor value={cvssVec} onChange={handleCvssChange} />
            </div>
          )}

          {/* ── Tab: Clasificación ──────────────────────────── */}
          {activeTab === 'clasificacion' && (
            <div className='space-y-5'>
              <div className='grid grid-cols-2 gap-4'>
                <div className='space-y-1.5'>
                  <Label>{t('finding.label_exploitability')}</Label>
                  <Select value={form.exploitability} onValueChange={setVal('exploitability')}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {EXPLOITABILITIES.map(item => <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className='space-y-1.5'>
                  <Label>{t('finding.label_business_risk')}</Label>
                  <Select value={form.business_risk} onValueChange={setVal('business_risk')}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value='high'>{t('finding.business_high')}</SelectItem>
                      <SelectItem value='medium'>{t('finding.business_medium')}</SelectItem>
                      <SelectItem value='low'>{t('finding.business_low')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <Separator />
              <div className='space-y-2'>
                <p className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>{t('finding.cve_section')}</p>
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
                    <span className='ml-1.5'>{cveLoading ? t('finding.cve_searching') : t('finding.cve_search_btn')}</span>
                  </Button>
                </div>
                <p className='text-[10px] text-muted-foreground'>
                  {t('finding.cve_hint')}
                </p>
              </div>

              <Separator />
              <p className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>CWE</p>
              <div className='grid grid-cols-2 gap-4'>
                <div className='space-y-1.5'>
                  <Label>{t('finding.label_cwe_id')}</Label>
                  <Input value={form.cwe_id} onChange={set('cwe_id')} placeholder='CWE-89' className='font-mono' />
                </div>
                <div className='space-y-1.5'>
                  <Label>{t('finding.label_cwe_name')}</Label>
                  <Input value={form.cwe_name} onChange={set('cwe_name')} placeholder='SQL Injection' />
                </div>
              </div>

              <Separator />
              <p className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>OWASP</p>
              <div className='space-y-1.5'>
                <Label>{t('finding.label_owasp')}</Label>
                <Input value={form.owasp_category} onChange={set('owasp_category')}
                  placeholder='A03:2021 - Injection' />
              </div>

              <Separator />
              <p className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>MITRE ATT&amp;CK</p>
              <div className='grid grid-cols-2 gap-4'>
                <div className='space-y-1.5'>
                  <Label>{t('finding.label_mitre_tactic')}</Label>
                  <Input value={form.mitre_tactic} onChange={set('mitre_tactic')}
                    placeholder='Initial Access' />
                </div>
                <div className='space-y-1.5'>
                  <Label>{t('finding.label_mitre_tech_id')}</Label>
                  <Input value={form.mitre_technique_id} onChange={set('mitre_technique_id')}
                    placeholder='T1190' className='font-mono' />
                </div>
              </div>
              <div className='space-y-1.5'>
                <Label>{t('finding.label_mitre_tech_name')}</Label>
                <Input value={form.mitre_technique_name} onChange={set('mitre_technique_name')}
                  placeholder='Exploit Public-Facing Application' />
              </div>
            </div>
          )}

          {/* ── Tab: Remediación ────────────────────────────── */}
          {activeTab === 'remediacion' && (
            <div className='space-y-4'>
              <div className='space-y-1.5'>
                <Label>{t('finding.label_recommendation')}</Label>
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
            {saving ? t('finding.btn_saving') : isEdit ? t('finding.btn_update') : t('finding.btn_save')}
          </Button>
          {isEdit && (
            <Button variant='outline' size='sm' onClick={handleDelete} disabled={deleting}
              className='text-destructive hover:text-destructive border-destructive/30 hover:bg-destructive/10'>
              <Trash2 className='mr-2 size-3.5' />
              {deleting ? t('finding.btn_deleting') : t('common.delete')}
            </Button>
          )}
          <Button variant='ghost' size='sm' onClick={() => onOpenChange(false)} className='ml-auto text-muted-foreground'>
            {t('common.cancel')}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  )
}
