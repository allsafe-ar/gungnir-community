import { useEffect, useState } from 'react'
import { useNavigate, useSearch } from '@tanstack/react-router'
import { toast } from 'sonner'
import { ClipboardList, Save, ArrowLeft, Crosshair, Settings2, Info } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { apiFetch } from '@/lib/api'

interface EngagementFormProps {
  initial?: Partial<FormData>
  engagementId?: string
}
interface FormData {
  client_id: string
  title: string
  codename: string
  type: string
  methodology: string
  mode: string
  start_date: string
  end_date: string
  notes: string
}
interface Cliente { id: string; name: string }

// Tipos que usan fases de pentesting por defecto
const PENTESTING_TYPES = new Set([
  'external_pt','internal_pt','web_app','api','mobile','red_team','social_eng','physical',
])

const METHODOLOGIES = [
  { group: 'Pentesting', items: [
    { value: 'ptes',           label: 'PTES — Penetration Testing Execution Standard' },
    { value: 'owasp_wstg',    label: 'OWASP WSTG — Web Security Testing Guide' },
    { value: 'nist',          label: 'NIST SP 800-115' },
    { value: 'red_team_mitre',label: 'Red Team / MITRE ATT&CK' },
  ]},
  { group: 'Frameworks', items: [
    { value: 'owasp_samm', label: 'OWASP SAMM — Software Assurance Maturity Model' },
    { value: 'nist_csf',   label: 'NIST Cybersecurity Framework (CSF)' },
    { value: 'iso27001',   label: 'ISO/IEC 27001' },
    { value: 'cobit',      label: 'COBIT 2019' },
  ]},
  { group: 'General', items: [
    { value: 'custom', label: 'Metodología propia' },
    { value: 'none',   label: 'Sin metodología formal' },
  ]},
]

// ─── Selector de modo ─────────────────────────────────────────────────────────
function ModeSelector({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { t } = useTranslation()
  return (
    <div className='grid sm:grid-cols-2 gap-3'>
      <button
        type='button'
        onClick={() => onChange('pentesting')}
        className={cn(
          'text-left rounded-lg border p-4 transition-all',
          value === 'pentesting'
            ? 'border-red-700/60 bg-red-950/30'
            : 'border-zinc-800 hover:border-zinc-700'
        )}
      >
        <div className='flex items-center gap-2 mb-1'>
          <Crosshair className={cn('h-4 w-4', value === 'pentesting' ? 'text-red-400' : 'text-zinc-500')} />
          <p className={cn('text-sm font-semibold', value === 'pentesting' ? 'text-red-300' : 'text-zinc-300')}>
            {t('engform.mode_pentesting_label')}
          </p>
        </div>
        <p className='text-xs text-zinc-600 leading-relaxed'>
          {t('engform.mode_pentesting_desc')}
        </p>
      </button>

      <button
        type='button'
        onClick={() => onChange('custom')}
        className={cn(
          'text-left rounded-lg border p-4 transition-all',
          value === 'custom'
            ? 'border-blue-700/60 bg-blue-950/30'
            : 'border-zinc-800 hover:border-zinc-700'
        )}
      >
        <div className='flex items-center gap-2 mb-1'>
          <Settings2 className={cn('h-4 w-4', value === 'custom' ? 'text-blue-400' : 'text-zinc-500')} />
          <p className={cn('text-sm font-semibold', value === 'custom' ? 'text-blue-300' : 'text-zinc-300')}>
            {t('engform.mode_custom_label')}
          </p>
        </div>
        <p className='text-xs text-zinc-600 leading-relaxed'>
          {t('engform.mode_custom_desc')}
        </p>
      </button>
    </div>
  )
}

export function EngagementForm({ initial, engagementId }: EngagementFormProps) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const search = useSearch({ strict: false }) as Record<string, string>
  const isEdit = !!engagementId
  const [clientes, setClientes] = useState<Cliente[]>([])
  const [saving, setSaving]     = useState(false)
  const [form, setForm]         = useState<FormData>({
    client_id:   initial?.client_id   ?? search?.client_id ?? '',
    title:       initial?.title       ?? '',
    codename:    initial?.codename    ?? '',
    type:        (initial as Record<string, string>)?.type        ?? 'web_app',
    methodology: (initial as Record<string, string>)?.methodology ?? 'ptes',
    mode:        (initial as Record<string, string>)?.mode        ?? 'pentesting',
    start_date:  (initial as Record<string, string>)?.start_date  ?? '',
    end_date:    (initial as Record<string, string>)?.end_date    ?? '',
    notes:       (initial as Record<string, string>)?.notes       ?? '',
  })

  // ─── Tipos agrupados — must be inside component to use t() ────────────────
  const TYPE_GROUPS = [
    {
      label: t('engform.group_pentesting'),
      types: [
        { value: 'external_pt',  label: t('engform.type_external_pt') },
        { value: 'internal_pt',  label: t('engform.type_internal_pt') },
        { value: 'web_app',      label: t('engform.type_web_app') },
        { value: 'api',          label: t('engform.type_api') },
        { value: 'mobile',       label: t('engform.type_mobile') },
        { value: 'red_team',     label: t('engform.type_red_team') },
        { value: 'social_eng',   label: t('engform.type_social_eng') },
        { value: 'physical',     label: t('engform.type_physical') },
      ],
    },
    {
      label: t('engform.group_appsec'),
      types: [
        { value: 'app_security', label: t('engform.type_app_security') },
        { value: 'code_review',  label: t('engform.type_code_review') },
        { value: 'arch_review',  label: t('engform.type_arch_review') },
      ],
    },
    {
      label: t('engform.group_audit'),
      types: [
        { value: 'security_audit', label: t('engform.type_security_audit') },
        { value: 'compliance',     label: 'Evaluación de Cumplimiento' },
        { value: 'gap_analysis',   label: 'Análisis de Brechas (Gap Analysis)' },
      ],
    },
    {
      label: t('engform.group_investigation'),
      types: [
        { value: 'risk_analysis',    label: 'Análisis de Riesgo' },
        { value: 'preliminary',      label: t('engform.type_preliminary') },
        { value: 'situation',        label: 'Análisis de Situación Actual' },
        { value: 'incident_response',label: t('engform.type_incident_response') },
        { value: 'consulting',       label: 'Consultoría de Seguridad' },
        { value: 'training',         label: 'Capacitación / Awareness' },
      ],
    },
  ]

  const ALL_TYPES = TYPE_GROUPS.flatMap(g => g.types)

  useEffect(() => {
    apiFetch<Cliente[]>('/clientes').then(d => setClientes(d as Cliente[])).catch(() => {})
  }, [])

  // Al cambiar tipo, sugerir el modo adecuado
  const handleTypeChange = (v: string) => {
    setForm(prev => ({
      ...prev,
      type: v,
      mode: PENTESTING_TYPES.has(v) ? prev.mode : 'custom',
    }))
  }

  const set = (k: keyof FormData) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm(prev => ({ ...prev, [k]: e.target.value }))
  const setVal = (k: keyof FormData) => (v: string) => setForm(prev => ({ ...prev, [k]: v }))

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.client_id) { toast.error(t('engform.client_required')); return }
    if (!form.title.trim()) { toast.error(t('engform.title_required')); return }
    setSaving(true)
    try {
      if (isEdit) {
        await apiFetch(`/engagements/${engagementId}`, { method: 'PUT', body: form })
        toast.success(t('engform.toast_updated'))
        navigate({ to: '/engagements/$engagementId', params: { engagementId } })
      } else {
        const created = await apiFetch<{ id: string }>('/engagements', { method: 'POST', body: form })
        toast.success(t('engform.toast_created'))
        navigate({ to: '/engagements/$engagementId', params: { engagementId: created.id } })
      }
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : t('common.error'))
    } finally {
      setSaving(false)
    }
  }

  const typeLabel = ALL_TYPES.find(item => item.value === form.type)?.label ?? form.type

  return (
    <form onSubmit={handleSubmit} className='space-y-6 max-w-2xl'>
      <div className='flex items-center gap-3'>
        <Button type='button' variant='ghost' size='sm' className='text-muted-foreground -ml-2'
          onClick={() => navigate({ to: '/engagements' })}>
          <ArrowLeft className='mr-1 size-3' /> {t('engs.title')}
        </Button>
      </div>

      <div className='flex items-center gap-3'>
        <ClipboardList className='size-6 text-muted-foreground' />
        <h1 className='text-2xl font-bold'>{isEdit ? t('engform.title_edit') : t('engform.title_new')}</h1>
      </div>

      {/* Identificación */}
      <Card>
        <CardHeader className='pb-3'>
          <CardTitle className='text-sm font-semibold text-muted-foreground uppercase tracking-wide'>
            {t('engform.section_general')}
          </CardTitle>
        </CardHeader>
        <CardContent className='space-y-4'>
          <div className='space-y-1.5'>
            <Label>{t('engform.label_client')} <span className='text-destructive'>*</span></Label>
            <Select value={form.client_id} onValueChange={setVal('client_id')}>
              <SelectTrigger><SelectValue placeholder={t('client.select_placeholder')} /></SelectTrigger>
              <SelectContent>
                {clientes.map(c => <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div className='space-y-1.5'>
            <Label htmlFor='title'>{t('engform.label_title')} <span className='text-destructive'>*</span></Label>
            <Input id='title' value={form.title} onChange={set('title')}
              placeholder='Ej: Application Security Review — App de Turnos Q2 2026' required />
          </div>
          <div className='space-y-1.5'>
            <Label htmlFor='codename'>
              {t('engform.label_codename')} <span className='text-xs text-muted-foreground ml-1'>(opcional)</span>
            </Label>
            <Input id='codename' value={form.codename} onChange={set('codename')}
              placeholder='PROJ-042, OP-FENRIR...' className='font-mono' />
          </div>
        </CardContent>
      </Card>

      {/* Tipo */}
      <Card>
        <CardHeader className='pb-3'>
          <CardTitle className='text-sm font-semibold text-muted-foreground uppercase tracking-wide'>
            {t('engform.label_type')}
          </CardTitle>
        </CardHeader>
        <CardContent className='space-y-4'>
          <div className='space-y-1.5'>
            <Label>{t('engform.label_type')}</Label>
            <Select value={form.type} onValueChange={handleTypeChange}>
              <SelectTrigger>
                <SelectValue>{typeLabel}</SelectValue>
              </SelectTrigger>
              <SelectContent>
                {TYPE_GROUPS.map(g => (
                  <div key={g.label}>
                    <div className='px-2 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground'>
                      {g.label}
                    </div>
                    {g.types.map(item => (
                      <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>
                    ))}
                  </div>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className='space-y-1.5'>
            <Label>{t('engform.label_methodology')}</Label>
            <Select value={form.methodology} onValueChange={setVal('methodology')}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {METHODOLOGIES.map(g => (
                  <div key={g.group}>
                    <div className='px-2 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground'>
                      {g.group}
                    </div>
                    {g.items.map(m => (
                      <SelectItem key={m.value} value={m.value}>{m.label}</SelectItem>
                    ))}
                  </div>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Modo de trabajo — solo en creación */}
      {!isEdit && (
        <Card>
          <CardHeader className='pb-3'>
            <CardTitle className='text-sm font-semibold text-muted-foreground uppercase tracking-wide'>
              {t('engform.section_structure')}
            </CardTitle>
          </CardHeader>
          <CardContent className='space-y-3'>
            <ModeSelector value={form.mode} onChange={setVal('mode')} />
            {form.mode === 'custom' && (
              <div className='flex items-start gap-2 rounded-lg bg-blue-950/20 border border-blue-900/30 p-3'>
                <Info className='h-3.5 w-3.5 text-blue-400 mt-0.5 shrink-0' />
                <p className='text-xs text-blue-300/70'>
                  {t('engform.mode_custom_info')}
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Fechas */}
      <Card>
        <CardHeader className='pb-3'>
          <CardTitle className='text-sm font-semibold text-muted-foreground uppercase tracking-wide'>
            {t('engform.section_dates')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className='grid gap-4 sm:grid-cols-2'>
            <div className='space-y-1.5'>
              <Label htmlFor='start_date'>{t('engform.label_start')}</Label>
              <Input id='start_date' type='date' value={form.start_date} onChange={set('start_date')} />
            </div>
            <div className='space-y-1.5'>
              <Label htmlFor='end_date'>{t('engform.label_end')}</Label>
              <Input id='end_date' type='date' value={form.end_date} onChange={set('end_date')} />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Notas */}
      <Card>
        <CardHeader className='pb-3'>
          <CardTitle className='text-sm font-semibold text-muted-foreground uppercase tracking-wide'>
            {t('engform.section_notes')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Textarea value={form.notes} onChange={set('notes')} rows={3}
            placeholder='Contexto general, objetivos, restricciones, alcance inicial...' />
        </CardContent>
      </Card>

      <div className='flex gap-3'>
        <Button type='submit' disabled={saving}>
          <Save className='mr-2 size-4' />
          {saving ? t('engform.btn_saving') : isEdit ? t('engform.btn_update') : t('engform.btn_create')}
        </Button>
        <Button type='button' variant='outline' onClick={() => navigate({ to: '/engagements' })}>
          {t('common.cancel')}
        </Button>
      </div>
    </form>
  )
}
