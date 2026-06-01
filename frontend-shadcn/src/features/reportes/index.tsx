/**
 * Reportes — Generador de informes de pentesting
 * Seleccioná un engagement → configurá opciones → generá el PDF ejecutivo/técnico.
 */

import { useEffect, useState } from 'react'
import {
  FileText, Download, Loader2, AlertCircle, ChevronRight,
  Shield, CheckCircle2, Clock, Package, Eye, EyeOff,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { cn } from '@/lib/utils'
import { apiFetch } from '@/lib/api'
import { generatePentestReport, type PentestReportData, type FindingDetail } from '@/lib/pentest-pdf'

// ─── Tipos básicos ─────────────────────────────────────────────────────────────
interface EngagementItem {
  id: string
  title: string
  codename?: string
  client_name: string
  status: string
  type: string
  current_phase: string
  start_date?: string
  end_date?: string
  methodology: string
  notes?: string
  lead_name?: string
}

interface ScopeItem {
  id: string
  type: string
  value: string
  in_scope: boolean
  note?: string
}

// ─── Labels ───────────────────────────────────────────────────────────────────
const STATUS_LABEL: Record<string, string> = {
  planned: 'Planificado', in_progress: 'En curso', reporting: 'Reportando',
  qa: 'QA', delivered: 'Entregado', archived: 'Archivado',
}
const STATUS_COLOR: Record<string, string> = {
  planned: 'bg-zinc-700 text-zinc-300',
  in_progress: 'bg-blue-900/50 text-blue-300',
  reporting: 'bg-yellow-900/50 text-yellow-300',
  qa: 'bg-purple-900/50 text-purple-300',
  delivered: 'bg-green-900/50 text-green-300',
  archived: 'bg-zinc-800 text-zinc-500',
}
const TYPE_LABEL: Record<string, string> = {
  external_pt: 'External PT', internal_pt: 'Internal PT',
  web_app: 'Web App', api: 'API', mobile: 'Mobile',
  red_team: 'Red Team', social_eng: 'Social Eng', physical: 'Físico',
}
const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-blue-400',
  info:     'text-zinc-400',
}
const SEV_BG: Record<string, string> = {
  critical: 'bg-red-500/10',
  high:     'bg-orange-500/10',
  medium:   'bg-yellow-500/10',
  low:      'bg-blue-500/10',
  info:     'bg-zinc-500/10',
}

// ─── Preview de findings ───────────────────────────────────────────────────────
function FindingPreview({ findings }: { findings: FindingDetail[] }) {
  const counts = ['critical', 'high', 'medium', 'low', 'info'].map(s => ({
    sev: s,
    count: findings.filter(f => f.severity === s).length,
  })).filter(x => x.count > 0)

  if (!findings.length) return (
    <div className='flex items-center gap-2 rounded-lg border border-dashed border-zinc-800 p-4 text-zinc-600 text-sm'>
      <AlertCircle className='h-4 w-4' />
      Sin hallazgos registrados en este engagement.
    </div>
  )

  return (
    <div className='space-y-2'>
      {/* Severity summary */}
      <div className='flex gap-3 flex-wrap'>
        {counts.map(({ sev, count }) => (
          <div key={sev} className={cn('flex items-center gap-1.5 rounded-md px-3 py-1.5', SEV_BG[sev])}>
            <span className={cn('text-xs font-bold uppercase', SEV_COLOR[sev])}>{sev}</span>
            <span className={cn('text-lg font-bold', SEV_COLOR[sev])}>{count}</span>
          </div>
        ))}
        <div className='ml-auto flex items-center gap-1.5 rounded-md bg-zinc-800/50 px-3 py-1.5'>
          <span className='text-xs text-zinc-500'>Total</span>
          <span className='text-lg font-bold text-zinc-300'>{findings.length}</span>
        </div>
      </div>
      {/* Finding list */}
      <div className='rounded-lg border border-zinc-800 divide-y divide-zinc-800/50 max-h-48 overflow-y-auto'>
        {findings.map((f, i) => (
          <div key={f.id} className='flex items-center gap-3 px-3 py-2 text-xs'>
            <span className='font-mono text-zinc-600 w-8 shrink-0'>F{String(i + 1).padStart(2, '0')}</span>
            <span className={cn('font-semibold uppercase text-[10px] w-14 shrink-0', SEV_COLOR[f.severity])}>
              {f.severity}
            </span>
            <span className='flex-1 truncate text-zinc-300'>{f.title}</span>
            {f.cvss_score_31 != null && (
              <span className='text-zinc-500 shrink-0'>{Number(f.cvss_score_31).toFixed(1)}</span>
            )}
            {f.status === 'open' ? (
              <span className='text-red-500 text-[10px] shrink-0'>Abierto</span>
            ) : (
              <span className='text-green-600 text-[10px] shrink-0'>Cerrado</span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Componente principal ─────────────────────────────────────────────────────
export function Reportes() {
  const [engagements, setEngagements]     = useState<EngagementItem[]>([])
  const [loadingList, setLoadingList]     = useState(true)
  const [selected, setSelected]           = useState<EngagementItem | null>(null)
  const [findings, setFindings]           = useState<FindingDetail[]>([])
  const [scope, setScope]                 = useState<ScopeItem[]>([])
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [generating, setGenerating]       = useState(false)
  const [orgSettings, setOrgSettings]     = useState<{ name?: string; email?: string; website?: string }>({})

  // Opciones del reporte
  const [includeSteps, setIncludeSteps]   = useState(true)
  const [includeScope, setIncludeScope]   = useState(true)
  const [onlyOpen, setOnlyOpen]           = useState(false)
  const [reportTemplate, setReportTemplate] = useState<'allsafe' | 'htb' | 'offsec' | 'ptes'>('allsafe')

  // Cargar settings de org para el PDF
  useEffect(() => {
    apiFetch<Record<string, string>>('/settings')
      .then(s => setOrgSettings({
        name:    s['report_org_name']    || '',
        email:   s['report_org_email']   || '',
        website: s['report_org_website'] || '',
      }))
      .catch(() => {})
  }, [])

  // Cargar lista de engagements
  useEffect(() => {
    apiFetch<EngagementItem[]>('/engagements')
      .then(r => setEngagements(Array.isArray(r) ? r : []))
      .catch(() => {})
      .finally(() => setLoadingList(false))
  }, [])

  // Cargar detalle cuando se selecciona un engagement
  useEffect(() => {
    if (!selected) { setFindings([]); setScope([]); return }
    setLoadingDetail(true)
    Promise.all([
      apiFetch<FindingDetail[]>(`/engagements/${selected.id}/findings`),
      apiFetch<ScopeItem[]>(`/engagements/${selected.id}/scope`),
    ])
      .then(([fRes, sRes]) => {
        setFindings(Array.isArray(fRes) ? fRes : [])
        setScope(Array.isArray(sRes) ? sRes : [])
      })
      .catch(() => {})
      .finally(() => setLoadingDetail(false))
  }, [selected])

  const displayedFindings = onlyOpen
    ? findings.filter(f => f.status === 'open')
    : findings

  async function handleGenerate() {
    if (!selected) return
    setGenerating(true)
    try {
      const data: PentestReportData = {
        engagement: {
          id:          selected.id,
          title:       selected.title,
          codename:    selected.codename,
          type:        selected.type,
          methodology: selected.methodology,
          status:      selected.status,
          start_date:  selected.start_date,
          end_date:    selected.end_date,
          notes:       selected.notes,
          client_name: selected.client_name,
          lead_name:   selected.lead_name,
          scope_in:    scope.filter(s => s.in_scope).map(s => s.value),
          scope_out:   scope.filter(s => !s.in_scope).map(s => s.value),
        },
        findings: displayedFindings,
        includeSteps,
        includeScope,
        org: orgSettings,
      }
      await generatePentestReport(data, reportTemplate)
    } catch (e) {
      console.error('Error generando PDF:', e)
    } finally {
      setGenerating(false)
    }
  }

  const canGenerate = !!selected && !loadingDetail && displayedFindings.length > 0

  return (
    <div className='flex h-[calc(100vh-4rem)] -m-6 overflow-hidden'>
      {/* ── Left: engagement selector ─────────────────────────────────────── */}
      <div className='w-80 shrink-0 flex flex-col border-r border-zinc-800 overflow-hidden'>
        <div className='border-b border-zinc-800 p-4'>
          <div className='flex items-center gap-2'>
            <FileText className='h-4 w-4 text-red-500' />
            <h1 className='font-semibold text-sm text-zinc-200'>Generador de Reportes</h1>
          </div>
          <p className='mt-1 text-xs text-zinc-500'>Seleccioná un engagement para generar el informe PDF</p>
        </div>

        <div className='flex-1 overflow-y-auto p-2 space-y-1'>
          {loadingList ? (
            <div className='flex justify-center py-12'>
              <Loader2 className='h-5 w-5 animate-spin text-zinc-600' />
            </div>
          ) : engagements.length === 0 ? (
            <div className='flex flex-col items-center justify-center py-16 text-center px-4'>
              <Package className='h-8 w-8 text-zinc-700 mb-3' />
              <p className='text-xs text-zinc-500'>Sin engagements registrados</p>
            </div>
          ) : (
            engagements.map(eng => {
              const active = selected?.id === eng.id
              return (
                <button
                  key={eng.id}
                  onClick={() => setSelected(active ? null : eng)}
                  className={cn(
                    'w-full text-left rounded-md px-3 py-2.5 transition border',
                    active
                      ? 'bg-red-950/40 border-red-900/50'
                      : 'border-transparent hover:bg-zinc-900 hover:border-zinc-800'
                  )}
                >
                  <div className='flex items-start justify-between gap-2'>
                    <div className='flex-1 min-w-0'>
                      <p className={cn('text-xs font-medium truncate', active ? 'text-red-300' : 'text-zinc-300')}>
                        {eng.title}
                      </p>
                      <p className='text-[10px] text-zinc-500 mt-0.5 truncate'>{eng.client_name}</p>
                    </div>
                    <div className='flex flex-col items-end gap-1 shrink-0'>
                      <span className={cn('rounded px-1.5 py-0.5 text-[10px] font-medium', STATUS_COLOR[eng.status] ?? 'bg-zinc-700 text-zinc-400')}>
                        {STATUS_LABEL[eng.status] ?? eng.status}
                      </span>
                      <span className='text-[10px] text-zinc-600'>
                        {TYPE_LABEL[eng.type] ?? eng.type}
                      </span>
                    </div>
                  </div>
                  {active && <ChevronRight className='mt-1 h-3 w-3 text-red-500' />}
                </button>
              )
            })
          )}
        </div>
      </div>

      {/* ── Right: config + preview ────────────────────────────────────────── */}
      <div className='flex-1 overflow-y-auto'>
        {!selected ? (
          <div className='flex flex-col items-center justify-center h-full gap-4 text-center'>
            <div className='rounded-full border border-zinc-800 bg-zinc-900 p-6'>
              <FileText className='h-10 w-10 text-zinc-700' />
            </div>
            <div>
              <p className='text-sm text-zinc-400 font-medium'>Seleccioná un engagement</p>
              <p className='text-xs text-zinc-600 mt-1'>El informe incluirá todos los hallazgos, scope y metadata del engagement</p>
            </div>
          </div>
        ) : (
          <div className='p-6 max-w-2xl mx-auto space-y-6'>
            {/* Engagement header */}
            <div className='rounded-xl border border-zinc-800 bg-zinc-900/50 p-5'>
              <div className='flex items-start justify-between gap-3'>
                <div>
                  <h2 className='font-semibold text-zinc-100 text-base'>{selected.title}</h2>
                  {selected.codename && (
                    <span className='font-mono text-xs text-zinc-500'>op: {selected.codename}</span>
                  )}
                  <p className='text-xs text-zinc-400 mt-1'>{selected.client_name}</p>
                </div>
                <span className={cn('rounded-md px-2 py-1 text-xs font-medium', STATUS_COLOR[selected.status])}>
                  {STATUS_LABEL[selected.status]}
                </span>
              </div>
              <div className='mt-3 flex flex-wrap gap-3 text-xs text-zinc-500'>
                <span>{TYPE_LABEL[selected.type] ?? selected.type}</span>
                {selected.start_date && (
                  <span className='flex items-center gap-1'>
                    <Clock className='h-3 w-3' />
                    {new Date(selected.start_date).toLocaleDateString('es-AR')}
                    {selected.end_date && ` → ${new Date(selected.end_date).toLocaleDateString('es-AR')}`}
                  </span>
                )}
                {selected.lead_name && (
                  <span>Responsable: {selected.lead_name}</span>
                )}
              </div>
            </div>

            {/* Findings preview */}
            <div>
              <h3 className='mb-3 text-xs font-semibold uppercase tracking-wider text-zinc-600'>
                Hallazgos
                {loadingDetail && <Loader2 className='ml-2 inline h-3 w-3 animate-spin' />}
              </h3>
              {!loadingDetail && <FindingPreview findings={displayedFindings} />}
            </div>

            {/* Scope summary */}
            {!loadingDetail && scope.length > 0 && (
              <div>
                <h3 className='mb-3 text-xs font-semibold uppercase tracking-wider text-zinc-600'>
                  Scope ({scope.filter(s => s.in_scope).length} in · {scope.filter(s => !s.in_scope).length} out)
                </h3>
                <div className='flex flex-wrap gap-1.5'>
                  {scope.map(s => (
                    <span
                      key={s.id}
                      className={cn(
                        'rounded px-2 py-0.5 text-[10px] font-mono',
                        s.in_scope
                          ? 'bg-green-950/50 text-green-400 border border-green-900/50'
                          : 'bg-red-950/30 text-red-500/70 border border-red-900/30 line-through'
                      )}
                    >
                      {s.value}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Template selector */}
            <div className='rounded-xl border border-zinc-800 bg-zinc-900/30 p-5 space-y-3'>
              <h3 className='text-xs font-semibold uppercase tracking-wider text-zinc-500'>Template de informe</h3>
              <div className='grid grid-cols-2 gap-2'>
                {[
                  { id: 'allsafe', label: 'Standard', sub: 'Navy + Rojo (por defecto)',    dot: '#dc2626' },
                  { id: 'htb',     label: 'HackTheBox',       sub: 'Dark + Verde (#9fef00)',        dot: '#9fef00' },
                  { id: 'offsec',  label: 'OffSec / OSCP',    sub: 'Blanco + Rojo profesional',     dot: '#c1292e' },
                  { id: 'ptes',    label: 'PTES',              sub: 'Blanco + Azul metodológico',    dot: '#2563eb' },
                ].map(t => (
                  <button
                    key={t.id}
                    onClick={() => setReportTemplate(t.id as typeof reportTemplate)}
                    className={cn(
                      'text-left rounded-lg border p-3 transition-all',
                      reportTemplate === t.id
                        ? 'border-red-700/60 bg-red-950/30'
                        : 'border-zinc-800 hover:border-zinc-700'
                    )}
                  >
                    <div className='flex items-center gap-2 mb-0.5'>
                      <div className='h-2.5 w-2.5 rounded-full shrink-0' style={{ background: t.dot }} />
                      <p className={cn('text-xs font-semibold', reportTemplate === t.id ? 'text-red-300' : 'text-zinc-300')}>
                        {t.label}
                      </p>
                    </div>
                    <p className='text-[10px] text-zinc-600 ml-4'>{t.sub}</p>
                  </button>
                ))}
              </div>
            </div>

            {/* Report options */}
            <div className='rounded-xl border border-zinc-800 bg-zinc-900/30 p-5 space-y-4'>
              <h3 className='text-xs font-semibold uppercase tracking-wider text-zinc-500'>
                Opciones del informe
              </h3>

              <div className='space-y-3'>
                <div className='flex items-center justify-between'>
                  <div>
                    <Label className='text-sm text-zinc-300'>Pasos para reproducir</Label>
                    <p className='text-xs text-zinc-600 mt-0.5'>Incluye los steps en el detalle técnico de cada hallazgo</p>
                  </div>
                  <Switch checked={includeSteps} onCheckedChange={setIncludeSteps} />
                </div>

                <div className='flex items-center justify-between'>
                  <div>
                    <Label className='text-sm text-zinc-300'>Scope completo</Label>
                    <p className='text-xs text-zinc-600 mt-0.5'>Incluye los activos in-scope y out-of-scope en el resumen ejecutivo</p>
                  </div>
                  <Switch checked={includeScope} onCheckedChange={setIncludeScope} />
                </div>

                <div className='flex items-center justify-between'>
                  <div>
                    <Label className='text-sm text-zinc-300 flex items-center gap-1.5'>
                      {onlyOpen ? <Eye className='h-3.5 w-3.5 text-orange-400' /> : <EyeOff className='h-3.5 w-3.5' />}
                      Solo hallazgos abiertos
                    </Label>
                    <p className='text-xs text-zinc-600 mt-0.5'>
                      {onlyOpen
                        ? `${displayedFindings.length} de ${findings.length} hallazgos incluidos`
                        : `Todos los ${findings.length} hallazgos incluidos`
                      }
                    </p>
                  </div>
                  <Switch checked={onlyOpen} onCheckedChange={setOnlyOpen} />
                </div>
              </div>
            </div>

            {/* Generate button */}
            <div className='rounded-xl border border-zinc-800 bg-zinc-950 p-5'>
              <div className='flex items-center justify-between gap-4'>
                <div>
                  <p className='text-sm font-medium text-zinc-200'>Informe PDF — Ejecutivo + Técnico</p>
                  <p className='text-xs text-zinc-500 mt-0.5'>
                    Portada · Resumen ejecutivo · Tabla de hallazgos · Detalle técnico · Metodología
                  </p>
                  {displayedFindings.length === 0 && !loadingDetail && (
                    <p className='mt-2 flex items-center gap-1.5 text-xs text-yellow-500'>
                      <AlertCircle className='h-3.5 w-3.5' />
                      Necesitás al menos un hallazgo para generar el informe
                    </p>
                  )}
                </div>
                <Button
                  onClick={handleGenerate}
                  disabled={!canGenerate || generating}
                  className={cn(
                    'shrink-0 gap-2',
                    canGenerate
                      ? 'bg-red-700 hover:bg-red-600 text-white'
                      : 'opacity-40'
                  )}
                >
                  {generating ? (
                    <><Loader2 className='h-4 w-4 animate-spin' /> Generando...</>
                  ) : (
                    <><Download className='h-4 w-4' /> Generar PDF</>
                  )}
                </Button>
              </div>

              {canGenerate && (
                <div className='mt-3 flex items-center gap-2 text-xs text-zinc-600'>
                  <CheckCircle2 className='h-3.5 w-3.5 text-green-600' />
                  <span>
                    Listo para generar — {displayedFindings.length} hallazgo{displayedFindings.length !== 1 ? 's' : ''} ·{' '}
                    {scope.filter(s => s.in_scope).length} activos in-scope
                  </span>
                </div>
              )}
            </div>

            {/* Confidentiality note */}
            <div className='flex items-start gap-2 rounded-lg bg-zinc-900/30 border border-zinc-800/50 p-3'>
              <Shield className='h-3.5 w-3.5 text-zinc-600 mt-0.5 shrink-0' />
              <p className='text-[11px] text-zinc-600 leading-relaxed'>
                El PDF se genera completamente en el cliente (no se envían datos a ningún servidor externo).
                El informe incluye aviso de confidencialidad y está marcado como documento restringido.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
