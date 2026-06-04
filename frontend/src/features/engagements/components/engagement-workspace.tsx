import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from '@tanstack/react-router'
import {
  CheckCircle2, Circle, Clock,
  ArrowLeft, Terminal, Upload, Crosshair,
  ShieldAlert, Target, Settings, Pencil, Check, X, Download, Paperclip,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Textarea } from '@/components/ui/textarea'
import { Input } from '@/components/ui/input'
import { apiFetch } from '@/lib/api'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'
import { HallazgoSheet } from '@/features/hallazgos/components/hallazgo-sheet'
import { ScannerImportDialog } from '@/features/hallazgos/components/scanner-import-dialog'
import { ScopeSheet } from './scope-sheet'
import { EvidenceSheet } from './evidence-sheet'
import { CustomWorkspace } from './custom-workspace'
import { TecnicasSheet } from './tecnicas-sheet'
import { getPhaseLabel } from '@/features/engagements'

// ─── Tipos ────────────────────────────────────────────────────────────────────
interface Phase {
  id: string
  phase_type: string
  status: 'not_started' | 'in_progress' | 'completed'
  logs_count: number
  findings_count: number
}
interface OperationLog {
  id: string
  logged_at: string
  target: string
  tool: string
  command: string
  notes: string
}
interface Finding {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: string
  cvss_score_31: number | null
  affected_asset: string
}
interface EngagementDetail {
  id: string
  title: string
  client_name: string
  type: string
  mode: string
  status: string
  current_phase: string
  phases: Phase[]
}

// ─── Constantes ───────────────────────────────────────────────────────────────
const PHASES_ORDER = ['planning','recon','scanning','exploitation','post_exploitation','reporting']

function getPhaseDesc(t: (k: string, o?: Record<string, unknown>) => string): Record<string, string> {
  return {
    planning:          t('planning.objectives_label'),
    recon:             'OSINT, enumeración de activos, superficie de ataque',
    scanning:          'Nmap, Nessus, Burp, nuclei, análisis de vulnerabilidades',
    exploitation:      'Explotación controlada, evidencias, impacto demostrado',
    post_exploitation: 'Solo si autorizado: escalamiento, movimiento lateral',
    reporting:         'Consolidación de hallazgos, informe ejecutivo y técnico',
  }
}

const SEV_COLOR: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  high:     'bg-orange-500/10 text-orange-500 border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-600 border-yellow-500/20',
  low:      'bg-blue-500/10 text-blue-500 border-blue-500/20',
  info:     'bg-muted text-muted-foreground border-border',
}

function getSevLabel(t: (k: string) => string): Record<string, string> {
  return {
    critical: t('finding.sev_critical').toUpperCase(),
    high:     t('finding.sev_high').toUpperCase(),
    medium:   t('finding.sev_medium').toUpperCase(),
    low:      t('finding.sev_low').toUpperCase(),
    info:     'INFO',
  }
}

// ─── Componente ───────────────────────────────────────────────────────────────
export function EngagementWorkspace({ engagementId }: { engagementId: string }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [engagement, setEngagement] = useState<EngagementDetail | null>(null)
  const [activePhase, setActivePhase] = useState<string>('')
  const [logs, setLogs] = useState<OperationLog[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)

  const [logTarget, setLogTarget]   = useState('')
  const [logTool, setLogTool]       = useState('')
  const [logCommand, setLogCommand] = useState('')
  const [logNotes, setLogNotes]     = useState('')
  const [savingLog, setSavingLog]   = useState(false)

  // Hallazgo sheet
  const [hallazgoOpen, setHallazgoOpen]   = useState(false)
  const [hallazgoId, setHallazgoId]       = useState<string | undefined>(undefined)
  // Scanner import
  const [scannerOpen, setScannerOpen]     = useState(false)
  // Scope sheet
  const [scopeOpen, setScopeOpen]         = useState(false)
  // Evidence sheet
  const [evidenceOpen, setEvidenceOpen]   = useState(false)
  // Técnicas sheet
  const [tecnicasOpen, setTecnicasOpen]   = useState(false)

  const [evidenceCounts, setEvidenceCounts] = useState<Record<string, number>>({})

  // Inline title edit
  const [editingTitle, setEditingTitle] = useState(false)
  const [titleInput, setTitleInput]     = useState('')

  const phaseLabel = getPhaseLabel(t)
  const sevLabel   = getSevLabel(t)

  const saveTitle = async () => {
    if (!titleInput.trim() || titleInput.trim() === engagement?.title) { setEditingTitle(false); return }
    try {
      await apiFetch(`/engagements/${engagementId}/title`, { method: 'PATCH', body: { title: titleInput.trim() } })
      setEngagement(prev => prev ? { ...prev, title: titleInput.trim() } : prev)
      setEditingTitle(false)
      toast.success(t('eng.title_updated'))
    } catch { toast.error(t('eng.title_error')) }
  }

  const loadEvidenceCounts = useCallback(() => {
    apiFetch<Array<{ phase_type?: string }>>(`/engagements/${engagementId}/evidences`)
      .then(items => {
        const counts: Record<string, number> = {}
        for (const item of (items ?? [])) {
          const key = item.phase_type ?? '__none__'
          counts[key] = (counts[key] ?? 0) + 1
        }
        setEvidenceCounts(counts)
      })
      .catch(() => {})
  }, [engagementId])

  const load = () => {
    apiFetch(`/engagements/${engagementId}`)
      .then((eng: unknown) => {
        const e = eng as EngagementDetail
        setEngagement(e)
        const current = e.current_phase ||
          e.phases.find(p => p.status === 'in_progress')?.phase_type || PHASES_ORDER[0]
        setActivePhase(current)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  const loadPhaseData = (phase: string) => {
    apiFetch(`/engagements/${engagementId}/phases/${phase}/logs`)
      .then((d: unknown) => setLogs(d as OperationLog[])).catch(() => setLogs([]))
    apiFetch(`/engagements/${engagementId}/findings?phase=${phase}`)
      .then((d: unknown) => setFindings(d as Finding[])).catch(() => setFindings([]))
  }

  useEffect(() => { load(); loadEvidenceCounts() }, [engagementId, loadEvidenceCounts])
  useEffect(() => { if (activePhase) loadPhaseData(activePhase) }, [activePhase])

  const saveLog = async () => {
    if (!logCommand && !logNotes) return
    setSavingLog(true)
    try {
      await apiFetch(`/engagements/${engagementId}/phases/${activePhase}/logs`, {
        method: 'POST',
        body: JSON.stringify({ target: logTarget, tool: logTool, command: logCommand, notes: logNotes }),
      })
      setLogTarget(''); setLogTool(''); setLogCommand(''); setLogNotes('')
      loadPhaseData(activePhase)
      toast.success('Log registrado')
    } catch { toast.error('Error al guardar') } finally { setSavingLog(false) }
  }

  const setPhaseActive = async (phase: string) => {
    try {
      await apiFetch(`/engagements/${engagementId}/phase`, {
        method: 'PUT',
        body: JSON.stringify({ phase }),
      })
      load()
    } catch { toast.error(t('eng.phase_change_error')) }
  }

  const handleExport = () => {
    const token = localStorage.getItem('gungnir_token')
    fetch(`/api/engagements/${engagementId}/export`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then(r => {
        if (!r.ok) return Promise.reject()
        const cd = r.headers.get('Content-Disposition')
        const match = cd?.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/)
        const filename = match ? match[1].replace(/['"]/g, '') : `engagement-${engagementId}.zip`
        return r.blob().then(blob => ({ blob, filename }))
      })
      .then(({ blob, filename }) => {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url; a.download = filename
        document.body.appendChild(a); a.click()
        document.body.removeChild(a); URL.revokeObjectURL(url)
      })
      .catch(() => toast.error(t('eng.export_error')))
  }

  if (loading) {
    return (
      <div className='flex h-64 items-center justify-center'>
        <div className='h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent' />
      </div>
    )
  }

  if (!engagement) {
    return (
      <div className='flex flex-col items-center gap-4 py-16'>
        <p className='text-muted-foreground'>{t('eng.not_found')}</p>
        <Button variant='outline' onClick={() => navigate({ to: '/engagements' })}>{t('eng.go_back')}</Button>
      </div>
    )
  }

  // ── Modo custom: workspace con fases editables ────────────────────────────
  if (engagement.mode === 'custom') {
    return <CustomWorkspace engagementId={engagementId} />
  }

  return (
    <div className='flex h-[calc(100vh-4rem)] gap-0 -m-6'>
      {/* ── Sidebar de fases ─────────────────────────────────────────────── */}
      <div className='w-52 shrink-0 border-r border-border flex flex-col bg-sidebar'>
        <div className='p-4 border-b border-border'>
          <Button variant='ghost' size='sm' className='mb-3 -ml-2 h-7 text-xs text-muted-foreground'
            onClick={() => navigate({ to: '/engagements' })}>
            <ArrowLeft className='mr-1 size-3' /> {t('engs.title')}
          </Button>
          {editingTitle ? (
            <div className='flex items-center gap-1 mt-1'>
              <input
                autoFocus
                value={titleInput}
                onChange={e => setTitleInput(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') saveTitle(); if (e.key === 'Escape') setEditingTitle(false) }}
                className='flex-1 min-w-0 rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-100 border border-zinc-600 outline-none'
              />
              <button onClick={saveTitle} className='text-green-400 hover:text-green-300 shrink-0'><Check className='size-3' /></button>
              <button onClick={() => setEditingTitle(false)} className='text-zinc-500 hover:text-zinc-300 shrink-0'><X className='size-3' /></button>
            </div>
          ) : (
            <div className='group/title flex items-center gap-1'>
              <p className='font-semibold text-sm leading-tight truncate flex-1'>{engagement.title}</p>
              <button
                onClick={() => { setTitleInput(engagement.title); setEditingTitle(true) }}
                className='opacity-0 group-hover/title:opacity-100 transition rounded p-0.5 text-zinc-600 hover:text-zinc-300 shrink-0'>
                <Pencil className='size-3' />
              </button>
            </div>
          )}
          <p className='text-xs text-muted-foreground truncate mt-0.5'>{engagement.client_name}</p>
        </div>

        <div className='flex-1 overflow-y-auto py-2'>
          {PHASES_ORDER.map((phaseKey) => {
            const phaseData = engagement.phases.find(p => p.phase_type === phaseKey)
            const isActive  = activePhase === phaseKey
            const status    = phaseData?.status ?? 'not_started'

            return (
              <button
                key={phaseKey}
                onClick={() => setActivePhase(phaseKey)}
                className={`w-full text-left px-4 py-2.5 transition-colors ${
                  isActive
                    ? 'bg-sidebar-accent border-l-2 border-primary text-sidebar-foreground'
                    : 'text-muted-foreground hover:bg-sidebar-accent/50 border-l-2 border-transparent'
                }`}
              >
                <div className='flex items-center gap-2'>
                  {status === 'completed' ? (
                    <CheckCircle2 className='size-3.5 text-green-500 shrink-0' />
                  ) : status === 'in_progress' ? (
                    <Clock className='size-3.5 text-primary shrink-0' />
                  ) : (
                    <Circle className='size-3.5 shrink-0 opacity-40' />
                  )}
                  <span className='text-xs font-medium'>{phaseLabel[phaseKey] ?? phaseKey}</span>
                </div>
                {phaseData && (phaseData.logs_count > 0 || phaseData.findings_count > 0 || (evidenceCounts[phaseKey] ?? 0) > 0) && (
                  <div className='ml-5 mt-0.5 flex gap-2 text-[10px] text-muted-foreground'>
                    {phaseData.logs_count > 0 && <span>{phaseData.logs_count} log{phaseData.logs_count !== 1 ? 's' : ''}</span>}
                    {phaseData.findings_count > 0 && <span>{phaseData.findings_count} hall.</span>}
                    {(evidenceCounts[phaseKey] ?? 0) > 0 && <span className='text-primary/70'>{evidenceCounts[phaseKey]} ev.</span>}
                  </div>
                )}
              </button>
            )
          })}
        </div>

        <div className='p-3 border-t border-border space-y-1.5'>
          <Button size='sm' variant='outline' className='w-full text-xs h-8'
            onClick={() => { setHallazgoId(undefined); setHallazgoOpen(true) }}>
            <ShieldAlert className='mr-1.5 size-3' />
            {t('eng.new_finding')}
          </Button>
          <Button size='sm' variant='ghost' className='w-full text-xs h-8 text-muted-foreground'
            onClick={() => setScannerOpen(true)}>
            <Upload className='mr-1.5 size-3' />
            {t('eng.import_scan')}
          </Button>
          <Button size='sm' variant='ghost' className='w-full text-xs h-8 text-muted-foreground'
            onClick={() => setScopeOpen(true)}>
            <Target className='mr-1.5 size-3' />
            {t('scope.title')}
          </Button>
          <Button size='sm' variant='ghost' className='w-full text-xs h-8 text-muted-foreground'
            onClick={() => setTecnicasOpen(true)}>
            <Crosshair className='mr-1.5 size-3' />
            {t('eng.techniques')}
          </Button>
          <Button size='sm' variant='ghost' className='w-full text-xs h-8 text-muted-foreground'
            onClick={() => navigate({ to: '/engagements/$engagementId/editar', params: { engagementId } })}>
            <Settings className='mr-1.5 size-3' />
            {t('eng.edit_engagement')}
          </Button>
          <Button size='sm' variant='ghost' className='w-full text-xs h-8 text-muted-foreground'
            onClick={handleExport}>
            <Download className='mr-1.5 size-3' />{t('eng.export_zip')}
          </Button>
        </div>
      </div>

      {/* ── Área principal ────────────────────────────────────────────────── */}
      <div className='flex-1 overflow-y-auto'>
        <div className='p-6 space-y-5 max-w-3xl'>
          {/* Header de la fase */}
          <div className='flex items-start justify-between'>
            <div>
              <div className='flex items-center gap-2'>
                <h2 className='text-xl font-bold'>{phaseLabel[activePhase] ?? activePhase}</h2>
                {engagement.current_phase === activePhase && (
                  <Badge variant='default' className='text-xs'>{t('eng.activate')}</Badge>
                )}
              </div>
            </div>
            {engagement.current_phase !== activePhase && (
              <Button size='sm' variant='outline' onClick={() => setPhaseActive(activePhase)}>
                {t('eng.activate')}
              </Button>
            )}
          </div>

          <Separator />

          {/* Quick log */}
          <div>
            <h3 className='text-sm font-semibold mb-3 flex items-center gap-2'>
              <Terminal className='size-4 text-muted-foreground' />
              Registrar actividad
            </h3>
            <div className='space-y-2'>
              <div className='grid grid-cols-2 gap-2'>
                <Input placeholder='Target (IP / dominio)' value={logTarget} onChange={(e) => setLogTarget(e.target.value)} className='text-xs font-mono h-8' />
                <Input placeholder='Herramienta (nmap, burp...)' value={logTool} onChange={(e) => setLogTool(e.target.value)} className='text-xs h-8' />
              </div>
              <Textarea placeholder='Comando ejecutado...' value={logCommand} onChange={(e) => setLogCommand(e.target.value)} className='font-mono text-xs resize-none' rows={2} />
              <Textarea placeholder='Notas / resultado relevante...' value={logNotes} onChange={(e) => setLogNotes(e.target.value)} className='text-xs resize-none' rows={2} />
              <div className='flex gap-2'>
                <Button size='sm' onClick={saveLog} disabled={savingLog || (!logCommand && !logNotes)} className='text-xs h-7'>
                  {savingLog ? t('common.loading') : 'Guardar log'}
                </Button>
                <Button size='sm' variant='outline' className={`text-xs h-7 relative ${(evidenceCounts[activePhase] ?? 0) > 0 ? 'text-primary border-primary/40' : ''}`}
                  onClick={() => setEvidenceOpen(true)}>
                  <Paperclip className='mr-1.5 size-3' />
                  {t('eng.evidence')}
                  {(evidenceCounts[activePhase] ?? 0) > 0 && (
                    <span className='ml-1.5 rounded-full bg-primary text-primary-foreground text-[9px] font-bold px-1.5 py-0.5 leading-none'>
                      {evidenceCounts[activePhase]}
                    </span>
                  )}
                </Button>
              </div>
            </div>
          </div>

          {/* Operation log */}
          {logs.length > 0 && (
            <div>
              <h3 className='text-sm font-semibold mb-3'>
                Operation Log — {phaseLabel[activePhase] ?? activePhase}
              </h3>
              <div className='space-y-2'>
                {logs.slice(0, 10).map((log) => (
                  <div key={log.id} className='rounded-md border border-border bg-muted/30 px-3 py-2'>
                    <div className='flex items-center gap-2 text-xs text-muted-foreground mb-1'>
                      <span className='font-mono'>{new Date(log.logged_at).toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit' })}</span>
                      {log.tool && <Badge variant='outline' className='text-[10px] px-1 py-0 h-4'>{log.tool}</Badge>}
                      {log.target && <span className='font-mono'>{log.target}</span>}
                    </div>
                    {log.command && <p className='font-mono text-xs text-foreground/80 break-all'>{log.command}</p>}
                    {log.notes && <p className='text-xs text-muted-foreground mt-1'>{log.notes}</p>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Hallazgos */}
          {findings.length > 0 && (
            <div>
              <h3 className='text-sm font-semibold mb-3'>Hallazgos en esta fase</h3>
              <div className='space-y-2'>
                {findings.map((f) => (
                  <button
                    key={f.id}
                    className='w-full flex items-center gap-3 rounded-md border border-border px-3 py-2 hover:bg-accent transition-colors text-left'
                    onClick={() => { setHallazgoId(f.id); setHallazgoOpen(true) }}
                  >
                    <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-bold ${SEV_COLOR[f.severity]}`}>
                      {sevLabel[f.severity] ?? f.severity}
                    </span>
                    <span className='text-sm flex-1 truncate'>{f.title}</span>
                    {f.cvss_score_31 && (
                      <span className='text-xs text-muted-foreground shrink-0'>{Number(f.cvss_score_31).toFixed(1)}</span>
                    )}
                  </button>
                ))}
              </div>
            </div>
          )}

          {logs.length === 0 && findings.length === 0 && (
            <div className='flex flex-col items-center gap-3 py-10 text-center'>
              <Crosshair className='size-10 text-muted-foreground/30' />
              <p className='text-sm text-muted-foreground'>
                Fase vacía. Registrá tu primera actividad arriba o añadí un hallazgo.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Hallazgo sheet */}
      <HallazgoSheet
        open={hallazgoOpen}
        onOpenChange={setHallazgoOpen}
        engagementId={engagementId}
        defaultPhase={activePhase}
        hallazgoId={hallazgoId}
        onSaved={() => loadPhaseData(activePhase)}
      />

      {/* Scanner import */}
      <ScannerImportDialog
        open={scannerOpen}
        onOpenChange={setScannerOpen}
        engagementId={engagementId}
        onImported={() => loadPhaseData(activePhase)}
      />

      {/* Scope sheet */}
      <ScopeSheet
        open={scopeOpen}
        onOpenChange={setScopeOpen}
        engagementId={engagementId}
      />

      {/* Evidence sheet */}
      <EvidenceSheet
        open={evidenceOpen}
        onOpenChange={v => { setEvidenceOpen(v); if (!v) loadEvidenceCounts() }}
        engagementId={engagementId}
        currentPhase={activePhase}
      />

      {/* Técnicas sheet */}
      <TecnicasSheet
        open={tecnicasOpen}
        onOpenChange={setTecnicasOpen}
        engagementId={engagementId}
        currentPhaseType={activePhase}
      />
    </div>
  )
}
