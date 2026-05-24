import { useEffect, useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import {
  CheckCircle2, Circle, Clock,
  ArrowLeft, Terminal, Upload, Crosshair,
  ShieldAlert, Target, Settings,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Textarea } from '@/components/ui/textarea'
import { Input } from '@/components/ui/input'
import { apiFetch } from '@/lib/api'
import { toast } from 'sonner'
import { HallazgoSheet } from '@/features/hallazgos/components/hallazgo-sheet'
import { ScannerImportDialog } from '@/features/hallazgos/components/scanner-import-dialog'
import { ScopeSheet } from './scope-sheet'
import { EvidenceSheet } from './evidence-sheet'
import { CustomWorkspace } from './custom-workspace'
import { TecnicasSheet } from './tecnicas-sheet'

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

const PHASE_LABEL: Record<string, string> = {
  planning:          'Planificación',
  recon:             'Reconocimiento',
  scanning:          'Escaneo',
  exploitation:      'Explotación',
  post_exploitation: 'Post-explotación',
  reporting:         'Reporting',
}
const PHASE_DESC: Record<string, string> = {
  planning:          'Pre-engagement, alcance, RoE, contactos, autorización',
  recon:             'OSINT, enumeración de activos, superficie de ataque',
  scanning:          'Nmap, Nessus, Burp, nuclei, análisis de vulnerabilidades',
  exploitation:      'Explotación controlada, evidencias, impacto demostrado',
  post_exploitation: 'Solo si autorizado: escalamiento, movimiento lateral',
  reporting:         'Consolidación de hallazgos, informe ejecutivo y técnico',
}
const SEV_COLOR: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  high:     'bg-orange-500/10 text-orange-500 border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-600 border-yellow-500/20',
  low:      'bg-blue-500/10 text-blue-500 border-blue-500/20',
  info:     'bg-muted text-muted-foreground border-border',
}
const SEV_LABEL: Record<string, string> = {
  critical: 'CRÍTICO', high: 'ALTO', medium: 'MEDIO', low: 'BAJO', info: 'INFO',
}

// ─── Componente ───────────────────────────────────────────────────────────────
export function EngagementWorkspace({ engagementId }: { engagementId: string }) {
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

  useEffect(() => { load() }, [engagementId])
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
    } catch { toast.error('Error al cambiar fase') }
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
        <p className='text-muted-foreground'>Engagement no encontrado.</p>
        <Button variant='outline' onClick={() => navigate({ to: '/engagements' })}>Volver</Button>
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
            <ArrowLeft className='mr-1 size-3' /> Engagements
          </Button>
          <p className='font-semibold text-sm leading-tight truncate'>{engagement.title}</p>
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
                  <span className='text-xs font-medium'>{PHASE_LABEL[phaseKey]}</span>
                </div>
                {phaseData && (phaseData.logs_count > 0 || phaseData.findings_count > 0) && (
                  <div className='ml-5 mt-0.5 flex gap-2 text-[10px] text-muted-foreground'>
                    {phaseData.logs_count > 0 && <span>{phaseData.logs_count} log{phaseData.logs_count !== 1 ? 's' : ''}</span>}
                    {phaseData.findings_count > 0 && <span>{phaseData.findings_count} hall.</span>}
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
            + Hallazgo
          </Button>
          <Button size='sm' variant='ghost' className='w-full text-xs h-8 text-muted-foreground'
            onClick={() => setScannerOpen(true)}>
            <Upload className='mr-1.5 size-3' />
            Importar scan
          </Button>
          <Button size='sm' variant='ghost' className='w-full text-xs h-8 text-muted-foreground'
            onClick={() => setScopeOpen(true)}>
            <Target className='mr-1.5 size-3' />
            Scope
          </Button>
          <Button size='sm' variant='ghost' className='w-full text-xs h-8 text-muted-foreground'
            onClick={() => setTecnicasOpen(true)}>
            <Crosshair className='mr-1.5 size-3' />
            Técnicas
          </Button>
          <Button size='sm' variant='ghost' className='w-full text-xs h-8 text-muted-foreground'
            onClick={() => navigate({ to: '/engagements/$engagementId/editar', params: { engagementId } })}>
            <Settings className='mr-1.5 size-3' />
            Editar
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
                <h2 className='text-xl font-bold'>{PHASE_LABEL[activePhase]}</h2>
                {engagement.current_phase === activePhase && (
                  <Badge variant='default' className='text-xs'>Activa</Badge>
                )}
              </div>
              <p className='text-sm text-muted-foreground mt-0.5'>{PHASE_DESC[activePhase]}</p>
            </div>
            {engagement.current_phase !== activePhase && (
              <Button size='sm' variant='outline' onClick={() => setPhaseActive(activePhase)}>
                Activar fase
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
                  {savingLog ? 'Guardando...' : 'Guardar log'}
                </Button>
                <Button size='sm' variant='outline' className='text-xs h-7'
                  onClick={() => setEvidenceOpen(true)}>
                  <Upload className='mr-1.5 size-3' />
                  Evidencia
                </Button>
              </div>
            </div>
          </div>

          {/* Operation log */}
          {logs.length > 0 && (
            <div>
              <h3 className='text-sm font-semibold mb-3'>
                Operation Log — {PHASE_LABEL[activePhase]}
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
                      {SEV_LABEL[f.severity]}
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
        onOpenChange={setEvidenceOpen}
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
