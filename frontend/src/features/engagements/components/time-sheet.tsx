/**
 * TimeSheet - Registro de tiempo por fase y operador dentro de un engagement.
 * Herramienta interna del equipo (horas de pentest), no se expone al cliente.
 */

import { useState, useEffect } from 'react'
import { Timer, Plus, Trash2, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { apiFetch } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'

interface TimeEntry {
  id: string
  phase_type: string | null
  custom_phase_name: string | null
  user_name: string | null
  minutes: number
  note: string | null
  worked_on: string | null
  user_id: string
}
interface TimeResumen {
  total_minutes: number
  por_fase: Record<string, number>
  por_operador: Record<string, number>
}

const PHASES = ['planning', 'recon', 'scanning', 'exploitation', 'post_exploitation', 'reporting']

function fmtDur(min: number) {
  const h = Math.floor(min / 60), m = min % 60
  return h > 0 ? `${h}h${m > 0 ? ` ${m}m` : ''}` : `${m}m`
}

export function TimeSheet({ open, onOpenChange, engagementId, currentPhase }: {
  open: boolean
  onOpenChange: (v: boolean) => void
  engagementId: string
  currentPhase?: string
}) {
  const { t } = useTranslation()
  const { auth } = useAuthStore()
  const canWrite = auth.user?.role !== 'lector'
  const [entries, setEntries] = useState<TimeEntry[]>([])
  const [resumen, setResumen] = useState<TimeResumen | null>(null)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)

  const [hours, setHours]   = useState('')
  const [phase, setPhase]   = useState(currentPhase || 'recon')
  const [note, setNote]     = useState('')
  const [day, setDay]       = useState(() => new Date().toLocaleDateString('en-CA'))

  const load = () => {
    setLoading(true)
    apiFetch<{ entries: TimeEntry[]; resumen: TimeResumen }>(`/engagements/${engagementId}/time`)
      .then(d => { setEntries(d.entries); setResumen(d.resumen) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }
  useEffect(() => { if (open) { load(); setPhase(currentPhase || 'recon') } }, [open, engagementId])

  const add = async () => {
    const h = parseFloat(hours.replace(',', '.'))
    if (!h || h <= 0) { toast.error(t('time.hours_required')); return }
    setSaving(true)
    try {
      await apiFetch(`/engagements/${engagementId}/time`, {
        method: 'POST',
        body: JSON.stringify({ hours: h, phase_type: phase, note: note || undefined, worked_on: day }),
      })
      setHours(''); setNote('')
      load()
      toast.success(t('time.added'))
    } catch (e) { toast.error(e instanceof Error ? e.message : t('time.error')) } finally { setSaving(false) }
  }

  const del = async (id: string) => {
    try {
      await apiFetch(`/engagements/${engagementId}/time/${id}`, { method: 'DELETE' })
      load()
    } catch { toast.error(t('time.error')) }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side='right' className='w-full sm:max-w-lg flex flex-col p-0 gap-0'>
        <SheetHeader className='p-4 border-b border-border'>
          <SheetTitle className='text-sm font-semibold flex items-center gap-2'>
            <Timer className='size-4 text-primary' />
            {t('time.title')}
            {resumen && <span className='ml-auto text-xs font-normal text-muted-foreground'>{t('time.total')}: {fmtDur(resumen.total_minutes)}</span>}
          </SheetTitle>
        </SheetHeader>

        <div className='flex-1 overflow-y-auto p-4 space-y-4'>
          {canWrite && (
            <div className='rounded-lg border border-border/60 bg-muted/20 p-3 space-y-2'>
              <div className='grid grid-cols-2 gap-2'>
                <Input type='number' step='0.25' min='0' value={hours} onChange={e => setHours(e.target.value)}
                  placeholder={t('time.hours_ph')} className='h-8 text-xs' />
                <Input type='date' value={day} onChange={e => setDay(e.target.value)} className='h-8 text-xs' />
              </div>
              <Select value={phase} onValueChange={setPhase}>
                <SelectTrigger className='h-8 text-xs'><SelectValue /></SelectTrigger>
                <SelectContent>
                  {PHASES.map(p => <SelectItem key={p} value={p}>{t(`phase.${p}`)}</SelectItem>)}
                </SelectContent>
              </Select>
              <Input value={note} onChange={e => setNote(e.target.value)} placeholder={t('time.note_ph')} className='h-8 text-xs' />
              <Button size='sm' onClick={add} disabled={saving} className='h-7 text-xs gap-1'>
                {saving ? <Loader2 className='size-3 animate-spin' /> : <Plus className='size-3' />} {t('time.add')}
              </Button>
            </div>
          )}

          {resumen && Object.keys(resumen.por_fase).length > 0 && (
            <div className='grid grid-cols-2 gap-3'>
              <div className='rounded-md border border-border bg-card p-3'>
                <p className='text-[10px] font-semibold uppercase tracking-wide text-muted-foreground mb-1.5'>{t('time.by_phase')}</p>
                {Object.entries(resumen.por_fase).map(([k, v]) => (
                  <div key={k} className='flex justify-between text-xs py-0.5'>
                    <span className='text-muted-foreground'>{PHASES.includes(k) ? t(`phase.${k}`) : k}</span>
                    <span className='font-mono'>{fmtDur(v)}</span>
                  </div>
                ))}
              </div>
              <div className='rounded-md border border-border bg-card p-3'>
                <p className='text-[10px] font-semibold uppercase tracking-wide text-muted-foreground mb-1.5'>{t('time.by_operator')}</p>
                {Object.entries(resumen.por_operador).map(([k, v]) => (
                  <div key={k} className='flex justify-between text-xs py-0.5'>
                    <span className='text-muted-foreground truncate max-w-28'>{k}</span>
                    <span className='font-mono'>{fmtDur(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className='space-y-1.5'>
            {loading && <div className='flex justify-center py-6'><Loader2 className='size-4 animate-spin text-muted-foreground' /></div>}
            {!loading && entries.length === 0 && <p className='text-xs text-muted-foreground text-center py-6'>{t('time.empty')}</p>}
            {entries.map(e => (
              <div key={e.id} className='group flex items-center gap-2 rounded-md border border-border bg-muted/20 px-3 py-2 text-xs'>
                <span className='font-mono font-semibold tabular-nums'>{fmtDur(e.minutes)}</span>
                <span className='text-muted-foreground'>{e.custom_phase_name || (e.phase_type ? t(`phase.${e.phase_type}`) : '—')}</span>
                {e.note && <span className='truncate flex-1 text-foreground/70'>{e.note}</span>}
                <span className='ml-auto text-[10px] text-muted-foreground shrink-0'>{e.user_name} · {e.worked_on?.slice(0, 10)}</span>
                {(canWrite && (auth.user?.id === e.user_id || auth.user?.role === 'admin' || auth.user?.role === 'auditor')) && (
                  <button onClick={() => del(e.id)} className='opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive shrink-0'>
                    <Trash2 className='size-3' />
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      </SheetContent>
    </Sheet>
  )
}
