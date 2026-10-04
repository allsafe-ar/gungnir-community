/**
 * MethodologySheet - Cobertura de metodología (checklist WSTG / PTES) de un engagement.
 * QA del informe: qué se testeó y qué no. Herramienta interna del equipo.
 */

import { useState, useEffect, useMemo } from 'react'
import { ListChecks, Loader2, ChevronDown, ChevronRight } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { apiFetch } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'

interface Item {
  key: string
  category: string
  name: string
  status: 'pending' | 'tested' | 'not_applicable'
  note: string
}
interface Resumen { total: number; tested: number; not_applicable: number; pending: number; coverage_pct: number }

const FRAMEWORKS = [
  { value: 'owasp_wstg', label: 'OWASP WSTG' },
  { value: 'ptes', label: 'PTES' },
]
const NEXT: Record<Item['status'], Item['status']> = { pending: 'tested', tested: 'not_applicable', not_applicable: 'pending' }
const DOT: Record<Item['status'], string> = {
  pending: 'bg-muted-foreground/30',
  tested: 'bg-green-500',
  not_applicable: 'bg-muted-foreground/50',
}

export function MethodologySheet({ open, onOpenChange, engagementId }: {
  open: boolean
  onOpenChange: (v: boolean) => void
  engagementId: string
}) {
  const { t } = useTranslation()
  const { auth } = useAuthStore()
  const canWrite = auth.user?.role !== 'lector'
  const [framework, setFramework] = useState('owasp_wstg')
  const [items, setItems] = useState<Item[]>([])
  const [resumen, setResumen] = useState<Resumen | null>(null)
  const [loading, setLoading] = useState(false)
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({})

  const load = (fw: string) => {
    setLoading(true)
    apiFetch<{ items: Item[]; resumen: Resumen }>(`/engagements/${engagementId}/methodology?framework=${fw}`)
      .then(d => { setItems(d.items); setResumen(d.resumen) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }
  useEffect(() => { if (open) load(framework) }, [open, engagementId, framework])

  const byCategory = useMemo(() => {
    const g: Record<string, Item[]> = {}
    for (const it of items) { (g[it.category] ||= []).push(it) }
    return g
  }, [items])

  const cycle = async (it: Item) => {
    if (!canWrite) return
    const status = NEXT[it.status]
    setItems(prev => prev.map(x => x.key === it.key ? { ...x, status } : x))
    try {
      await apiFetch(`/engagements/${engagementId}/methodology/${it.key}`, {
        method: 'PUT', body: JSON.stringify({ framework, status, note: it.note || undefined }),
      })
      // Recalcular el resumen con el estado nuevo.
      load(framework)
    } catch (e) { toast.error(e instanceof Error ? e.message : t('methodology.error')); load(framework) }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side='right' className='w-full sm:max-w-xl flex flex-col p-0 gap-0'>
        <SheetHeader className='p-4 border-b border-border space-y-3'>
          <SheetTitle className='text-sm font-semibold flex items-center gap-2'>
            <ListChecks className='size-4 text-primary' />
            {t('methodology.title')}
          </SheetTitle>
          <div className='flex items-center gap-3'>
            <Select value={framework} onValueChange={setFramework}>
              <SelectTrigger className='h-8 text-xs w-40'><SelectValue /></SelectTrigger>
              <SelectContent>
                {FRAMEWORKS.map(f => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}
              </SelectContent>
            </Select>
            {resumen && (
              <div className='flex-1 flex items-center gap-2'>
                <div className='flex-1 h-2 rounded-full bg-muted overflow-hidden'>
                  <div className='h-full bg-green-500 transition-all' style={{ width: `${resumen.coverage_pct}%` }} />
                </div>
                <span className='text-xs font-semibold tabular-nums'>{resumen.coverage_pct}%</span>
              </div>
            )}
          </div>
          {resumen && (
            <p className='text-[11px] text-muted-foreground'>
              {t('methodology.summary', { tested: resumen.tested, total: resumen.total, na: resumen.not_applicable })}
            </p>
          )}
        </SheetHeader>

        <div className='flex-1 overflow-y-auto p-3 space-y-3'>
          {loading && <div className='flex justify-center py-8'><Loader2 className='size-5 animate-spin text-muted-foreground' /></div>}
          {!loading && Object.entries(byCategory).map(([cat, list]) => {
            const done = list.filter(i => i.status === 'tested').length
            const isCollapsed = collapsed[cat]
            return (
              <div key={cat} className='rounded-lg border border-border overflow-hidden'>
                <button onClick={() => setCollapsed(c => ({ ...c, [cat]: !c[cat] }))}
                  className='w-full flex items-center gap-2 px-3 py-2 bg-muted/30 hover:bg-muted/50 transition-colors text-left'>
                  {isCollapsed ? <ChevronRight className='size-3.5 text-muted-foreground' /> : <ChevronDown className='size-3.5 text-muted-foreground' />}
                  <span className='text-xs font-semibold'>{cat}</span>
                  <span className='ml-auto text-[10px] text-muted-foreground tabular-nums'>{done}/{list.length}</span>
                </button>
                {!isCollapsed && (
                  <div className='divide-y divide-border/50'>
                    {list.map(it => (
                      <button key={it.key} onClick={() => cycle(it)} disabled={!canWrite}
                        className={cn('w-full flex items-start gap-2.5 px-3 py-2 text-left transition-colors',
                          canWrite ? 'hover:bg-accent cursor-pointer' : 'cursor-default',
                          it.status === 'not_applicable' && 'opacity-50')}>
                        <span className={cn('mt-0.5 size-2.5 rounded-full shrink-0', DOT[it.status])} />
                        <span className='shrink-0 font-mono text-[10px] text-primary font-semibold mt-0.5'>{it.key}</span>
                        <span className={cn('text-xs flex-1', it.status === 'tested' && 'text-foreground', it.status !== 'tested' && 'text-muted-foreground')}>
                          {it.name}
                        </span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
          {canWrite && !loading && items.length > 0 && (
            <p className='text-[11px] text-muted-foreground text-center pt-1'>{t('methodology.cycle_hint')}</p>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}
