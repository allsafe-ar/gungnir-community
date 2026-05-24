/**
 * ScopeSheet — Manage scope items (in-scope / out-of-scope) for an engagement.
 * Opens as a Sheet from the right, keeping workspace context intact.
 */

import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { X, Plus, Trash2, ShieldCheck, ShieldOff, Target } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Badge } from '@/components/ui/badge'
import { apiFetch } from '@/lib/api'
import { cn } from '@/lib/utils'

// ─── Tipos ────────────────────────────────────────────────────────────────────
interface ScopeItem {
  id: string
  type: string
  value: string
  in_scope: boolean | number
  notes: string
}

interface ScopeSheetProps {
  open: boolean
  onOpenChange: (v: boolean) => void
  engagementId: string
}

const TYPES = [
  { value: 'ip',          label: 'IP' },
  { value: 'cidr',        label: 'CIDR' },
  { value: 'domain',      label: 'Dominio' },
  { value: 'url',         label: 'URL' },
  { value: 'application', label: 'Aplicación' },
  { value: 'other',       label: 'Otro' },
]

const TYPE_BADGE: Record<string, string> = {
  ip:          'font-mono text-[10px] bg-blue-500/10 text-blue-400 border-blue-500/20',
  cidr:        'font-mono text-[10px] bg-purple-500/10 text-purple-400 border-purple-500/20',
  domain:      'font-mono text-[10px] bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  url:         'font-mono text-[10px] bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  application: 'text-[10px] bg-orange-500/10 text-orange-400 border-orange-500/20',
  other:       'text-[10px] bg-muted text-muted-foreground border-border',
}

// ─── Componente ───────────────────────────────────────────────────────────────
export function ScopeSheet({ open, onOpenChange, engagementId }: ScopeSheetProps) {
  const [items, setItems]   = useState<ScopeItem[]>([])
  const [loading, setLoading] = useState(false)
  const [type, setType]     = useState('domain')
  const [value, setValue]   = useState('')
  const [inScope, setInScope] = useState(true)
  const [notes, setNotes]   = useState('')
  const [adding, setAdding] = useState(false)

  const load = () => {
    setLoading(true)
    apiFetch<ScopeItem[]>(`/engagements/${engagementId}/scope`)
      .then(d => setItems(d as ScopeItem[]))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    if (open) load()
  }, [open, engagementId])

  const handleAdd = async () => {
    if (!value.trim()) { toast.error('El valor es requerido'); return }
    setAdding(true)
    try {
      await apiFetch(`/engagements/${engagementId}/scope`, {
        method: 'POST',
        body: JSON.stringify({ type, value: value.trim(), in_scope: inScope, notes: notes.trim() || undefined }),
      })
      setValue(''); setNotes('')
      load()
      toast.success(`${inScope ? 'In-scope' : 'Out-of-scope'}: ${value.trim()}`)
    } catch {
      toast.error('Error al agregar')
    } finally {
      setAdding(false)
    }
  }

  const handleDelete = async (id: string, val: string) => {
    try {
      await apiFetch(`/engagements/${engagementId}/scope/${id}`, { method: 'DELETE' })
      setItems(prev => prev.filter(i => i.id !== id))
      toast.success(`Eliminado: ${val}`)
    } catch {
      toast.error('Error al eliminar')
    }
  }

  const inScopeItems  = items.filter(i => i.in_scope)
  const outOfScope    = items.filter(i => !i.in_scope)

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side='right' className='w-full sm:max-w-lg flex flex-col p-0 gap-0' hideCloseButton>
        {/* Header */}
        <SheetHeader className='px-6 py-4 border-b border-border flex-row items-center justify-between space-y-0'>
          <SheetTitle className='text-base font-semibold flex items-center gap-2'>
            <Target className='size-4 text-primary' />
            Alcance / Scope
          </SheetTitle>
          <Button variant='ghost' size='icon' className='h-7 w-7' onClick={() => onOpenChange(false)}>
            <X className='size-4' />
          </Button>
        </SheetHeader>

        {/* Add form */}
        <div className='px-6 py-4 border-b border-border bg-muted/30 space-y-3'>
          <p className='text-xs font-semibold text-muted-foreground uppercase tracking-wide'>Agregar objetivo</p>
          <div className='flex gap-2'>
            <Select value={type} onValueChange={setType}>
              <SelectTrigger className='w-32 h-8 text-xs'>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TYPES.map(t => <SelectItem key={t.value} value={t.value} className='text-xs'>{t.label}</SelectItem>)}
              </SelectContent>
            </Select>
            <Input
              value={value}
              onChange={e => setValue(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAdd()}
              placeholder={type === 'ip' ? '192.168.1.0' : type === 'cidr' ? '10.0.0.0/8' : type === 'domain' ? 'ejemplo.com' : type === 'url' ? 'https://app.ejemplo.com' : 'valor...'}
              className='flex-1 h-8 text-xs font-mono'
            />
          </div>
          <div className='flex gap-2 items-center'>
            <div className='flex rounded-md border border-border overflow-hidden'>
              <button
                onClick={() => setInScope(true)}
                className={cn('px-3 py-1.5 text-xs font-medium transition-colors flex items-center gap-1.5',
                  inScope ? 'bg-green-500/10 text-green-500 border-r border-green-500/20' : 'text-muted-foreground hover:bg-muted border-r border-border'
                )}
              >
                <ShieldCheck className='size-3' /> In-scope
              </button>
              <button
                onClick={() => setInScope(false)}
                className={cn('px-3 py-1.5 text-xs font-medium transition-colors flex items-center gap-1.5',
                  !inScope ? 'bg-red-500/10 text-red-500' : 'text-muted-foreground hover:bg-muted'
                )}
              >
                <ShieldOff className='size-3' /> Excluido
              </button>
            </div>
            <Input
              value={notes}
              onChange={e => setNotes(e.target.value)}
              placeholder='Nota opcional...'
              className='flex-1 h-8 text-xs'
            />
            <Button size='sm' onClick={handleAdd} disabled={adding || !value.trim()} className='h-8 shrink-0'>
              <Plus className='size-3.5' />
            </Button>
          </div>
        </div>

        {/* Scope list */}
        <div className='flex-1 overflow-y-auto px-6 py-4 space-y-5'>
          {loading ? (
            <div className='flex justify-center py-8'>
              <div className='h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent' />
            </div>
          ) : items.length === 0 ? (
            <div className='flex flex-col items-center gap-2 py-12 text-center'>
              <Target className='size-10 text-muted-foreground/30' />
              <p className='text-sm text-muted-foreground'>Sin objetivos definidos.</p>
              <p className='text-xs text-muted-foreground'>Agregá IPs, dominios o URLs al alcance del engagement.</p>
            </div>
          ) : (
            <>
              {inScopeItems.length > 0 && (
                <div>
                  <div className='flex items-center gap-2 mb-2'>
                    <ShieldCheck className='size-3.5 text-green-500' />
                    <p className='text-xs font-semibold text-green-500 uppercase tracking-wide'>In-scope ({inScopeItems.length})</p>
                  </div>
                  <div className='space-y-1.5'>
                    {inScopeItems.map(item => (
                      <ScopeRow key={item.id} item={item} onDelete={() => handleDelete(item.id, item.value)} />
                    ))}
                  </div>
                </div>
              )}

              {outOfScope.length > 0 && (
                <div>
                  <div className='flex items-center gap-2 mb-2'>
                    <ShieldOff className='size-3.5 text-red-500' />
                    <p className='text-xs font-semibold text-red-500 uppercase tracking-wide'>Excluido ({outOfScope.length})</p>
                  </div>
                  <div className='space-y-1.5'>
                    {outOfScope.map(item => (
                      <ScopeRow key={item.id} item={item} onDelete={() => handleDelete(item.id, item.value)} />
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}

function ScopeRow({ item, onDelete }: { item: ScopeItem; onDelete: () => void }) {
  const typeBadge = TYPE_BADGE[item.type] ?? TYPE_BADGE.other
  const isIn = !!item.in_scope

  return (
    <div className={cn(
      'flex items-center gap-2 rounded-md border px-3 py-2 group',
      isIn ? 'border-green-500/10 bg-green-500/5' : 'border-red-500/10 bg-red-500/5'
    )}>
      <Badge variant='outline' className={cn('shrink-0', typeBadge)}>
        {item.type}
      </Badge>
      <span className='font-mono text-xs flex-1 truncate'>{item.value}</span>
      {item.notes && (
        <span className='text-[10px] text-muted-foreground hidden group-hover:block truncate max-w-24'>
          {item.notes}
        </span>
      )}
      <button
        onClick={onDelete}
        className='opacity-0 group-hover:opacity-100 transition-opacity text-muted-foreground hover:text-destructive'
      >
        <Trash2 className='size-3.5' />
      </button>
    </div>
  )
}
