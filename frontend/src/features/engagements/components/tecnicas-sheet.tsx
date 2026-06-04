/**
 * TecnicasSheet — Panel de técnicas MITRE ATT&CK asociadas a un engagement.
 * Funciona tanto en workspace pentesting como custom.
 */

import { useState, useEffect, useMemo } from 'react'
import { Search, Plus, Trash2, ExternalLink, Crosshair, ChevronDown, ChevronRight } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Textarea } from '@/components/ui/textarea'
import { cn } from '@/lib/utils'
import { apiFetch } from '@/lib/api'
import { TECHNIQUES, TACTICS_ORDER, TACTIC_PHASE_LABEL, type Technique } from '@/data/techniques'

// ─── Tipos ────────────────────────────────────────────────────────────────────
interface EngTechnique {
  id: string
  mitre_id: string | null
  name: string
  tactic: string | null
  tool: string | null
  notes: string | null
  added_at: string
  added_by_name: string | null
  custom_phase_id: string | null
  phase_type: string | null
}

interface Props {
  open: boolean
  onOpenChange: (v: boolean) => void
  engagementId: string
  /** Para custom engagements: ID de la fase actual (opcional) */
  currentPhaseId?: string
  /** Para pentesting: nombre de la fase actual (opcional) */
  currentPhaseType?: string
}

const PHASE_COLOR: Record<string, string> = {
  recon:             'bg-blue-500/10 text-blue-400 border-blue-500/20',
  scanning:          'bg-purple-500/10 text-purple-400 border-purple-500/20',
  exploitation:      'bg-red-500/10 text-red-400 border-red-500/20',
  post_exploitation: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
}

// ─── Componente principal ─────────────────────────────────────────────────────
export function TecnicasSheet({ open, onOpenChange, engagementId, currentPhaseId, currentPhaseType }: Props) {
  const { t } = useTranslation()
  const [techniques, setTechniques] = useState<EngTechnique[]>([])
  const [loading, setLoading]       = useState(false)
  const [mode, setMode]             = useState<'list' | 'catalog' | 'custom'>('list')
  const [search, setSearch]         = useState('')
  const [expandedTactic, setExpandedTactic] = useState<string | null>('Reconnaissance')

  // Form estado para técnica custom
  const [customName, setCustomName] = useState('')
  const [customTool, setCustomTool] = useState('')
  const [customNotes, setCustomNotes] = useState('')
  const [saving, setSaving] = useState(false)

  const load = () => {
    setLoading(true)
    apiFetch<EngTechnique[]>(`/engagements/${engagementId}/techniques`)
      .then(setTechniques).catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => { if (open) { load(); setMode('list') } }, [open, engagementId])

  // ── Catálogo filtrado ────────────────────────────────────────────────────────
  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    if (!q) return TECHNIQUES
    return TECHNIQUES.filter(tech =>
      tech.id.toLowerCase().includes(q) ||
      tech.name.toLowerCase().includes(q) ||
      tech.tactic.toLowerCase().includes(q) ||
      tech.tools.some(tool => tool.toLowerCase().includes(q))
    )
  }, [search])

  const byTactic = useMemo(() =>
    TACTICS_ORDER
      .map(tactic => ({ tactic, items: filtered.filter(tech => tech.tactic === tactic) }))
      .filter(g => g.items.length > 0),
    [filtered]
  )

  // ── Agregar desde catálogo ───────────────────────────────────────────────────
  const addFromCatalog = async (tech: Technique) => {
    setSaving(true)
    try {
      await apiFetch(`/engagements/${engagementId}/techniques`, {
        method: 'POST',
        body: {
          mitre_id: tech.id,
          name: tech.name,
          tactic: tech.tactic,
          tool: tech.tools[0] ?? null,
          custom_phase_id: currentPhaseId ?? null,
          phase_type: currentPhaseType ?? null,
        },
      })
      toast.success(t('techniques.added'))
      load()
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : t('common.error'))
    } finally { setSaving(false) }
  }

  // ── Agregar técnica custom ───────────────────────────────────────────────────
  const addCustom = async () => {
    if (!customName.trim()) { toast.error(t('techniques.label_name') + ' requerido'); return }
    setSaving(true)
    try {
      await apiFetch(`/engagements/${engagementId}/techniques`, {
        method: 'POST',
        body: {
          name: customName.trim(),
          tool: customTool.trim() || null,
          notes: customNotes.trim() || null,
          custom_phase_id: currentPhaseId ?? null,
          phase_type: currentPhaseType ?? null,
        },
      })
      toast.success(t('techniques.added'))
      setCustomName(''); setCustomTool(''); setCustomNotes('')
      load()
      setMode('list')
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : t('common.error'))
    } finally { setSaving(false) }
  }

  // ── Eliminar ─────────────────────────────────────────────────────────────────
  const remove = async (techId: string) => {
    try {
      await apiFetch(`/engagements/${engagementId}/techniques/${techId}`, { method: 'DELETE' })
      setTechniques(prev => prev.filter(item => item.id !== techId))
      toast.success(t('techniques.removed'))
    } catch { toast.error(t('common.error')) }
  }

  // ─── Render ───────────────────────────────────────────────────────────────────
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side='right' className='w-full sm:max-w-xl flex flex-col p-0 gap-0' hideCloseButton>
        {/* Header */}
        <SheetHeader className='p-4 border-b border-border flex-row items-center justify-between space-y-0'>
          <SheetTitle className='text-sm font-semibold flex items-center gap-2'>
            <Crosshair className='size-4 text-primary' />
            {t('techniques.title')}
          </SheetTitle>
          <Button variant='ghost' size='icon' className='size-7' onClick={() => onOpenChange(false)}>
            ✕
          </Button>
        </SheetHeader>

        {/* Tabs */}
        <div className='flex border-b border-border'>
          {(['list', 'catalog', 'custom'] as const).map(m => (
            <button key={m} onClick={() => setMode(m)}
              className={cn(
                'flex-1 px-3 py-2 text-xs font-medium transition-colors',
                mode === m ? 'border-b-2 border-primary text-foreground' : 'text-muted-foreground hover:text-foreground'
              )}>
              {m === 'list'
                ? `${t('techniques.tab_current')} (${techniques.length})`
                : m === 'catalog'
                  ? t('techniques.tab_catalog')
                  : t('techniques.tab_custom')}
            </button>
          ))}
        </div>

        <div className='flex-1 overflow-y-auto'>

          {/* ── Tab: Lista actual ─────────────────────────────────────────────── */}
          {mode === 'list' && (
            <div className='p-3 space-y-2'>
              {loading && (
                <div className='flex justify-center py-8'>
                  <div className='h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent' />
                </div>
              )}
              {!loading && techniques.length === 0 && (
                <div className='flex flex-col items-center gap-3 py-12 text-center'>
                  <Crosshair className='size-10 text-muted-foreground/20' />
                  <p className='text-sm text-muted-foreground'>{t('techniques.no_techniques')}</p>
                  <p className='text-xs text-muted-foreground'>{t('techniques.custom_add')}</p>
                </div>
              )}
              {techniques.map(item => (
                <div key={item.id} className='group flex items-start gap-3 rounded-lg border border-border bg-card p-3'>
                  <div className='flex-1 min-w-0'>
                    <div className='flex items-center gap-2 flex-wrap'>
                      {item.mitre_id && (
                        <span className='font-mono text-[10px] font-bold text-primary bg-primary/10 px-1.5 py-0.5 rounded border border-primary/20'>
                          {item.mitre_id}
                        </span>
                      )}
                      <span className='text-xs font-semibold truncate'>{item.name}</span>
                    </div>
                    {item.tactic && (
                      <p className='text-[10px] text-muted-foreground mt-0.5'>{item.tactic}</p>
                    )}
                    {item.tool && (
                      <code className='text-[10px] font-mono text-muted-foreground mt-1 block'>{item.tool}</code>
                    )}
                    {item.notes && (
                      <p className='text-xs text-muted-foreground mt-1 leading-relaxed'>{item.notes}</p>
                    )}
                  </div>
                  <div className='flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity shrink-0'>
                    {item.mitre_id && (
                      <a href={`https://attack.mitre.org/techniques/${item.mitre_id}/`}
                        target='_blank' rel='noreferrer'
                        className='p-1 rounded hover:bg-accent transition-colors text-muted-foreground hover:text-foreground'>
                        <ExternalLink className='size-3' />
                      </a>
                    )}
                    <button onClick={() => remove(item.id)}
                      className='p-1 rounded hover:bg-destructive/10 transition-colors text-muted-foreground hover:text-destructive'>
                      <Trash2 className='size-3' />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ── Tab: Catálogo MITRE ───────────────────────────────────────────── */}
          {mode === 'catalog' && (
            <div className='flex flex-col h-full'>
              <div className='p-3 border-b border-border'>
                <div className='relative'>
                  <Search className='absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground' />
                  <Input value={search} onChange={e => setSearch(e.target.value)}
                    placeholder={t('techniques.search_placeholder')} className='pl-8 h-8 text-xs' />
                </div>
              </div>
              <div className='flex-1 overflow-y-auto py-1'>
                {byTactic.map(({ tactic, items }) => (
                  <div key={tactic}>
                    <button
                      onClick={() => setExpandedTactic(expandedTactic === tactic ? null : tactic)}
                      className='w-full flex items-center justify-between px-3 py-2 hover:bg-accent/50 transition-colors'>
                      <div className='flex items-center gap-2'>
                        {expandedTactic === tactic
                          ? <ChevronDown className='size-3 text-muted-foreground' />
                          : <ChevronRight className='size-3 text-muted-foreground' />}
                        <span className='text-xs font-semibold text-muted-foreground uppercase tracking-wide'>{tactic}</span>
                      </div>
                      <span className='text-[10px] text-muted-foreground'>{items.length}</span>
                    </button>

                    {expandedTactic === tactic && items.map(tech => {
                      const already = techniques.some(item => item.mitre_id === tech.id)
                      return (
                        <div key={tech.id}
                          className='mx-3 mb-1 flex items-start justify-between gap-2 rounded border border-border bg-card px-3 py-2'>
                          <div className='flex-1 min-w-0'>
                            <div className='flex items-center gap-2'>
                              <span className='font-mono text-[10px] font-bold text-primary shrink-0'>{tech.id}</span>
                              <span className='text-xs truncate'>{tech.name}</span>
                            </div>
                            {tech.phase && (
                              <Badge variant='outline' className={cn('mt-0.5 text-[10px] px-1 py-0 h-4 border', PHASE_COLOR[tech.phase])}>
                                {TACTIC_PHASE_LABEL[tech.phase] ?? tech.phase}
                              </Badge>
                            )}
                            <p className='text-[10px] text-muted-foreground mt-1 leading-relaxed line-clamp-2'>{tech.description}</p>
                          </div>
                          <Button
                            size='icon'
                            variant={already ? 'secondary' : 'outline'}
                            className='size-6 shrink-0'
                            disabled={already || saving}
                            onClick={() => addFromCatalog(tech)}
                            title={already ? t('techniques.added') : t('techniques.add')}
                          >
                            {already ? '✓' : <Plus className='size-3' />}
                          </Button>
                        </div>
                      )
                    })}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── Tab: Técnica manual ───────────────────────────────────────────── */}
          {mode === 'custom' && (
            <div className='p-4 space-y-4'>
              <p className='text-xs text-muted-foreground'>
                {t('techniques.custom_add')}
              </p>
              <div className='space-y-3'>
                <div className='space-y-1'>
                  <label className='text-xs font-medium'>{t('techniques.label_name')} <span className='text-destructive'>*</span></label>
                  <Input value={customName} onChange={e => setCustomName(e.target.value)}
                    placeholder='Ej: OWASP WSTG — Authentication Testing, ZAP Spider...' className='text-xs h-8' />
                </div>
                <div className='space-y-1'>
                  <label className='text-xs font-medium'>{t('techniques.label_tool')}</label>
                  <Input value={customTool} onChange={e => setCustomTool(e.target.value)}
                    placeholder='Ej: OWASP ZAP, Burp Suite, manual...' className='text-xs h-8 font-mono' />
                </div>
                <div className='space-y-1'>
                  <label className='text-xs font-medium'>{t('techniques.label_notes')}</label>
                  <Textarea value={customNotes} onChange={e => setCustomNotes(e.target.value)}
                    placeholder='Descripción, variantes, contexto...' rows={3} className='text-xs resize-none' />
                </div>
                <Button onClick={addCustom} disabled={saving || !customName.trim()} className='w-full' size='sm'>
                  {saving ? t('common.loading') : t('techniques.add')}
                </Button>
              </div>
            </div>
          )}

        </div>
      </SheetContent>
    </Sheet>
  )
}
