/**
 * Templates de Findings — Biblioteca reutilizable de hallazgos.
 * Permite crear, editar y aplicar plantillas de findings a cualquier engagement.
 * Incluye 15 templates built-in del sistema + templates personalizados.
 */

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Search, Plus, Copy, Pencil, Trash2, BookOpen, Shield,
  ChevronRight, Star, X, Check,
} from 'lucide-react'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Textarea } from '@/components/ui/textarea'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog'
import { cn } from '@/lib/utils'

// ─── Tipos ────────────────────────────────────────────────────────────────────
interface FindingTemplate {
  id: string
  title: string
  category: string | null
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  description: string | null
  steps_to_reproduce: string | null
  recommendation: string | null
  cwe_id: string | null
  cwe_name: string | null
  owasp_category: string | null
  cvss_vector_31: string | null
  cvss_score_31: number | null
  is_builtin: number
  created_at: string
}

// ─── Constantes ───────────────────────────────────────────────────────────────
const SEV_CONFIG: Record<string, { label: string; cls: string; dot: string }> = {
  critical: { label: 'Crítico', cls: 'border-red-500/30 bg-red-500/5 text-red-400',    dot: 'bg-red-500' },
  high:     { label: 'Alto',    cls: 'border-orange-500/30 bg-orange-500/5 text-orange-400', dot: 'bg-orange-500' },
  medium:   { label: 'Medio',   cls: 'border-yellow-500/30 bg-yellow-500/5 text-yellow-400', dot: 'bg-yellow-500' },
  low:      { label: 'Bajo',    cls: 'border-blue-500/30 bg-blue-500/5 text-blue-400',  dot: 'bg-blue-500' },
  info:     { label: 'Info',    cls: 'border-border bg-muted/30 text-muted-foreground', dot: 'bg-muted-foreground' },
}

const CATEGORIES = [
  'Injection', 'XSS', 'SSRF', 'CSRF', 'Authentication', 'Authorization',
  'Broken Access Control', 'Cryptography', 'Configuration', 'Deserialization',
  'File Access', 'Infrastructure', 'Information Disclosure', 'Business Logic', 'Other',
]

const EMPTY_FORM = {
  title: '', category: '', severity: 'medium' as FindingTemplate['severity'],
  description: '', steps_to_reproduce: '', recommendation: '',
  cwe_id: '', cwe_name: '', owasp_category: '', cvss_vector_31: '', cvss_score_31: '',
}

// ─── Componente ───────────────────────────────────────────────────────────────
export function Templates() {
  const qc = useQueryClient()
  const { auth } = useAuthStore()
  const role = auth.user?.role

  const [q, setQ] = useState('')
  const [sevFilter, setSevFilter] = useState('all')
  const [selected, setSelected] = useState<FindingTemplate | null>(null)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<FindingTemplate | null>(null)
  const [form, setForm] = useState({ ...EMPTY_FORM })

  // ── Queries ──────────────────────────────────────────────────────────────────
  const { data: templates = [], isLoading } = useQuery<FindingTemplate[]>({
    queryKey: ['gungnir-templates', q, sevFilter],
    queryFn: () => {
      const params = new URLSearchParams()
      if (q)              params.set('q', q)
      if (sevFilter !== 'all') params.set('severity', sevFilter)
      return apiFetch<FindingTemplate[]>(`/templates/findings?${params}`)
    },
    staleTime: 30_000,
  })

  // ── Mutations ─────────────────────────────────────────────────────────────────
  const saveMutation = useMutation({
    mutationFn: () => {
      const payload = {
        ...form,
        cvss_score_31: form.cvss_score_31 ? Number(form.cvss_score_31) : null,
      }
      if (editing) {
        return apiFetch(`/templates/findings/${editing.id}`, { method: 'PUT', body: JSON.stringify(payload) })
      }
      return apiFetch('/templates/findings', { method: 'POST', body: JSON.stringify(payload) })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['gungnir-templates'] })
      setDialogOpen(false)
      toast.success(editing ? 'Template actualizado' : 'Template creado')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/templates/findings/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['gungnir-templates'] })
      if (selected?.id === deleteMutation.variables) setSelected(null)
      toast.success('Template eliminado')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  // ── Handlers ──────────────────────────────────────────────────────────────────
  function openCreate() {
    setEditing(null)
    setForm({ ...EMPTY_FORM })
    setDialogOpen(true)
  }

  function openEdit(t: FindingTemplate) {
    setEditing(t)
    setForm({
      title: t.title,
      category: t.category || '',
      severity: t.severity,
      description: t.description || '',
      steps_to_reproduce: t.steps_to_reproduce || '',
      recommendation: t.recommendation || '',
      cwe_id: t.cwe_id || '',
      cwe_name: t.cwe_name || '',
      owasp_category: t.owasp_category || '',
      cvss_vector_31: t.cvss_vector_31 || '',
      cvss_score_31: t.cvss_score_31?.toString() || '',
    })
    setDialogOpen(true)
  }

  function copyToClipboard(t: FindingTemplate) {
    const text = [
      `# ${t.title}`,
      t.owasp_category ? `**OWASP:** ${t.owasp_category}` : '',
      t.cwe_id ? `**CWE:** ${t.cwe_id} — ${t.cwe_name || ''}` : '',
      '',
      '## Descripción',
      t.description || '',
      '',
      '## Pasos para reproducir',
      t.steps_to_reproduce || '',
      '',
      '## Recomendación',
      t.recommendation || '',
    ].filter(x => x !== null).join('\n')
    navigator.clipboard.writeText(text).then(() => toast.success('Copiado al portapapeles'))
  }

  const canEdit = (t: FindingTemplate) =>
    role === 'admin' || (!t.is_builtin && (role === 'auditor' || role === 'pentester'))
  const canDelete = (t: FindingTemplate) =>
    role === 'admin' || (!t.is_builtin && (role === 'auditor' || role === 'pentester'))

  return (
    <div className='flex h-[calc(100vh-4rem)] gap-0 -mt-1'>
      {/* ── Left: Lista ──────────────────────────────────────────────────────── */}
      <div className='flex flex-col w-80 shrink-0 border-r border-border'>
        {/* Header */}
        <div className='p-4 border-b border-border'>
          <div className='flex items-center justify-between mb-3'>
            <div>
              <h1 className='text-base font-bold flex items-center gap-2'>
                <BookOpen className='size-4 text-primary' />
                Templates
              </h1>
              <p className='text-xs text-muted-foreground'>{templates.length} plantillas</p>
            </div>
            <Button size='sm' className='h-7 px-2 gap-1 text-xs' onClick={openCreate}>
              <Plus className='size-3' />
              Nuevo
            </Button>
          </div>
          {/* Search */}
          <div className='relative'>
            <Search className='absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground' />
            <Input
              value={q}
              onChange={e => setQ(e.target.value)}
              placeholder='Buscar templates...'
              className='pl-8 h-7 text-xs'
            />
          </div>
          {/* Severity filter */}
          <div className='flex gap-1 mt-2 flex-wrap'>
            {['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => (
              <button
                key={s}
                onClick={() => setSevFilter(s)}
                className={cn(
                  'rounded px-2 py-0.5 text-[10px] font-medium border transition-all',
                  sevFilter === s
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border text-muted-foreground hover:border-primary/40'
                )}
              >
                {s === 'all' ? 'Todos' : SEV_CONFIG[s]?.label}
              </button>
            ))}
          </div>
        </div>

        {/* Lista */}
        <div className='flex-1 overflow-y-auto'>
          {isLoading ? (
            <div className='flex justify-center py-8'>
              <div className='h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent' />
            </div>
          ) : templates.length === 0 ? (
            <div className='flex flex-col items-center gap-2 py-10 text-center text-muted-foreground'>
              <BookOpen className='size-6 opacity-30' />
              <p className='text-xs'>Sin templates</p>
            </div>
          ) : (
            templates.map(t => {
              const sev = SEV_CONFIG[t.severity]
              const isActive = selected?.id === t.id
              return (
                <button
                  key={t.id}
                  onClick={() => setSelected(t)}
                  className={cn(
                    'w-full text-left px-4 py-3 border-b border-border/50 transition-colors hover:bg-accent/50',
                    isActive && 'bg-accent'
                  )}
                >
                  <div className='flex items-start gap-2'>
                    <div className={cn('mt-1.5 h-2 w-2 rounded-full shrink-0', sev?.dot)} />
                    <div className='min-w-0 flex-1'>
                      <p className='text-xs font-medium leading-tight truncate'>{t.title}</p>
                      <div className='flex items-center gap-1.5 mt-0.5'>
                        {t.category && (
                          <span className='text-[10px] text-muted-foreground'>{t.category}</span>
                        )}
                        {!!t.is_builtin && (
                          <span className='text-[10px] text-primary/60 flex items-center gap-0.5'>
                            <Star className='size-2.5' />Built-in
                          </span>
                        )}
                      </div>
                    </div>
                    {isActive && <ChevronRight className='size-3 text-muted-foreground shrink-0 mt-1' />}
                  </div>
                </button>
              )
            })
          )}
        </div>
      </div>

      {/* ── Right: Detalle ───────────────────────────────────────────────────── */}
      <div className='flex-1 overflow-y-auto'>
        {!selected ? (
          <div className='flex flex-col items-center justify-center h-full gap-3 text-center text-muted-foreground'>
            <Shield className='size-12 opacity-20' />
            <p className='text-sm'>Seleccioná un template para ver el detalle</p>
            <p className='text-xs opacity-60'>o creá uno nuevo con el botón "Nuevo"</p>
          </div>
        ) : (
          <div className='p-6 max-w-3xl'>
            {/* Header */}
            <div className='flex items-start justify-between gap-4 mb-6'>
              <div className='min-w-0 flex-1'>
                <div className='flex items-center gap-2 mb-1 flex-wrap'>
                  {(() => { const s = SEV_CONFIG[selected.severity]; return (
                    <span className={cn('inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-bold', s?.cls)}>
                      <span className={cn('h-1.5 w-1.5 rounded-full', s?.dot)} />
                      {s?.label}
                    </span>
                  )})()}
                  {selected.category && (
                    <span className='text-xs text-muted-foreground border border-border rounded px-1.5 py-0.5'>{selected.category}</span>
                  )}
                  {!!selected.is_builtin && (
                    <span className='text-xs text-primary/70 border border-primary/20 rounded px-1.5 py-0.5 flex items-center gap-1'>
                      <Star className='size-2.5' />
                      Built-in
                    </span>
                  )}
                </div>
                <h2 className='text-lg font-bold'>{selected.title}</h2>
              </div>

              {/* Actions */}
              <div className='flex gap-1 shrink-0'>
                <Button variant='outline' size='sm' className='h-7 gap-1.5 text-xs'
                  onClick={() => copyToClipboard(selected)}>
                  <Copy className='size-3' />
                  Copiar
                </Button>
                {canEdit(selected) && (
                  <Button variant='outline' size='sm' className='h-7 gap-1.5 text-xs'
                    onClick={() => openEdit(selected)}>
                    <Pencil className='size-3' />
                    Editar
                  </Button>
                )}
                {canDelete(selected) && (
                  <Button variant='outline' size='sm' className='h-7 gap-1.5 text-xs text-destructive hover:text-destructive'
                    onClick={() => {
                      if (!confirm(`¿Eliminar el template "${selected.title}"?`)) return
                      deleteMutation.mutate(selected.id)
                    }}>
                    <Trash2 className='size-3' />
                  </Button>
                )}
              </div>
            </div>

            {/* Metadata chips */}
            <div className='flex flex-wrap gap-3 mb-6 text-xs text-muted-foreground'>
              {selected.cwe_id && (
                <span className='font-mono bg-muted rounded px-2 py-0.5'>{selected.cwe_id}</span>
              )}
              {selected.cwe_name && (
                <span>{selected.cwe_name}</span>
              )}
              {selected.owasp_category && (
                <span className='text-orange-400/80'>{selected.owasp_category}</span>
              )}
              {selected.cvss_score_31 != null && (
                <span className='font-bold text-foreground'>CVSS {Number(selected.cvss_score_31).toFixed(1)}</span>
              )}
            </div>

            {/* Sections */}
            {[
              { label: 'Descripción', content: selected.description },
              { label: 'Pasos para reproducir', content: selected.steps_to_reproduce },
              { label: 'Recomendación', content: selected.recommendation },
            ].map(({ label, content }) => content ? (
              <div key={label} className='mb-6'>
                <p className='text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2'>{label}</p>
                <div className='rounded-lg border border-border bg-muted/20 p-4'>
                  <pre className='text-sm leading-relaxed whitespace-pre-wrap font-sans text-foreground/90'>{content}</pre>
                </div>
              </div>
            ) : null)}

            {selected.cvss_vector_31 && (
              <div className='mb-6'>
                <p className='text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2'>CVSS Vector</p>
                <code className='text-xs font-mono text-muted-foreground bg-muted rounded px-2 py-1'>
                  {selected.cvss_vector_31}
                </code>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Dialog: Crear / Editar ───────────────────────────────────────────── */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className='max-w-2xl max-h-[90vh] overflow-y-auto'>
          <DialogHeader>
            <DialogTitle>{editing ? `Editar — ${editing.title}` : 'Nuevo template'}</DialogTitle>
          </DialogHeader>

          <div className='space-y-4 py-2'>
            <div className='grid grid-cols-2 gap-4'>
              <div className='col-span-2 space-y-1.5'>
                <Label className='text-xs'>Título *</Label>
                <Input value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
                  placeholder='SQL Injection en /api/login' className='text-sm h-8' />
              </div>
              <div className='space-y-1.5'>
                <Label className='text-xs'>Severidad</Label>
                <Select value={form.severity} onValueChange={v => setForm(f => ({ ...f, severity: v as FindingTemplate['severity'] }))}>
                  <SelectTrigger className='h-8 text-sm'><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {['critical','high','medium','low','info'].map(s => (
                      <SelectItem key={s} value={s}>{SEV_CONFIG[s]?.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className='space-y-1.5'>
                <Label className='text-xs'>Categoría</Label>
                <Select value={form.category} onValueChange={v => setForm(f => ({ ...f, category: v }))}>
                  <SelectTrigger className='h-8 text-sm'><SelectValue placeholder='Seleccionar...' /></SelectTrigger>
                  <SelectContent>
                    {CATEGORIES.map(c => <SelectItem key={c} value={c}>{c}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className='grid grid-cols-2 gap-4'>
              <div className='space-y-1.5'>
                <Label className='text-xs'>CWE ID</Label>
                <Input value={form.cwe_id} onChange={e => setForm(f => ({ ...f, cwe_id: e.target.value }))}
                  placeholder='CWE-89' className='text-sm h-8 font-mono' />
              </div>
              <div className='space-y-1.5'>
                <Label className='text-xs'>OWASP</Label>
                <Input value={form.owasp_category} onChange={e => setForm(f => ({ ...f, owasp_category: e.target.value }))}
                  placeholder='A03:2021 – Injection' className='text-sm h-8' />
              </div>
              <div className='col-span-2 space-y-1.5'>
                <Label className='text-xs'>CWE Nombre</Label>
                <Input value={form.cwe_name} onChange={e => setForm(f => ({ ...f, cwe_name: e.target.value }))}
                  placeholder='Improper Neutralization of Special Elements...' className='text-sm h-8' />
              </div>
              <div className='space-y-1.5'>
                <Label className='text-xs'>CVSS Vector</Label>
                <Input value={form.cvss_vector_31} onChange={e => setForm(f => ({ ...f, cvss_vector_31: e.target.value }))}
                  placeholder='CVSS:3.1/AV:N/AC:L/...' className='text-sm h-8 font-mono' />
              </div>
              <div className='space-y-1.5'>
                <Label className='text-xs'>CVSS Score</Label>
                <Input value={form.cvss_score_31} onChange={e => setForm(f => ({ ...f, cvss_score_31: e.target.value }))}
                  placeholder='9.8' type='number' step='0.1' min='0' max='10' className='text-sm h-8' />
              </div>
            </div>

            <div className='space-y-1.5'>
              <Label className='text-xs'>Descripción</Label>
              <Textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                rows={4} placeholder='Descripción técnica detallada...' className='text-sm' />
            </div>
            <div className='space-y-1.5'>
              <Label className='text-xs'>Pasos para reproducir</Label>
              <Textarea value={form.steps_to_reproduce} onChange={e => setForm(f => ({ ...f, steps_to_reproduce: e.target.value }))}
                rows={4} placeholder={'1. Enviar payload...\n2. Observar respuesta...'} className='text-sm' />
            </div>
            <div className='space-y-1.5'>
              <Label className='text-xs'>Recomendación</Label>
              <Textarea value={form.recommendation} onChange={e => setForm(f => ({ ...f, recommendation: e.target.value }))}
                rows={3} placeholder='Implementar consultas parametrizadas...' className='text-sm' />
            </div>
          </div>

          <DialogFooter>
            <Button variant='outline' size='sm' onClick={() => setDialogOpen(false)}>Cancelar</Button>
            <Button size='sm' onClick={() => saveMutation.mutate()}
              disabled={saveMutation.isPending || !form.title}>
              {saveMutation.isPending ? 'Guardando...' : editing ? 'Guardar cambios' : 'Crear template'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
