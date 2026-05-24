/**
 * Custom Workspace — Para engagements de modo 'custom'
 * Fases editables, documentos adjuntos, plan de trabajo,
 * actualizaciones con bloques de texto + código + imágenes.
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { toast } from 'sonner'
import {
  Plus, ArrowLeft, Loader2,
  FileText, Upload, Trash2, Download, CheckCircle2,
  Clock, Circle, Pencil, Check, X, MessageSquare,
  FolderOpen, ListChecks, Send, Type, Code2, Image,
  Copy, ChevronDown, Crosshair,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { apiFetch } from '@/lib/api'
import { TecnicasSheet } from './tecnicas-sheet'

// ─── Tipos ────────────────────────────────────────────────────────────────────
interface Engagement {
  id: string; title: string; codename?: string; client_name: string
  status: string; type: string; mode: string; methodology: string
  start_date?: string; end_date?: string; notes?: string
}
interface CustomPhase {
  id: string; engagement_id: string; name: string; description?: string
  work_plan?: string; status: 'not_started' | 'in_progress' | 'completed'
  order_index: number; docs_count?: number; updates_count?: number
  created_at: string
}
interface PhaseDoc {
  id: string; phase_id: string; original_name: string; file_type: string
  file_size: number; caption?: string; uploader_name?: string; uploaded_at: string
}
interface UpdateImage {
  id: string; update_id: string; filename: string; original_name: string; file_size: number
}
interface PhaseUpdate {
  id: string; phase_id: string; content: string
  images?: UpdateImage[]
  author_name?: string; created_at: string
}

// ─── Block editor types ───────────────────────────────────────────────────────
export type BlockLang = 'bash' | 'python' | 'sql' | 'javascript' | 'output' | 'other'
export interface Block {
  id: string
  type: 'text' | 'code'
  content: string
  language?: BlockLang
}

function mkId() { return Math.random().toString(36).slice(2, 10) }
function mkTextBlock(): Block { return { id: mkId(), type: 'text', content: '' } }
function mkCodeBlock(lang: BlockLang = 'bash'): Block { return { id: mkId(), type: 'code', content: '', language: lang } }

/** Parsea el contenido de una actualización: puede ser JSON de bloques o texto plano */
function parseContent(raw: string): Block[] {
  try {
    const parsed = JSON.parse(raw)
    if (Array.isArray(parsed) && parsed.length > 0 && parsed[0].type) return parsed as Block[]
  } catch {}
  return [{ id: mkId(), type: 'text', content: raw }]
}

// ─── Constantes ───────────────────────────────────────────────────────────────
const STATUS_CFG: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
  not_started: { label: 'Pendiente',  color: 'text-zinc-500',  icon: <Circle className='h-3.5 w-3.5' /> },
  in_progress: { label: 'En curso',   color: 'text-blue-400',  icon: <Clock className='h-3.5 w-3.5' /> },
  completed:   { label: 'Completada', color: 'text-green-400', icon: <CheckCircle2 className='h-3.5 w-3.5' /> },
}

const TYPE_LABELS: Record<string, string> = {
  app_security:'App Security', code_review:'Code Review', arch_review:'Architecture Review',
  security_audit:'Auditoría', compliance:'Compliance', gap_analysis:'Gap Analysis',
  risk_analysis:'Análisis de Riesgo', preliminary:'Análisis Preliminar',
  situation:'Situación Actual', incident_response:'Incident Response',
  consulting:'Consultoría', training:'Capacitación',
  external_pt:'Pentesting Externo', internal_pt:'Pentesting Interno',
  web_app:'Web App PT', api:'API PT', mobile:'Mobile PT', red_team:'Red Team',
  social_eng:'Ingeniería Social', physical:'Físico',
}

const LANG_LABEL: Record<BlockLang, string> = {
  bash:'bash', python:'python', sql:'sql', javascript:'javascript', output:'output', other:'code',
}

const LANG_COLOR: Record<BlockLang, string> = {
  bash: 'text-green-400', python: 'text-yellow-400', sql: 'text-blue-400',
  javascript: 'text-orange-400', output: 'text-zinc-400', other: 'text-violet-400',
}

function fmtSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024*1024) return `${(bytes/1024).toFixed(0)} KB`
  return `${(bytes/1024/1024).toFixed(1)} MB`
}

// ─── DropZone ─────────────────────────────────────────────────────────────────
function DropZone({ onFile }: { onFile: (f: File) => void }) {
  const [drag, setDrag] = useState(false)
  const ref = useRef<HTMLInputElement>(null)
  return (
    <div
      onClick={() => ref.current?.click()}
      onDragOver={e => { e.preventDefault(); setDrag(true) }}
      onDragLeave={() => setDrag(false)}
      onDrop={e => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files[0]; if (f) onFile(f) }}
      className={cn(
        'flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed p-6 cursor-pointer transition-colors',
        drag ? 'border-blue-500/60 bg-blue-950/20' : 'border-zinc-700 hover:border-zinc-600'
      )}
    >
      <Upload className='h-6 w-6 text-zinc-600' />
      <p className='text-xs text-zinc-500'>Arrastrá un archivo o hacé click</p>
      <p className='text-[10px] text-zinc-700'>PDF, DOCX, XLSX, imágenes · máx 100 MB</p>
      <input ref={ref} type='file' className='hidden' onChange={e => { const f = e.target.files?.[0]; if (f) onFile(f) }} />
    </div>
  )
}

// ─── Block editor ─────────────────────────────────────────────────────────────
function BlockEditor({
  blocks, onChange,
}: {
  blocks: Block[]
  onChange: (blocks: Block[]) => void
}) {
  const [langMenu, setLangMenu] = useState<string | null>(null)

  const update = (id: string, patch: Partial<Block>) =>
    onChange(blocks.map(b => b.id === id ? { ...b, ...patch } : b))
  const remove = (id: string) => onChange(blocks.filter(b => b.id !== id))
  const add = (block: Block) => onChange([...blocks, block])

  const LANGS: BlockLang[] = ['bash', 'python', 'sql', 'javascript', 'output', 'other']

  return (
    <div className='space-y-2'>
      {blocks.map((block, idx) => (
        <div key={block.id} className='group relative rounded-lg border border-zinc-800 overflow-hidden'>
          {/* Block header */}
          <div className='flex items-center justify-between px-3 py-1.5 bg-zinc-900 border-b border-zinc-800'>
            <div className='flex items-center gap-2'>
              {block.type === 'text' ? (
                <span className='flex items-center gap-1 text-[10px] text-zinc-500 font-medium'>
                  <Type className='h-3 w-3' /> Texto
                </span>
              ) : (
                <div className='relative'>
                  <button
                    onClick={() => setLangMenu(langMenu === block.id ? null : block.id)}
                    className={cn('flex items-center gap-1 text-[10px] font-mono font-bold', LANG_COLOR[block.language ?? 'bash'])}
                  >
                    <Code2 className='h-3 w-3' />
                    {LANG_LABEL[block.language ?? 'bash']}
                    <ChevronDown className='h-2.5 w-2.5' />
                  </button>
                  {langMenu === block.id && (
                    <div className='absolute z-50 top-full left-0 mt-1 rounded-md border border-zinc-700 bg-zinc-900 shadow-lg py-1'>
                      {LANGS.map(l => (
                        <button key={l} onClick={() => { update(block.id, { language: l }); setLangMenu(null) }}
                          className={cn('w-full text-left px-3 py-1 text-xs font-mono hover:bg-zinc-800', LANG_COLOR[l])}>
                          {l}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
            <div className='flex items-center gap-1'>
              {block.type === 'code' && (
                <button
                  onClick={() => { navigator.clipboard.writeText(block.content); toast.success('Copiado') }}
                  className='rounded p-1 text-zinc-600 hover:text-zinc-300 hover:bg-zinc-800 transition'
                  title='Copiar'
                >
                  <Copy className='h-3 w-3' />
                </button>
              )}
              <button onClick={() => remove(block.id)}
                className='rounded p-1 text-zinc-700 hover:text-red-400 hover:bg-red-950/30 transition'>
                <X className='h-3 w-3' />
              </button>
            </div>
          </div>

          {/* Block content */}
          {block.type === 'text' ? (
            <Textarea
              value={block.content}
              onChange={e => update(block.id, { content: e.target.value })}
              placeholder='Escribí tu texto acá...'
              rows={3}
              className='border-0 rounded-none bg-zinc-950/40 text-zinc-200 text-xs resize-y font-sans focus-visible:ring-0'
            />
          ) : (
            <Textarea
              value={block.content}
              onChange={e => update(block.id, { content: e.target.value })}
              placeholder={block.language === 'output' ? 'Pegá la salida del comando...' : '# Escribí el comando o código...'}
              rows={4}
              className='border-0 rounded-none bg-black/60 text-green-300 text-xs resize-y font-mono focus-visible:ring-0'
            />
          )}
        </div>
      ))}

      {/* Add block */}
      <div className='flex items-center gap-2 flex-wrap'>
        <button onClick={() => add(mkTextBlock())}
          className='flex items-center gap-1.5 rounded-md border border-dashed border-zinc-700 px-3 py-1.5 text-xs text-zinc-500 hover:border-zinc-500 hover:text-zinc-300 transition-colors'>
          <Type className='h-3 w-3' /> Texto
        </button>
        {(['bash','python','sql','javascript','output','other'] as BlockLang[]).map(lang => (
          <button key={lang} onClick={() => add(mkCodeBlock(lang))}
            className={cn('flex items-center gap-1.5 rounded-md border border-dashed border-zinc-700 px-3 py-1.5 text-xs hover:border-zinc-500 transition-colors', LANG_COLOR[lang])}>
            <Code2 className='h-3 w-3' /> {lang}
          </button>
        ))}
      </div>
    </div>
  )
}

// ─── Block viewer ─────────────────────────────────────────────────────────────
function BlockViewer({ blocks }: { blocks: Block[] }) {
  return (
    <div className='space-y-2'>
      {blocks.map(block => (
        <div key={block.id}>
          {block.type === 'text' ? (
            <p className='text-xs text-zinc-300 whitespace-pre-wrap leading-relaxed'>{block.content}</p>
          ) : (
            <div className='relative rounded-lg border border-zinc-800 overflow-hidden'>
              <div className='flex items-center justify-between px-3 py-1 bg-zinc-900 border-b border-zinc-800'>
                <span className={cn('text-[10px] font-mono font-bold', LANG_COLOR[block.language ?? 'bash'])}>
                  {LANG_LABEL[block.language ?? 'bash']}
                </span>
                <button
                  onClick={() => { navigator.clipboard.writeText(block.content); toast.success('Copiado') }}
                  className='flex items-center gap-1 text-[10px] text-zinc-600 hover:text-zinc-300 transition'>
                  <Copy className='h-2.5 w-2.5' /> copiar
                </button>
              </div>
              <pre className='bg-black/60 text-green-300 text-xs font-mono px-4 py-3 overflow-x-auto whitespace-pre-wrap break-words'>
                {block.content}
              </pre>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// ─── Phase detail ─────────────────────────────────────────────────────────────
type Tab = 'plan' | 'docs' | 'updates'

function PhaseDetail({
  phase, engagementId, onPhaseChange,
}: {
  phase: CustomPhase
  engagementId: string
  onPhaseChange: () => void
}) {
  const [tab, setTab]           = useState<Tab>('plan')
  const [docs, setDocs]         = useState<PhaseDoc[]>([])
  const [updates, setUpdates]   = useState<PhaseUpdate[]>([])
  const [loadingDocs, setLDocs] = useState(false)
  const [loadingUpd, setLUpd]   = useState(false)

  // Work plan
  const [plan, setPlan]           = useState(phase.work_plan || '')
  const [planDirty, setPlanDirty] = useState(false)
  const [savingPlan, setSavingPlan] = useState(false)

  // Documento upload
  const [uploading, setUploading]   = useState(false)
  const [pendingFile, setPendingFile] = useState<File | null>(null)
  const [fileCaption, setFileCaption] = useState('')

  // Blocks editor state
  const [blocks, setBlocks]         = useState<Block[]>([mkTextBlock()])
  const [pendingImages, setPendingImages] = useState<File[]>([])
  const [imagePreviews, setImagePreviews] = useState<string[]>([])
  const [savingUpd, setSavingUpd]   = useState(false)

  // Status
  const [savingStatus, setSavingStatus] = useState(false)

  const base = `/engagements/${engagementId}/custom-phases/${phase.id}`

  useEffect(() => {
    setPlan(phase.work_plan || '')
    setPlanDirty(false)
  }, [phase.id, phase.work_plan])

  useEffect(() => {
    if (tab === 'docs') loadDocs()
    if (tab === 'updates') loadUpdates()
  }, [tab, phase.id])

  useEffect(() => { loadDocs(); loadUpdates() }, [phase.id])

  function loadDocs() {
    setLDocs(true)
    apiFetch<PhaseDoc[]>(`${base}/documents`)
      .then(d => setDocs(d)).catch(() => {})
      .finally(() => setLDocs(false))
  }
  function loadUpdates() {
    setLUpd(true)
    apiFetch<PhaseUpdate[]>(`${base}/updates`)
      .then(d => setUpdates(d as PhaseUpdate[])).catch(() => {})
      .finally(() => setLUpd(false))
  }

  async function savePlan() {
    setSavingPlan(true)
    try {
      await apiFetch(`${base}`, { method: 'PUT', body: { work_plan: plan } })
      setPlanDirty(false); onPhaseChange(); toast.success('Plan guardado')
    } catch { toast.error('Error al guardar') } finally { setSavingPlan(false) }
  }

  async function changeStatus(status: string) {
    setSavingStatus(true)
    try {
      await apiFetch(`${base}`, { method: 'PUT', body: { status } })
      onPhaseChange()
    } catch { toast.error('Error') } finally { setSavingStatus(false) }
  }

  async function uploadDoc() {
    if (!pendingFile) return
    setUploading(true)
    try {
      const fd = new FormData()
      fd.append('file', pendingFile)
      if (fileCaption) fd.append('caption', fileCaption)
      const token = localStorage.getItem('gungnir_token')
      const res = await fetch(`/api${base}/documents`, {
        method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: fd,
      })
      if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(b.error || 'Error al subir') }
      setPendingFile(null); setFileCaption('')
      loadDocs(); onPhaseChange(); toast.success('Documento subido')
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : 'Error al subir') }
    finally { setUploading(false) }
  }

  async function deleteDoc(docId: string) {
    try {
      await apiFetch(`${base}/documents/${docId}`, { method: 'DELETE' })
      setDocs(prev => prev.filter(d => d.id !== docId))
      onPhaseChange(); toast.success('Documento eliminado')
    } catch { toast.error('Error al eliminar') }
  }

  function downloadDoc(docId: string) {
    const token = localStorage.getItem('gungnir_token')
    fetch(`/api${base}/documents/${docId}/download`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.blob())
      .then(b => {
        const burl = URL.createObjectURL(b)
        const link = document.createElement('a')
        const doc = docs.find(d => d.id === docId)
        link.href = burl; link.download = doc?.original_name || 'documento'
        link.click(); URL.revokeObjectURL(burl)
      }).catch(() => toast.error('Error al descargar'))
  }

  // ── Imagen desde clipboard ─────────────────────────────────────────────────
  const handlePaste = useCallback((e: ClipboardEvent) => {
    if (tab !== 'updates') return
    const items = e.clipboardData?.items
    if (!items) return
    for (const item of Array.from(items)) {
      if (item.type.startsWith('image/')) {
        const file = item.getAsFile()
        if (!file) continue
        const named = new File([file], `paste-${Date.now()}.png`, { type: file.type })
        setPendingImages(prev => [...prev, named])
        const url = URL.createObjectURL(named)
        setImagePreviews(prev => [...prev, url])
        e.preventDefault()
      }
    }
  }, [tab])

  useEffect(() => {
    document.addEventListener('paste', handlePaste)
    return () => document.removeEventListener('paste', handlePaste)
  }, [handlePaste])

  function addImageFile(file: File) {
    setPendingImages(prev => [...prev, file])
    const url = URL.createObjectURL(file)
    setImagePreviews(prev => [...prev, url])
  }

  function removeImage(idx: number) {
    URL.revokeObjectURL(imagePreviews[idx])
    setPendingImages(prev => prev.filter((_, i) => i !== idx))
    setImagePreviews(prev => prev.filter((_, i) => i !== idx))
  }

  // ── Submit update con bloques e imágenes ───────────────────────────────────
  async function addUpdate() {
    const hasContent = blocks.some(b => b.content.trim())
    if (!hasContent && pendingImages.length === 0) {
      toast.error('Escribí algo o adjuntá una imagen'); return
    }
    setSavingUpd(true)
    try {
      const content = JSON.stringify(blocks.filter(b => b.content.trim() || b.type === 'code'))
      const upd = await apiFetch<PhaseUpdate>(`${base}/updates`, {
        method: 'POST', body: { content: content || JSON.stringify([mkTextBlock()]) },
      })
      // Upload images
      const token = localStorage.getItem('gungnir_token')
      const imageUrl = `/api${base}/updates/${upd.id}/images`
      for (const img of pendingImages) {
        const fd = new FormData(); fd.append('file', img)
        await fetch(imageUrl, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: fd })
      }
      // Reload to get images attached
      const fresh = await apiFetch<PhaseUpdate>(`${base}/updates`)
      // Reload all updates
      loadUpdates()
      setBlocks([mkTextBlock()])
      pendingImages.forEach((_, i) => URL.revokeObjectURL(imagePreviews[i]))
      setPendingImages([]); setImagePreviews([])
      onPhaseChange()
    } catch { toast.error('Error al guardar') } finally { setSavingUpd(false) }
  }

  async function deleteUpdate(uid: string) {
    try {
      await apiFetch(`${base}/updates/${uid}`, { method: 'DELETE' })
      setUpdates(prev => prev.filter(u => u.id !== uid))
      onPhaseChange()
    } catch { toast.error('Error') }
  }

  async function deleteUpdateImage(updateId: string, imageId: string) {
    try {
      await apiFetch(`${base}/updates/${updateId}/images/${imageId}`, { method: 'DELETE' })
      setUpdates(prev => prev.map(u => u.id === updateId
        ? { ...u, images: (u.images ?? []).filter(i => i.id !== imageId) }
        : u
      ))
    } catch { toast.error('Error') }
  }

  const TABS: { id: Tab; label: string; icon: React.ReactNode; count?: number }[] = [
    { id: 'plan',    label: 'Plan',          icon: <ListChecks className='h-3.5 w-3.5' /> },
    { id: 'docs',    label: 'Documentos',    icon: <FolderOpen className='h-3.5 w-3.5' />, count: docs.length },
    { id: 'updates', label: 'Registro',      icon: <MessageSquare className='h-3.5 w-3.5' />, count: updates.length },
  ]

  return (
    <div className='flex flex-col h-full'>
      {/* Phase header */}
      <div className='border-b border-border px-6 py-4 space-y-3'>
        <div className='flex items-center justify-between gap-3'>
          <h2 className='text-base font-semibold text-zinc-100 truncate'>{phase.name}</h2>
          <div className='flex items-center gap-1 shrink-0'>
            {Object.entries(STATUS_CFG).map(([s, cfg]) => (
              <button key={s} onClick={() => phase.status !== s && changeStatus(s)} disabled={savingStatus}
                className={cn(
                  'flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium transition-all border',
                  phase.status === s
                    ? `${cfg.color} border-current bg-current/10`
                    : 'text-zinc-600 border-transparent hover:border-zinc-700 hover:text-zinc-400'
                )}>
                {cfg.icon}
                <span className='hidden sm:inline'>{cfg.label}</span>
              </button>
            ))}
          </div>
        </div>
        {phase.description && (
          <p className='text-xs text-zinc-500 leading-relaxed'>{phase.description}</p>
        )}
      </div>

      {/* Tabs */}
      <div className='flex border-b border-border px-6'>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={cn(
              'flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium border-b-2 transition-colors -mb-px',
              tab === t.id ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
            )}>
            {t.icon}{t.label}
            {t.count != null && t.count > 0 && (
              <span className='ml-1 rounded-full bg-zinc-800 px-1.5 py-0.5 text-[10px]'>{t.count}</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className='flex-1 overflow-y-auto p-6'>

        {/* ── Plan de trabajo ──────────────────────────────────────────────── */}
        {tab === 'plan' && (
          <div className='space-y-3'>
            <p className='text-xs text-zinc-500'>
              Documentá el plan de trabajo, objetivos, criterios de aceptación y cualquier información relevante para esta etapa.
            </p>
            <Textarea
              value={plan}
              onChange={e => { setPlan(e.target.value); setPlanDirty(true) }}
              rows={12}
              placeholder={`Objetivos de esta etapa:\n- ...\n\nActividades planificadas:\n1. ...\n\nCriterios de aceptación:\n- ...`}
              className='bg-zinc-900/60 border-zinc-800 text-zinc-200 text-xs resize-y font-mono'
            />
            <div className='flex items-center gap-3'>
              <Button size='sm' onClick={savePlan} disabled={savingPlan || !planDirty} className='gap-1.5'>
                {savingPlan ? <Loader2 className='h-3.5 w-3.5 animate-spin' /> : <Check className='h-3.5 w-3.5' />}
                {savingPlan ? 'Guardando...' : 'Guardar plan'}
              </Button>
              {planDirty && <span className='text-xs text-yellow-500'>Cambios sin guardar</span>}
            </div>
          </div>
        )}

        {/* ── Documentos ───────────────────────────────────────────────────── */}
        {tab === 'docs' && (
          <div className='space-y-4'>
            {!pendingFile ? (
              <DropZone onFile={setPendingFile} />
            ) : (
              <div className='rounded-lg border border-zinc-700 bg-zinc-900/50 p-4 space-y-3'>
                <div className='flex items-center gap-3'>
                  <FileText className='h-8 w-8 text-zinc-500 shrink-0' />
                  <div className='flex-1 min-w-0'>
                    <p className='text-sm font-medium text-zinc-200 truncate'>{pendingFile.name}</p>
                    <p className='text-xs text-zinc-500'>{fmtSize(pendingFile.size)}</p>
                  </div>
                  <button onClick={() => setPendingFile(null)} className='text-zinc-600 hover:text-zinc-300'>
                    <X className='h-4 w-4' />
                  </button>
                </div>
                <Input value={fileCaption} onChange={e => setFileCaption(e.target.value)}
                  placeholder='Descripción del documento (opcional)' className='bg-zinc-900 border-zinc-700 text-xs h-8' />
                <div className='flex gap-2'>
                  <Button size='sm' onClick={uploadDoc} disabled={uploading} className='gap-1.5'>
                    {uploading ? <Loader2 className='h-3.5 w-3.5 animate-spin' /> : <Upload className='h-3.5 w-3.5' />}
                    {uploading ? 'Subiendo...' : 'Subir documento'}
                  </Button>
                  <Button size='sm' variant='ghost' onClick={() => setPendingFile(null)}>Cancelar</Button>
                </div>
              </div>
            )}

            {loadingDocs ? (
              <div className='flex justify-center py-6'><Loader2 className='h-5 w-5 animate-spin text-zinc-600' /></div>
            ) : docs.length === 0 ? (
              <div className='flex flex-col items-center gap-2 py-8 text-center'>
                <FolderOpen className='h-8 w-8 text-zinc-700' />
                <p className='text-xs text-zinc-600'>Sin documentos adjuntos</p>
              </div>
            ) : (
              <div className='space-y-2'>
                {docs.map(doc => (
                  <div key={doc.id} className='flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900/30 px-4 py-3'>
                    <FileText className='h-5 w-5 text-zinc-500 shrink-0' />
                    <div className='flex-1 min-w-0'>
                      <p className='text-xs font-medium text-zinc-200 truncate'>{doc.original_name}</p>
                      <div className='flex items-center gap-2 mt-0.5'>
                        <span className='text-[10px] text-zinc-600'>{fmtSize(doc.file_size)}</span>
                        {doc.caption && <span className='text-[10px] text-zinc-500 truncate'>· {doc.caption}</span>}
                      </div>
                    </div>
                    <div className='flex items-center gap-1 shrink-0'>
                      <button onClick={() => downloadDoc(doc.id)}
                        className='rounded p-1.5 text-zinc-600 hover:text-zinc-300 hover:bg-zinc-800 transition' title='Descargar'>
                        <Download className='h-3.5 w-3.5' />
                      </button>
                      <button onClick={() => deleteDoc(doc.id)}
                        className='rounded p-1.5 text-zinc-700 hover:text-red-400 hover:bg-red-950/30 transition' title='Eliminar'>
                        <Trash2 className='h-3.5 w-3.5' />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── Registro / Actualizaciones ────────────────────────────────────── */}
        {tab === 'updates' && (
          <div className='space-y-5'>
            {/* Block editor */}
            <div className='rounded-lg border border-zinc-800 bg-zinc-950/40 p-4 space-y-3'>
              <p className='text-[10px] text-zinc-600 uppercase tracking-widest font-semibold'>Nueva entrada</p>

              <BlockEditor blocks={blocks} onChange={setBlocks} />

              {/* Imágenes pendientes */}
              {pendingImages.length > 0 && (
                <div className='flex flex-wrap gap-2'>
                  {imagePreviews.map((src, i) => (
                    <div key={i} className='relative group rounded overflow-hidden border border-zinc-700'>
                      <img src={src} alt='preview' className='h-20 w-auto max-w-[160px] object-cover' />
                      <button onClick={() => removeImage(i)}
                        className='absolute top-1 right-1 rounded-full bg-black/70 p-0.5 text-zinc-300 hover:text-red-400 opacity-0 group-hover:opacity-100 transition'>
                        <X className='h-3 w-3' />
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* Image picker + submit */}
              <div className='flex items-center gap-2 flex-wrap'>
                <Button size='sm' onClick={addUpdate} disabled={savingUpd} className='gap-1.5'>
                  {savingUpd ? <Loader2 className='h-3.5 w-3.5 animate-spin' /> : <Send className='h-3.5 w-3.5' />}
                  {savingUpd ? 'Guardando...' : 'Guardar entrada'}
                </Button>
                <label className='flex items-center gap-1.5 cursor-pointer rounded-md border border-zinc-700 px-3 py-1.5 text-xs text-zinc-500 hover:border-zinc-500 hover:text-zinc-300 transition-colors'>
                  <Image className='h-3 w-3' /> Imagen
                  <input type='file' accept='image/*' className='hidden' onChange={e => { const f = e.target.files?.[0]; if (f) addImageFile(f) }} />
                </label>
                <span className='text-[10px] text-zinc-700'>o pegá una captura con Ctrl+V</span>
              </div>
            </div>

            {/* Feed de entradas */}
            {loadingUpd ? (
              <div className='flex justify-center py-6'><Loader2 className='h-5 w-5 animate-spin text-zinc-600' /></div>
            ) : updates.length === 0 ? (
              <div className='flex flex-col items-center gap-2 py-8 text-center'>
                <MessageSquare className='h-8 w-8 text-zinc-700' />
                <p className='text-xs text-zinc-600'>Sin entradas registradas</p>
              </div>
            ) : (
              <div className='space-y-4'>
                {updates.map(u => {
                  const parsedBlocks = parseContent(u.content)
                  return (
                    <div key={u.id} className='rounded-lg border border-zinc-800 bg-zinc-900/30 overflow-hidden'>
                      <div className='p-4 space-y-3'>
                        {/* Bloques */}
                        <BlockViewer blocks={parsedBlocks} />

                        {/* Imágenes */}
                        {u.images && u.images.length > 0 && (
                          <div className='flex flex-wrap gap-2 mt-2'>
                            {u.images.map(img => (
                              <div key={img.id} className='relative group rounded overflow-hidden border border-zinc-700'>
                                <img
                                  src={`/api/uploads/${img.filename}`}
                                  alt={img.original_name}
                                  className='h-32 w-auto max-w-xs object-cover cursor-pointer'
                                  onClick={() => window.open(`/api/uploads/${img.filename}`, '_blank')}
                                />
                                <button
                                  onClick={() => deleteUpdateImage(u.id, img.id)}
                                  className='absolute top-1 right-1 rounded-full bg-black/70 p-0.5 text-zinc-300 hover:text-red-400 opacity-0 group-hover:opacity-100 transition'>
                                  <X className='h-3 w-3' />
                                </button>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Footer */}
                      <div className='flex items-center justify-between px-4 py-2 bg-zinc-950/40 border-t border-zinc-800'>
                        <div className='flex items-center gap-2'>
                          {u.author_name && <span className='text-[10px] text-zinc-600'>{u.author_name}</span>}
                          <span className='text-[10px] text-zinc-700'>
                            {new Date(u.created_at).toLocaleString('es-AR', { dateStyle: 'short', timeStyle: 'short' })}
                          </span>
                        </div>
                        <button onClick={() => deleteUpdate(u.id)}
                          className='rounded p-1 text-zinc-700 hover:text-red-400 transition'>
                          <Trash2 className='h-3 w-3' />
                        </button>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Custom Workspace ─────────────────────────────────────────────────────────
export function CustomWorkspace({ engagementId }: { engagementId: string }) {
  const navigate = useNavigate()
  const [engagement, setEngagement] = useState<Engagement | null>(null)
  const [phases, setPhases]         = useState<CustomPhase[]>([])
  const [selected, setSelected]     = useState<CustomPhase | null>(null)
  const [loading, setLoading]       = useState(true)
  const [adding, setAdding]         = useState(false)
  const [newName, setNewName]       = useState('')
  const [newDesc, setNewDesc]       = useState('')
  const [savingNew, setSavingNew]   = useState(false)
  const [editing, setEditing]       = useState<string | null>(null)
  const [editName, setEditName]     = useState('')
  const [tecnicasOpen, setTecnicasOpen] = useState(false)

  async function load() {
    try {
      const eng = await apiFetch<Engagement>(`/engagements/${engagementId}`)
      setEngagement(eng)
    } catch {}
    try {
      const ps = await apiFetch<CustomPhase[]>(`/engagements/${engagementId}/custom-phases`)
      setPhases(ps)
      if (ps.length > 0 && !selected) setSelected(ps[0])
    } catch {}
    setLoading(false)
  }

  useEffect(() => { load() }, [engagementId])

  async function createPhase() {
    if (!newName.trim()) return
    setSavingNew(true)
    try {
      const p = await apiFetch<CustomPhase>(`/engagements/${engagementId}/custom-phases`, {
        method: 'POST', body: { name: newName.trim(), description: newDesc.trim() || undefined },
      })
      setPhases(prev => [...prev, p]); setSelected(p)
      setAdding(false); setNewName(''); setNewDesc('')
      toast.success('Etapa creada')
    } catch { toast.error('Error al crear etapa') } finally { setSavingNew(false) }
  }

  async function deletePhase(phase: CustomPhase) {
    if (!confirm(`¿Eliminar la etapa "${phase.name}" y todos sus documentos?`)) return
    try {
      await apiFetch(`/engagements/${engagementId}/custom-phases/${phase.id}`, { method: 'DELETE' })
      setPhases(prev => prev.filter(p => p.id !== phase.id))
      if (selected?.id === phase.id) setSelected(phases.find(p => p.id !== phase.id) ?? null)
      toast.success('Etapa eliminada')
    } catch { toast.error('Error al eliminar') }
  }

  async function saveEditName(phase: CustomPhase) {
    if (!editName.trim()) return
    try {
      const updated = await apiFetch<CustomPhase>(`/engagements/${engagementId}/custom-phases/${phase.id}`, {
        method: 'PUT', body: { name: editName.trim() },
      })
      setPhases(prev => prev.map(p => p.id === phase.id ? { ...p, name: updated.name } : p))
      if (selected?.id === phase.id) setSelected(prev => prev ? { ...prev, name: updated.name } : prev)
      setEditing(null)
    } catch { toast.error('Error') }
  }

  function onPhaseChange() {
    apiFetch<CustomPhase[]>(`/engagements/${engagementId}/custom-phases`)
      .then(ps => {
        setPhases(ps)
        if (selected) {
          const updated = ps.find(p => p.id === selected.id)
          if (updated) setSelected(updated)
        }
      }).catch(() => {})
  }

  if (loading) {
    return <div className='flex h-64 items-center justify-center'><Loader2 className='h-8 w-8 animate-spin text-zinc-600' /></div>
  }
  if (!engagement) {
    return (
      <div className='flex flex-col items-center gap-4 py-16'>
        <p className='text-muted-foreground'>Engagement no encontrado.</p>
        <Button variant='outline' onClick={() => navigate({ to: '/engagements' })}>Volver</Button>
      </div>
    )
  }

  return (
    <div className='flex h-[calc(100vh-4rem)] gap-0 -m-6'>
      {/* ── Sidebar ───────────────────────────────────────────────────────────── */}
      <div className='w-56 shrink-0 border-r border-border flex flex-col bg-sidebar'>
        {/* Header */}
        <div className='p-4 border-b border-border'>
          <Button variant='ghost' size='sm' className='mb-3 -ml-2 h-7 text-xs text-muted-foreground'
            onClick={() => navigate({ to: '/engagements' })}>
            <ArrowLeft className='mr-1 h-3 w-3' /> Engagements
          </Button>
          <p className='text-xs font-semibold text-zinc-200 truncate'>{engagement.title}</p>
          <p className='text-[10px] text-zinc-500 mt-0.5 truncate'>{engagement.client_name}</p>
          <div className='mt-2'>
            <span className='rounded bg-blue-950/60 border border-blue-900/40 px-1.5 py-0.5 text-[10px] text-blue-300'>
              {TYPE_LABELS[engagement.type] ?? engagement.type}
            </span>
          </div>
        </div>

        {/* Phase list */}
        <div className='flex-1 overflow-y-auto p-2 space-y-1'>
          {phases.map(phase => {
            const cfg = STATUS_CFG[phase.status]
            const isActive = selected?.id === phase.id
            return (
              <div key={phase.id} className={cn('group rounded-md transition-colors', isActive ? 'bg-accent' : 'hover:bg-accent/50')}>
                {editing === phase.id ? (
                  <div className='flex items-center gap-1 px-2 py-1.5'>
                    <input autoFocus value={editName} onChange={e => setEditName(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter') saveEditName(phase); if (e.key === 'Escape') setEditing(null) }}
                      className='flex-1 min-w-0 bg-zinc-800 rounded px-1.5 py-0.5 text-xs text-zinc-100 border border-zinc-600 outline-none' />
                    <button onClick={() => saveEditName(phase)} className='text-green-400 hover:text-green-300'><Check className='h-3 w-3' /></button>
                    <button onClick={() => setEditing(null)} className='text-zinc-500 hover:text-zinc-300'><X className='h-3 w-3' /></button>
                  </div>
                ) : (
                  <button onClick={() => setSelected(phase)} className='w-full text-left px-2 py-2'>
                    <div className='flex items-center gap-1.5'>
                      <span className={cfg.color}>{cfg.icon}</span>
                      <span className='text-xs text-zinc-300 flex-1 truncate'>{phase.name}</span>
                      <div className='opacity-0 group-hover:opacity-100 flex items-center gap-0.5'>
                        <button onClick={e => { e.stopPropagation(); setEditing(phase.id); setEditName(phase.name) }}
                          className='rounded p-0.5 text-zinc-600 hover:text-zinc-300 transition'>
                          <Pencil className='h-2.5 w-2.5' />
                        </button>
                        <button onClick={e => { e.stopPropagation(); deletePhase(phase) }}
                          className='rounded p-0.5 text-zinc-700 hover:text-red-400 transition'>
                          <Trash2 className='h-2.5 w-2.5' />
                        </button>
                      </div>
                    </div>
                    {(phase.docs_count || phase.updates_count) ? (
                      <div className='ml-5 mt-0.5 flex gap-2 text-[10px] text-zinc-700'>
                        {phase.docs_count ? <span>{phase.docs_count} doc{phase.docs_count !== 1 ? 's' : ''}</span> : null}
                        {phase.updates_count ? <span>{phase.updates_count} entrada{phase.updates_count !== 1 ? 's' : ''}</span> : null}
                      </div>
                    ) : null}
                  </button>
                )}
              </div>
            )
          })}

          {/* Add phase form */}
          {adding ? (
            <div className='rounded-md border border-zinc-700 bg-zinc-900/50 p-2 space-y-1.5'>
              <input autoFocus value={newName} onChange={e => setNewName(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') createPhase(); if (e.key === 'Escape') setAdding(false) }}
                placeholder='Nombre de la etapa...'
                className='w-full bg-zinc-800 rounded px-2 py-1 text-xs text-zinc-100 border border-zinc-600 outline-none' />
              <input value={newDesc} onChange={e => setNewDesc(e.target.value)}
                placeholder='Descripción (opcional)'
                className='w-full bg-zinc-800 rounded px-2 py-1 text-xs text-zinc-400 border border-zinc-700 outline-none' />
              <div className='flex gap-1'>
                <button onClick={createPhase} disabled={savingNew || !newName.trim()}
                  className='flex-1 rounded bg-blue-700 hover:bg-blue-600 disabled:opacity-50 px-2 py-1 text-[10px] text-white font-medium transition'>
                  {savingNew ? '...' : 'Crear'}
                </button>
                <button onClick={() => setAdding(false)}
                  className='rounded px-2 py-1 text-[10px] text-zinc-500 hover:text-zinc-300 transition'>
                  Cancelar
                </button>
              </div>
            </div>
          ) : (
            <button onClick={() => setAdding(true)}
              className='w-full flex items-center gap-1.5 rounded-md px-2 py-2 text-xs text-zinc-600 hover:text-zinc-300 hover:bg-zinc-800/50 transition-colors'>
              <Plus className='h-3 w-3' /> Nueva etapa
            </button>
          )}
        </div>

        {/* Bottom actions */}
        <div className='p-3 border-t border-border space-y-1'>
          <Button size='sm' variant='ghost' className='w-full justify-start text-xs h-8 text-muted-foreground'
            onClick={() => setTecnicasOpen(true)}>
            <Crosshair className='mr-1.5 h-3 w-3' /> Técnicas
          </Button>
          <Button size='sm' variant='ghost' className='w-full justify-start text-xs h-8 text-muted-foreground'
            onClick={() => navigate({ to: '/engagements/$engagementId/editar', params: { engagementId } })}>
            <FileText className='mr-1.5 h-3 w-3' /> Editar engagement
          </Button>
        </div>
      </div>

      {/* ── Main area ─────────────────────────────────────────────────────────── */}
      <div className='flex-1 overflow-hidden'>
        {selected ? (
          <PhaseDetail phase={selected} engagementId={engagementId} onPhaseChange={onPhaseChange} />
        ) : (
          <div className='flex flex-col items-center justify-center h-full gap-3 text-center'>
            <FolderOpen className='h-12 w-12 text-zinc-700' />
            <p className='text-sm text-zinc-500'>Seleccioná o creá una etapa.</p>
          </div>
        )}
      </div>

      {/* Técnicas sheet */}
      <TecnicasSheet
        open={tecnicasOpen}
        onOpenChange={setTecnicasOpen}
        engagementId={engagementId}
        currentPhaseId={selected?.id}
      />
    </div>
  )
}
