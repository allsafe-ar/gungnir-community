/**
 * EvidenceSheet — Upload y gestión de evidencias de un engagement.
 * Soporta imágenes, capturas, scripts, logs, texto y otros archivos.
 */

import { useEffect, useRef, useState, useCallback } from 'react'
import { Upload, X, FileText, Image, File, Trash2, Loader2, Paperclip, Download } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { apiFetch, API_BASE } from '@/lib/api'
import { toast } from 'sonner'

// ─── Tipos ────────────────────────────────────────────────────────────────────
interface Evidence {
  id: string
  engagement_id: string
  finding_id?: string
  phase_type?: string
  filename: string
  original_name: string
  file_type?: string
  file_size?: number
  caption?: string
  uploaded_by?: string
  uploaded_at: string
}

interface EvidenceSheetProps {
  open: boolean
  onOpenChange: (v: boolean) => void
  engagementId: string
  currentPhase?: string
}

const MAX_SIZE_MB = 20

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function fileIcon(type?: string) {
  if (!type) return <File className='h-4 w-4 text-zinc-500' />
  if (type.startsWith('image/')) return <Image className='h-4 w-4 text-blue-400' />
  if (type.includes('pdf')) return <FileText className='h-4 w-4 text-red-400' />
  if (type.includes('text') || type.includes('json') || type.includes('xml'))
    return <FileText className='h-4 w-4 text-green-400' />
  return <File className='h-4 w-4 text-zinc-400' />
}

// ─── Drop zone ────────────────────────────────────────────────────────────────
function DropZone({ onFile }: { onFile: (f: File) => void }) {
  const { t } = useTranslation()
  const [over, setOver] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setOver(false)
    const file = e.dataTransfer.files[0]
    if (file) onFile(file)
  }

  return (
    <div
      onDragOver={e => { e.preventDefault(); setOver(true) }}
      onDragLeave={() => setOver(false)}
      onDrop={onDrop}
      onClick={() => inputRef.current?.click()}
      className={cn(
        'flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed p-8 text-center cursor-pointer transition-colors',
        over
          ? 'border-red-700 bg-red-950/20'
          : 'border-zinc-700 hover:border-zinc-600 hover:bg-zinc-900/50'
      )}
    >
      <Upload className={cn('h-6 w-6 transition-colors', over ? 'text-red-500' : 'text-zinc-600')} />
      <div>
        <p className='text-sm text-zinc-400'>{t('evidence.dropzone')}</p>
        <p className='text-xs text-zinc-600 mt-0.5'>{t('evidence.dropzone_hint')}</p>
      </div>
      <input
        ref={inputRef}
        type='file'
        className='hidden'
        onChange={e => {
          const f = e.target.files?.[0]
          if (f) onFile(f)
          e.target.value = ''
        }}
      />
    </div>
  )
}

// ─── Componente principal ─────────────────────────────────────────────────────
export function EvidenceSheet({ open, onOpenChange, engagementId, currentPhase }: EvidenceSheetProps) {
  const { t } = useTranslation()
  const [evidences, setEvidences] = useState<Evidence[]>([])
  const [loading, setLoading]     = useState(false)
  const [uploading, setUploading] = useState(false)

  // Upload form state
  const [pendingFile, setPendingFile] = useState<File | null>(null)
  const [caption, setCaption]         = useState('')
  const [phase, setPhase]             = useState(currentPhase || 'recon')

  const PHASE_LABELS: Record<string, string> = {
    planning:          t('phase.planning'),
    recon:             t('phase.recon'),
    scanning:          t('phase.scanning'),
    exploitation:      t('phase.exploitation'),
    post_exploitation: t('phase.post_exploitation'),
    reporting:         t('phase.reporting'),
  }

  // Sync phase when workspace phase changes
  useEffect(() => {
    if (currentPhase) setPhase(currentPhase)
  }, [currentPhase])

  // Load evidences
  const load = useCallback(() => {
    if (!open) return
    setLoading(true)
    apiFetch<Evidence[]>(`/engagements/${engagementId}/evidences`)
      .then(r => setEvidences(Array.isArray(r) ? r : []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [open, engagementId])

  useEffect(() => { load() }, [load])

  // File selected (from drop zone or input)
  function onFile(f: File) {
    if (f.size > MAX_SIZE_MB * 1024 * 1024) {
      toast.error(`Archivo muy grande. Máximo ${MAX_SIZE_MB} MB.`)
      return
    }
    setPendingFile(f)
  }

  // Upload
  async function handleUpload() {
    if (!pendingFile) return
    setUploading(true)
    try {
      const form = new FormData()
      form.append('file', pendingFile)
      form.append('phase_type', phase)
      if (caption.trim()) form.append('caption', caption.trim())

      const token = localStorage.getItem('gungnir_token')
      const res = await fetch(`${API_BASE}/engagements/${engagementId}/evidences`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: form,
      })

      if (!res.ok) throw new Error(await res.text())
      const ev = await res.json() as Evidence
      setEvidences(prev => [ev, ...prev])
      setPendingFile(null)
      setCaption('')
      toast.success(t('evidence.uploaded'))
    } catch {
      toast.error('Error al subir el archivo')
    } finally {
      setUploading(false)
    }
  }

  // Delete
  async function handleDelete(ev: Evidence) {
    if (!confirm(t('evidence.delete_confirm'))) return
    try {
      await apiFetch(`/engagements/${engagementId}/evidences/${ev.id}`, { method: 'DELETE' })
      setEvidences(prev => prev.filter(e => e.id !== ev.id))
      toast.success(t('evidence.deleted'))
    } catch {
      toast.error('Error al eliminar')
    }
  }

  // Download
  function handleDownload(ev: Evidence) {
    const token = localStorage.getItem('gungnir_token')
    const url = `${API_BASE}/uploads/${ev.filename}`
    const a = document.createElement('a')
    a.href = token ? `${url}?token=${token}` : url
    a.download = ev.original_name
    a.click()
  }

  const byPhase = evidences.reduce<Record<string, Evidence[]>>((acc, e) => {
    const p = e.phase_type || 'general'
    if (!acc[p]) acc[p] = []
    acc[p].push(e)
    return acc
  }, {})

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side='right' className='w-full sm:max-w-lg flex flex-col gap-0 p-0 overflow-hidden'>
        <SheetHeader className='border-b border-border px-6 py-4'>
          <SheetTitle className='flex items-center gap-2 text-sm'>
            <Paperclip className='h-4 w-4 text-muted-foreground' />
            {t('evidence.title')}
            {evidences.length > 0 && (
              <span className='ml-auto rounded-full bg-zinc-800 px-2 py-0.5 text-xs font-normal text-zinc-400'>
                {evidences.length}
              </span>
            )}
          </SheetTitle>
        </SheetHeader>

        <div className='flex-1 overflow-y-auto px-6 py-4 space-y-5'>
          {/* Upload area */}
          <div className='space-y-3'>
            {!pendingFile ? (
              <DropZone onFile={onFile} />
            ) : (
              <div className='rounded-lg border border-zinc-700 bg-zinc-900 p-4 space-y-3'>
                {/* File info */}
                <div className='flex items-center gap-3'>
                  {fileIcon(pendingFile.type)}
                  <div className='flex-1 min-w-0'>
                    <p className='text-xs font-medium text-zinc-200 truncate'>{pendingFile.name}</p>
                    <p className='text-[10px] text-zinc-500'>{formatBytes(pendingFile.size)}</p>
                  </div>
                  <button
                    onClick={() => setPendingFile(null)}
                    className='rounded p-1 text-zinc-600 hover:text-zinc-300 transition'
                  >
                    <X className='h-3.5 w-3.5' />
                  </button>
                </div>

                {/* Preview para imágenes */}
                {pendingFile.type.startsWith('image/') && (
                  <img
                    src={URL.createObjectURL(pendingFile)}
                    alt='preview'
                    className='rounded border border-zinc-800 max-h-40 w-full object-contain bg-zinc-950'
                  />
                )}

                {/* Fase */}
                <div className='space-y-1'>
                  <Label className='text-xs text-zinc-400'>{t('evidence.phase_label')}</Label>
                  <Select value={phase} onValueChange={setPhase}>
                    <SelectTrigger className='h-8 text-xs'>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {Object.entries(PHASE_LABELS).map(([v, l]) => (
                        <SelectItem key={v} value={v} className='text-xs'>{l}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {/* Caption */}
                <div className='space-y-1'>
                  <Label className='text-xs text-zinc-400'>Descripción (opcional)</Label>
                  <Input
                    value={caption}
                    onChange={e => setCaption(e.target.value)}
                    placeholder='Ej: Captura de SQLi en login, RCE confirmado...'
                    className='h-8 text-xs'
                    onKeyDown={e => e.key === 'Enter' && !e.shiftKey && handleUpload()}
                  />
                </div>

                <Button
                  onClick={handleUpload}
                  disabled={uploading}
                  size='sm'
                  className='w-full bg-red-700 hover:bg-red-600 text-white text-xs'
                >
                  {uploading
                    ? <><Loader2 className='mr-2 h-3.5 w-3.5 animate-spin' /> {t('common.loading')}</>
                    : <><Upload className='mr-2 h-3.5 w-3.5' /> {t('evidence.upload')}</>
                  }
                </Button>
              </div>
            )}
          </div>

          {/* Evidence list */}
          {loading ? (
            <div className='flex justify-center py-8'>
              <Loader2 className='h-5 w-5 animate-spin text-zinc-600' />
            </div>
          ) : evidences.length === 0 ? (
            <div className='flex flex-col items-center py-8 text-center text-zinc-600 gap-2'>
              <Paperclip className='h-6 w-6' />
              <p className='text-xs'>{t('evidence.no_files')}</p>
            </div>
          ) : (
            <div className='space-y-5'>
              {Object.entries(byPhase).map(([p, evs]) => (
                <div key={p}>
                  <p className='mb-2 text-[10px] uppercase tracking-wider text-zinc-600 font-semibold'>
                    {PHASE_LABELS[p] ?? p} · {evs.length}
                  </p>
                  <div className='space-y-2'>
                    {evs.map(ev => (
                      <div key={ev.id} className='group rounded-lg border border-zinc-800 bg-zinc-900/40 p-3'>
                        {/* Image preview */}
                        {ev.file_type?.startsWith('image/') && (
                          <img
                            src={`${API_BASE}/uploads/${ev.filename}?token=${localStorage.getItem('gungnir_token')}`}
                            alt={ev.original_name}
                            className='rounded mb-2 border border-zinc-800 max-h-32 w-full object-contain bg-zinc-950'
                          />
                        )}
                        <div className='flex items-start gap-2'>
                          {fileIcon(ev.file_type)}
                          <div className='flex-1 min-w-0'>
                            <p className='text-xs font-medium text-zinc-300 truncate'>{ev.original_name}</p>
                            {ev.caption && (
                              <p className='text-[10px] text-zinc-500 mt-0.5 line-clamp-2'>{ev.caption}</p>
                            )}
                            <p className='text-[10px] text-zinc-700 mt-1'>
                              {ev.file_size ? formatBytes(ev.file_size) : ''} ·{' '}
                              {new Date(ev.uploaded_at).toLocaleDateString('es-AR')}
                            </p>
                          </div>
                          <div className='flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity shrink-0'>
                            <button
                              onClick={() => handleDownload(ev)}
                              className='rounded p-1 text-zinc-600 hover:text-zinc-300 transition'
                              title={t('evidence.download')}
                            >
                              <Download className='h-3.5 w-3.5' />
                            </button>
                            <button
                              onClick={() => handleDelete(ev)}
                              className='rounded p-1 text-zinc-600 hover:text-red-400 transition'
                              title={t('common.delete')}
                            >
                              <Trash2 className='h-3.5 w-3.5' />
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}
