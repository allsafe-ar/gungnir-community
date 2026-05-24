/**
 * Notas — Base de conocimiento personal.
 * Links, configs, comandos, observaciones. Markdown soportado.
 * Scoped al usuario autenticado. Opcionalmente vinculadas a un engagement.
 * Soporta compartir notas con otros usuarios (lectura).
 */

import { useEffect, useState, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import {
  StickyNote, Pin, PinOff, Plus, Search, Trash2, Edit2, Copy, Tag, X, ChevronDown,
  Users, UserPlus, UserMinus, Share2,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { cn } from '@/lib/utils'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Note {
  id: string
  title: string
  content: string
  tags: string[]
  is_pinned: number
  engagement_id: string | null
  engagement_name?: string
  is_owner: boolean
  owner_name?: string
  owner_username?: string
  created_at: string
  updated_at: string
}

interface Engagement {
  id: string
  name: string
}

interface NoteForm {
  title: string
  content: string
  tags: string[]
  is_pinned: boolean
  engagement_id: string
}

interface ShareUser {
  id: string
  username: string
  full_name: string
}

const EMPTY_FORM: NoteForm = {
  title: '',
  content: '',
  tags: [],
  is_pinned: false,
  engagement_id: '',
}

// ─── Markdown renderer (lightweight, sin dependencias) ────────────────────────

function MarkdownContent({ content }: { content: string }) {
  const blocks: Array<{ type: 'code'; lang: string; text: string } | { type: 'text'; text: string }> = []
  const codeFence = /^```(\w*)\n([\s\S]*?)^```/gm
  let last = 0
  let match: RegExpExecArray | null

  // eslint-disable-next-line no-cond-assign
  while ((match = codeFence.exec(content)) !== null) {
    if (match.index > last) {
      blocks.push({ type: 'text', text: content.slice(last, match.index) })
    }
    blocks.push({ type: 'code', lang: match[1] || 'bash', text: match[2].trimEnd() })
    last = match.index + match[0].length
  }
  if (last < content.length) {
    blocks.push({ type: 'text', text: content.slice(last) })
  }

  const renderText = (raw: string) =>
    raw.split('\n').map((line, i) => {
      if (/^## /.test(line)) {
        return (
          <p key={i} className='font-semibold text-sm text-foreground mt-4 mb-1 first:mt-0 border-b border-border pb-0.5'>
            {line.replace(/^## /, '')}
          </p>
        )
      }
      if (/^# /.test(line)) {
        return (
          <p key={i} className='font-bold text-base text-foreground mt-4 mb-1 first:mt-0'>
            {line.replace(/^# /, '')}
          </p>
        )
      }
      if (/^- /.test(line) || /^\* /.test(line)) {
        return (
          <p key={i} className='text-sm text-muted-foreground pl-3 before:content-["·"] before:mr-2 before:text-primary'>
            {line.replace(/^[-*] /, '')}
          </p>
        )
      }
      if (line.trim() === '') return <div key={i} className='h-2' />
      const parts = line.split(/(`[^`]+`)/)
      return (
        <p key={i} className='text-sm text-muted-foreground leading-relaxed'>
          {parts.map((p, j) =>
            p.startsWith('`') && p.endsWith('`')
              ? <code key={j} className='bg-muted text-foreground text-xs px-1 py-0.5 rounded font-mono'>{p.slice(1, -1)}</code>
              : p
          )}
        </p>
      )
    })

  return (
    <div className='space-y-0.5'>
      {blocks.map((block, i) =>
        block.type === 'code' ? (
          <div key={i} className='my-2 rounded-md border border-border overflow-hidden'>
            {block.lang && (
              <div className='px-3 py-1 bg-muted/60 border-b border-border flex items-center justify-between'>
                <span className='text-[10px] font-mono text-muted-foreground uppercase tracking-wider'>{block.lang}</span>
              </div>
            )}
            <pre className='p-3 text-xs font-mono text-foreground bg-muted/30 overflow-x-auto whitespace-pre leading-relaxed'>
              {block.text}
            </pre>
          </div>
        ) : (
          <div key={i}>{renderText(block.text)}</div>
        )
      )}
    </div>
  )
}

// ─── Tag input ────────────────────────────────────────────────────────────────

function TagInput({
  tags,
  onChange,
  placeholder,
}: {
  tags: string[]
  onChange: (tags: string[]) => void
  placeholder: string
}) {
  const [input, setInput] = useState('')

  const add = () => {
    const v = input.trim().toLowerCase()
    if (v && !tags.includes(v)) onChange([...tags, v])
    setInput('')
  }

  return (
    <div className='flex flex-wrap gap-1.5 items-center border border-input rounded-md px-2 py-1.5 bg-background min-h-9'>
      {tags.map((tag) => (
        <span key={tag} className='flex items-center gap-1 bg-muted text-xs px-2 py-0.5 rounded-full'>
          <Tag className='size-2.5 opacity-60' />
          {tag}
          <button
            type='button'
            onClick={() => onChange(tags.filter((t) => t !== tag))}
            className='opacity-50 hover:opacity-100 ml-0.5'
          >
            <X className='size-2.5' />
          </button>
        </span>
      ))}
      <input
        className='flex-1 min-w-[80px] bg-transparent text-sm outline-none placeholder:text-muted-foreground'
        value={input}
        placeholder={tags.length === 0 ? placeholder : ''}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add() }
          if (e.key === 'Backspace' && !input && tags.length) {
            onChange(tags.slice(0, -1))
          }
        }}
        onBlur={add}
      />
    </div>
  )
}

// ─── Share panel (dentro del NoteViewer, solo para dueño) ─────────────────────

function SharePanel({ noteId }: { noteId: string }) {
  const [shares, setShares] = useState<ShareUser[]>([])
  const [allUsers, setAllUsers] = useState<ShareUser[]>([])
  const [selectedUser, setSelectedUser] = useState('')
  const [adding, setAdding] = useState(false)
  const [open, setOpen] = useState(false)

  const loadShares = async () => {
    try {
      const data = await apiFetch<ShareUser[]>(`/notes/${noteId}/shares`)
      setShares(data)
    } catch { /* silent */ }
  }

  const loadUsers = async () => {
    try {
      const data = await apiFetch<ShareUser[]>('/notes/users')
      setAllUsers(data)
    } catch { /* silent */ }
  }

  useEffect(() => {
    loadShares()
    loadUsers()
  }, [noteId])

  const availableUsers = allUsers.filter(u => !shares.find(s => s.id === u.id))

  const handleAdd = async () => {
    if (!selectedUser) return
    setAdding(true)
    try {
      await apiFetch(`/notes/${noteId}/share`, {
        method: 'POST',
        body: JSON.stringify({ user_id: selectedUser }),
      })
      setSelectedUser('')
      await loadShares()
      toast.success('Nota compartida')
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Error al compartir')
    } finally {
      setAdding(false)
    }
  }

  const handleRevoke = async (userId: string, userName: string) => {
    try {
      await apiFetch(`/notes/${noteId}/share/${userId}`, { method: 'DELETE' })
      await loadShares()
      toast.success(`Acceso revocado a ${userName}`)
    } catch {
      toast.error('Error al revocar acceso')
    }
  }

  return (
    <div className='border-t border-border'>
      {/* Toggle header */}
      <button
        type='button'
        onClick={() => setOpen(!open)}
        className='w-full flex items-center justify-between px-6 py-2.5 hover:bg-muted/30 transition-colors'
      >
        <span className='flex items-center gap-2 text-xs font-medium text-muted-foreground'>
          <Share2 className='size-3.5' />
          Compartir nota
          {shares.length > 0 && (
            <Badge variant='secondary' className='text-[10px] h-4 px-1.5'>
              {shares.length}
            </Badge>
          )}
        </span>
        <ChevronDown className={cn('size-3.5 text-muted-foreground transition-transform', open && 'rotate-180')} />
      </button>

      {open && (
        <div className='px-6 pb-4 space-y-3'>
          {/* Current shares */}
          {shares.length > 0 ? (
            <div className='space-y-1.5'>
              {shares.map((u) => (
                <div
                  key={u.id}
                  className='flex items-center justify-between rounded-md bg-muted/40 px-3 py-1.5'
                >
                  <div className='flex items-center gap-2'>
                    <div className='size-5 rounded-full bg-primary/20 flex items-center justify-center text-[10px] font-semibold text-primary'>
                      {u.full_name.charAt(0).toUpperCase()}
                    </div>
                    <div className='leading-tight'>
                      <p className='text-xs font-medium'>{u.full_name}</p>
                      <p className='text-[10px] text-muted-foreground'>@{u.username}</p>
                    </div>
                  </div>
                  <button
                    type='button'
                    onClick={() => handleRevoke(u.id, u.full_name)}
                    className='p-1 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors'
                    title='Revocar acceso'
                  >
                    <UserMinus className='size-3.5' />
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <p className='text-xs text-muted-foreground italic'>
              Esta nota no está compartida con nadie todavía.
            </p>
          )}

          {/* Add user */}
          {availableUsers.length > 0 && (
            <div className='flex gap-2'>
              <select
                value={selectedUser}
                onChange={(e) => setSelectedUser(e.target.value)}
                className='flex-1 h-8 rounded-md border border-input bg-background px-2 text-xs focus:outline-none focus:ring-2 focus:ring-ring'
              >
                <option value=''>Seleccionar usuario…</option>
                {availableUsers.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.full_name} (@{u.username})
                  </option>
                ))}
              </select>
              <Button
                size='sm'
                className='h-8 gap-1.5 text-xs shrink-0'
                disabled={!selectedUser || adding}
                onClick={handleAdd}
              >
                <UserPlus className='size-3.5' />
                Agregar
              </Button>
            </div>
          )}

          {availableUsers.length === 0 && allUsers.length > 0 && (
            <p className='text-xs text-muted-foreground italic'>
              Todos los usuarios ya tienen acceso a esta nota.
            </p>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Note viewer (read-only) ──────────────────────────────────────────────────

function NoteViewer({
  note,
  onClose,
  onEdit,
  onCopy,
}: {
  note: Note | null
  onClose: () => void
  onEdit: (note: Note) => void
  onCopy: (content: string) => void
}) {
  const { t } = useTranslation()
  if (!note) return null

  const fmt = (iso: string) =>
    new Date(iso).toLocaleString(undefined, {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    })

  return (
    <Dialog open={!!note} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className='max-w-3xl max-h-[90vh] flex flex-col gap-0 p-0 overflow-hidden'>
        {/* Header */}
        <div className='flex items-start gap-3 px-6 pt-5 pb-4 border-b border-border'>
          <StickyNote className='size-4 text-primary mt-0.5 shrink-0' />
          <div className='flex-1 min-w-0'>
            <h2 className='font-semibold text-base leading-snug pr-4'>{note.title}</h2>
            <div className='flex flex-wrap items-center gap-2 mt-1.5'>
              {note.is_pinned ? (
                <span className='flex items-center gap-1 text-[10px] text-primary font-medium'>
                  <Pin className='size-2.5 fill-current' /> Fijada
                </span>
              ) : null}
              {!note.is_owner && note.owner_name && (
                <span className='flex items-center gap-1 text-[10px] text-muted-foreground bg-muted px-2 py-0.5 rounded-full'>
                  <Users className='size-2.5' />
                  Compartida por {note.owner_name}
                </span>
              )}
              {note.tags.map((tag) => (
                <Badge key={tag} variant='outline' className='text-[10px] px-1.5 py-0 h-4'>{tag}</Badge>
              ))}
            </div>
          </div>
        </div>

        {/* Content */}
        <div className='flex-1 overflow-y-auto px-6 py-4'>
          {note.content
            ? <MarkdownContent content={note.content} />
            : <p className='text-sm text-muted-foreground italic'>Sin contenido</p>
          }
        </div>

        {/* Share panel — solo si es dueño */}
        {note.is_owner && <SharePanel noteId={note.id} />}

        {/* Footer */}
        <div className='px-6 py-3 border-t border-border flex items-center justify-between gap-3 bg-muted/20'>
          <div className='text-[10px] text-muted-foreground space-y-0.5'>
            {note.engagement_name && (
              <p className='flex items-center gap-1'>
                <ChevronDown className='size-2.5 -rotate-90' />
                {t('notas.linked_to')}: {note.engagement_name}
              </p>
            )}
            <p>{t('notas.last_updated')}: {fmt(note.updated_at)}</p>
          </div>

          <div className='flex items-center gap-2'>
            <Button
              variant='outline'
              size='sm'
              className='gap-1.5 h-7 text-xs'
              onClick={() => { onCopy(note.content) }}
            >
              <Copy className='size-3' />
              {t('notas.copy')}
            </Button>
            {note.is_owner && (
              <Button
                variant='outline'
                size='sm'
                className='gap-1.5 h-7 text-xs'
                onClick={() => { onClose(); onEdit(note) }}
              >
                <Edit2 className='size-3' />
                {t('common.edit')}
              </Button>
            )}
            <Button size='sm' className='h-7 text-xs' onClick={onClose}>
              {t('common.cancel')}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// ─── Note card ────────────────────────────────────────────────────────────────

function NoteCard({
  note,
  onView,
  onEdit,
  onDelete,
  onTogglePin,
  onCopy,
}: {
  note: Note
  onView: (note: Note) => void
  onEdit: (note: Note) => void
  onDelete: (note: Note) => void
  onTogglePin: (note: Note) => void
  onCopy: (content: string) => void
}) {
  const { t } = useTranslation()

  const preview = note.content.length > 200
    ? note.content.slice(0, 200).trimEnd() + '…'
    : note.content

  const timeAgo = (iso: string) => {
    const diff = Date.now() - new Date(iso).getTime()
    const mins = Math.floor(diff / 60000)
    if (mins < 2) return 'Ahora'
    if (mins < 60) return `${mins}m`
    const hrs = Math.floor(mins / 60)
    if (hrs < 24) return `${hrs}h`
    const days = Math.floor(hrs / 24)
    if (days < 30) return `${days}d`
    return new Date(iso).toLocaleDateString()
  }

  const isShared = !note.is_owner

  return (
    <div className={cn(
      'group relative flex flex-col gap-2 rounded-lg border bg-card p-4 transition-all hover:shadow-md',
      note.is_pinned ? 'border-primary/30 bg-primary/5' : 'border-border',
      isShared && 'border-dashed',
    )}>
      {/* Pin indicator */}
      {note.is_pinned === 1 && (
        <div className='absolute top-3 right-3 text-primary/60'>
          <Pin className='size-3 fill-current' />
        </div>
      )}

      {/* Shared-by badge */}
      {isShared && note.owner_name && (
        <div className='flex items-center gap-1 text-[10px] text-muted-foreground'>
          <Users className='size-2.5' />
          <span>De: {note.owner_name}</span>
        </div>
      )}

      {/* Clickable body → abre visor */}
      <button
        className='text-left flex flex-col gap-2 flex-1 cursor-pointer'
        onClick={() => onView(note)}
      >
        <h3 className='font-semibold text-sm pr-6 leading-snug line-clamp-2 group-hover:text-primary transition-colors'>
          {note.title}
        </h3>

        {preview && (
          <p className='text-xs text-muted-foreground leading-relaxed line-clamp-4 font-mono whitespace-pre-wrap'>
            {preview}
          </p>
        )}
      </button>

      {/* Tags */}
      {note.tags.length > 0 && (
        <div className='flex flex-wrap gap-1 mt-auto'>
          {note.tags.slice(0, 4).map((tag) => (
            <Badge key={tag} variant='outline' className='text-[10px] px-1.5 py-0 h-4'>
              {tag}
            </Badge>
          ))}
          {note.tags.length > 4 && (
            <Badge variant='outline' className='text-[10px] px-1.5 py-0 h-4'>
              +{note.tags.length - 4}
            </Badge>
          )}
        </div>
      )}

      {/* Engagement link */}
      {note.engagement_name && (
        <p className='text-[10px] text-muted-foreground flex items-center gap-1'>
          <ChevronDown className='size-2.5 -rotate-90' />
          {t('notas.linked_to')}: {note.engagement_name}
        </p>
      )}

      {/* Footer: time + actions */}
      <div className='flex items-center justify-between mt-1'>
        <span className='text-[10px] text-muted-foreground'>
          {t('notas.last_updated')} {timeAgo(note.updated_at)}
        </span>
        <div className='flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity'>
          <button
            onClick={(e) => { e.stopPropagation(); onCopy(note.content) }}
            className='p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors'
            title={t('notas.copy')}
          >
            <Copy className='size-3' />
          </button>
          {/* Solo el dueño puede fijar, editar y borrar */}
          {note.is_owner && (
            <>
              <button
                onClick={(e) => { e.stopPropagation(); onTogglePin(note) }}
                className='p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors'
                title={note.is_pinned ? t('notas.unpin') : t('notas.pin')}
              >
                {note.is_pinned ? <PinOff className='size-3' /> : <Pin className='size-3' />}
              </button>
              <button
                onClick={(e) => { e.stopPropagation(); onEdit(note) }}
                className='p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors'
                title={t('common.edit')}
              >
                <Edit2 className='size-3' />
              </button>
              <button
                onClick={(e) => { e.stopPropagation(); onDelete(note) }}
                className='p-1 rounded hover:bg-muted text-muted-foreground hover:text-destructive transition-colors'
                title={t('common.delete')}
              >
                <Trash2 className='size-3' />
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Note modal (edit / create) ───────────────────────────────────────────────

function NoteModal({
  open,
  initial,
  engagements,
  onClose,
  onSave,
}: {
  open: boolean
  initial: Note | null
  engagements: Engagement[]
  onClose: () => void
  onSave: (form: NoteForm) => Promise<void>
}) {
  const { t } = useTranslation()
  const [form, setForm] = useState<NoteForm>(EMPTY_FORM)
  const [saving, setSaving] = useState(false)
  const titleRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (open) {
      setForm(
        initial
          ? {
              title: initial.title,
              content: initial.content,
              tags: initial.tags ?? [],
              is_pinned: !!initial.is_pinned,
              engagement_id: initial.engagement_id ?? '',
            }
          : EMPTY_FORM,
      )
      setTimeout(() => titleRef.current?.focus(), 80)
    }
  }, [open, initial])

  const handleSave = async () => {
    if (!form.title.trim()) {
      toast.error(t('notas.title_label') + ' requerido')
      return
    }
    setSaving(true)
    try {
      await onSave(form)
      onClose()
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className='max-w-2xl max-h-[90vh] flex flex-col'>
        <DialogHeader>
          <DialogTitle className='flex items-center gap-2'>
            <StickyNote className='size-4 text-primary' />
            {initial ? t('notas.edit_title') : t('notas.new_title')}
          </DialogTitle>
        </DialogHeader>

        <div className='flex-1 overflow-y-auto space-y-4 pr-1'>
          {/* Title */}
          <div className='space-y-1.5'>
            <label className='text-xs font-medium text-muted-foreground uppercase tracking-wider'>
              {t('notas.title_label')}
            </label>
            <Input
              ref={titleRef}
              value={form.title}
              onChange={(e) => setForm({ ...form, title: e.target.value })}
              placeholder={t('notas.title_placeholder')}
            />
          </div>

          {/* Content */}
          <div className='space-y-1.5'>
            <label className='text-xs font-medium text-muted-foreground uppercase tracking-wider'>
              {t('notas.content_label')}
            </label>
            <Textarea
              value={form.content}
              onChange={(e) => setForm({ ...form, content: e.target.value })}
              placeholder={t('notas.content_placeholder')}
              className='font-mono text-sm min-h-[220px] resize-y'
            />
          </div>

          {/* Tags */}
          <div className='space-y-1.5'>
            <label className='text-xs font-medium text-muted-foreground uppercase tracking-wider'>
              {t('notas.tags_label')}
            </label>
            <TagInput
              tags={form.tags}
              onChange={(tags) => setForm({ ...form, tags })}
              placeholder={t('notas.tag_placeholder')}
            />
          </div>

          {/* Engagement */}
          <div className='space-y-1.5'>
            <label className='text-xs font-medium text-muted-foreground uppercase tracking-wider'>
              {t('notas.engagement_label')}
            </label>
            <select
              value={form.engagement_id}
              onChange={(e) => setForm({ ...form, engagement_id: e.target.value })}
              className='w-full h-9 rounded-md border border-input bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring'
            >
              <option value=''>{t('notas.engagement_none')}</option>
              {engagements.map((e) => (
                <option key={e.id} value={e.id}>{e.name}</option>
              ))}
            </select>
          </div>

          {/* Pin */}
          <label className='flex items-center gap-2 cursor-pointer select-none'>
            <input
              type='checkbox'
              checked={form.is_pinned}
              onChange={(e) => setForm({ ...form, is_pinned: e.target.checked })}
              className='rounded border-input'
            />
            <span className='text-sm flex items-center gap-1.5'>
              <Pin className='size-3.5 text-muted-foreground' />
              {t('notas.pin')}
            </span>
          </label>
        </div>

        <DialogFooter className='pt-2 border-t'>
          <Button variant='outline' onClick={onClose} disabled={saving}>
            {t('common.cancel')}
          </Button>
          <Button onClick={handleSave} disabled={saving}>
            {saving ? t('common.loading') : t('common.save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export function Notas() {
  const { t } = useTranslation()
  const [notes, setNotes] = useState<Note[]>([])
  const [engagements, setEngagements] = useState<Engagement[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filterTag, setFilterTag] = useState('')
  const [showPinned, setShowPinned] = useState(false)

  const [viewing, setViewing] = useState<Note | null>(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<Note | null>(null)
  const [toDelete, setToDelete] = useState<Note | null>(null)

  // ── Load ───────────────────────────────────────────────────────────────────

  const load = async () => {
    try {
      const params = new URLSearchParams()
      if (search) params.set('search', search)
      if (filterTag) params.set('tag', filterTag)
      if (showPinned) params.set('pinned', '1')
      const data = await apiFetch<Note[]>(`/notes?${params}`)
      setNotes(data)
    } catch {
      // silent
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [search, filterTag, showPinned])

  useEffect(() => {
    apiFetch<Engagement[]>('/engagements')
      .then((d) => setEngagements(d))
      .catch(() => {})
  }, [])

  // ── CRUD ──────────────────────────────────────────────────────────────────

  const handleSave = async (form: NoteForm) => {
    const payload = {
      title: form.title,
      content: form.content,
      tags: form.tags,
      is_pinned: form.is_pinned ? 1 : 0,
      engagement_id: form.engagement_id || null,
    }

    if (editing) {
      await apiFetch(`/notes/${editing.id}`, { method: 'PUT', body: JSON.stringify(payload) })
    } else {
      await apiFetch('/notes', { method: 'POST', body: JSON.stringify(payload) })
    }

    toast.success(t('notas.saved'))
    await load()
  }

  const handleDelete = async () => {
    if (!toDelete) return
    await apiFetch(`/notes/${toDelete.id}`, { method: 'DELETE' })
    toast.success(t('notas.deleted'))
    setToDelete(null)
    await load()
  }

  const handleTogglePin = async (note: Note) => {
    await apiFetch(`/notes/${note.id}`, {
      method: 'PUT',
      body: JSON.stringify({ is_pinned: note.is_pinned ? 0 : 1 }),
    })
    await load()
  }

  const handleCopy = (content: string) => {
    navigator.clipboard.writeText(content)
    toast.success(t('notas.copy'))
  }

  // ── Derived data ──────────────────────────────────────────────────────────

  const pinned   = notes.filter((n) => n.is_pinned)
  const unpinned = notes.filter((n) => !n.is_pinned)
  const allTags  = [...new Set(notes.flatMap((n) => n.tags ?? []))].sort()

  const sharedCount = notes.filter(n => !n.is_owner).length

  const openNew  = () => { setEditing(null); setModalOpen(true) }
  const openEdit = (note: Note) => { setEditing(note); setModalOpen(true) }
  const openView = (note: Note) => setViewing(note)

  // ── Render ────────────────────────────────────────────────────────────────

  const renderGrid = (items: Note[]) => (
    <div className='grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3'>
      {items.map((note) => (
        <NoteCard
          key={note.id}
          note={note}
          onView={openView}
          onEdit={openEdit}
          onDelete={setToDelete}
          onTogglePin={handleTogglePin}
          onCopy={handleCopy}
        />
      ))}
    </div>
  )

  return (
    <div className='space-y-6'>
      {/* Header */}
      <div className='flex flex-col sm:flex-row sm:items-center justify-between gap-3'>
        <div>
          <h1 className='text-2xl font-bold tracking-tight flex items-center gap-2'>
            <StickyNote className='size-6 text-primary' />
            {t('notas.title')}
          </h1>
          <p className='text-sm text-muted-foreground mt-0.5'>
            {t('notas.subtitle')}
            {sharedCount > 0 && (
              <span className='ml-2 inline-flex items-center gap-1 text-xs text-muted-foreground'>
                · <Users className='size-3' /> {sharedCount} compartida{sharedCount !== 1 ? 's' : ''} con vos
              </span>
            )}
          </p>
        </div>
        <Button onClick={openNew} className='shrink-0'>
          <Plus className='mr-2 size-4' />
          {t('notas.new')}
        </Button>
      </div>

      {/* Filters row */}
      <div className='flex flex-col sm:flex-row gap-2 items-start sm:items-center'>
        <div className='relative flex-1 max-w-sm'>
          <Search className='absolute left-2.5 top-2.5 size-4 text-muted-foreground' />
          <Input
            className='pl-8'
            placeholder={t('notas.search_placeholder')}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <Button
          variant={showPinned ? 'default' : 'outline'}
          size='sm'
          onClick={() => setShowPinned(!showPinned)}
          className='gap-1.5'
        >
          <Pin className='size-3.5' />
          {t('notas.pinned')}
        </Button>

        {filterTag && (
          <Badge
            variant='secondary'
            className='gap-1 cursor-pointer'
            onClick={() => setFilterTag('')}
          >
            <Tag className='size-2.5' />
            {filterTag}
            <X className='size-2.5' />
          </Badge>
        )}
      </div>

      {/* Tag cloud */}
      {allTags.length > 0 && !filterTag && (
        <div className='flex flex-wrap gap-1.5'>
          {allTags.map((tag) => (
            <button
              key={tag}
              onClick={() => setFilterTag(tag)}
              className='text-[11px] px-2 py-0.5 rounded-full border border-border hover:border-primary hover:text-primary transition-colors text-muted-foreground'
            >
              {tag}
            </button>
          ))}
        </div>
      )}

      {/* Content */}
      {loading ? (
        <p className='text-sm text-muted-foreground'>{t('common.loading')}</p>
      ) : notes.length === 0 ? (
        <div className='flex flex-col items-center justify-center py-20 text-center gap-3'>
          <StickyNote className='size-12 text-muted-foreground/30' />
          <p className='text-sm text-muted-foreground'>
            {search || filterTag ? t('notas.no_results_search') : t('notas.no_results')}
          </p>
          {!search && !filterTag && (
            <p className='text-xs text-muted-foreground max-w-sm'>{t('notas.empty_hint')}</p>
          )}
        </div>
      ) : (
        <div className='space-y-6'>
          {pinned.length > 0 && !showPinned && (
            <div className='space-y-2'>
              <h2 className='text-xs font-semibold uppercase tracking-widest text-muted-foreground flex items-center gap-1.5'>
                <Pin className='size-3 fill-current' />
                {t('notas.pinned')}
              </h2>
              {renderGrid(pinned)}
            </div>
          )}

          {!showPinned && (
            <div className='space-y-2'>
              {pinned.length > 0 && (
                <h2 className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>
                  {t('notas.all')}
                </h2>
              )}
              {unpinned.length > 0 && renderGrid(unpinned)}
            </div>
          )}

          {showPinned && renderGrid(pinned)}
        </div>
      )}

      {/* Note viewer (read-only) */}
      <NoteViewer
        note={viewing}
        onClose={() => setViewing(null)}
        onEdit={(note) => { setViewing(null); openEdit(note) }}
        onCopy={handleCopy}
      />

      {/* Note modal (edit / create) */}
      <NoteModal
        open={modalOpen}
        initial={editing}
        engagements={engagements}
        onClose={() => setModalOpen(false)}
        onSave={handleSave}
      />

      {/* Delete confirmation */}
      <AlertDialog open={!!toDelete} onOpenChange={(v) => !v && setToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('common.delete')}</AlertDialogTitle>
            <AlertDialogDescription>{t('notas.delete_confirm')}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} className='bg-destructive text-destructive-foreground hover:bg-destructive/90'>
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
