import { useEffect, useState, useRef } from 'react'
import { Link, useNavigate } from '@tanstack/react-router'
import { ClipboardList, Plus, Search, Filter, Trash2, Upload, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel,
  AlertDialogContent, AlertDialogDescription, AlertDialogFooter,
  AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { toast } from 'sonner'
import { apiFetch, API_BASE } from '@/lib/api'
import { useTranslation } from 'react-i18next'

export interface Engagement {
  id: string
  title: string
  codename: string
  client_name: string
  client_id: string
  type: string
  mode: string
  methodology: string
  status: string
  current_phase: string
  start_date: string
  end_date: string
  findings_count: number
  critical_count: number
  lead_name: string
  updated_at: string
}

export function getTypeLabel(t: (k: string) => string): Record<string, string> {
  return {
    external_pt:   t('eng.type_external_pt'),
    internal_pt:   t('eng.type_internal_pt'),
    web_app:       t('eng.type_web_app'),
    api:           t('eng.type_api'),
    mobile:        t('eng.type_mobile'),
    red_team:      t('eng.type_red_team'),
    social_eng:    t('eng.type_social_eng'),
    physical:      t('eng.type_physical'),
  }
}

export function getStatusLabel(t: (k: string) => string): Record<string, string> {
  return {
    planned:      t('eng.status_planned'),
    in_progress:  t('eng.status_in_progress'),
    reporting:    t('eng.status_reporting'),
    qa:           t('eng.status_qa'),
    delivered:    t('eng.status_delivered'),
    archived:     t('eng.status_archived'),
  }
}

export function getPhaseLabel(t: (k: string) => string): Record<string, string> {
  return {
    planning:          t('phase.planning'),
    recon:             t('phase.recon'),
    scanning:          t('phase.scanning'),
    exploitation:      t('phase.exploitation'),
    post_exploitation: t('phase.post_exploitation'),
    reporting:         t('phase.reporting'),
  }
}

// Legacy static exports kept for backward compat
export const TYPE_LABEL: Record<string, string> = {
  external_pt:   'External PT',
  internal_pt:   'Internal PT',
  web_app:       'Web App',
  api:           'API',
  mobile:        'Mobile',
  red_team:      'Red Team',
  social_eng:    'Social Engineering',
  physical:      'Physical',
}
export const STATUS_LABEL: Record<string, string> = {
  planned:      'Planned',
  in_progress:  'In Progress',
  reporting:    'Reporting',
  qa:           'QA',
  delivered:    'Delivered',
  archived:     'Archived',
}
export const PHASE_LABEL: Record<string, string> = {
  planning:          'Planning',
  recon:             'Reconnaissance',
  scanning:          'Scanning',
  exploitation:      'Exploitation',
  post_exploitation: 'Post-exploitation',
  reporting:         'Reporting',
}
export const STATUS_VARIANT: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  planned:     'outline',
  in_progress: 'default',
  reporting:   'secondary',
  qa:          'secondary',
  delivered:   'outline',
  archived:    'outline',
}

export function Engagements() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [engagements, setEngagements] = useState<Engagement[]>([])
  const [search, setSearch] = useState('')
  const [filterStatus, setFilterStatus] = useState('all')
  const [loading, setLoading] = useState(true)

  // Delete confirmation
  const [deleteTarget, setDeleteTarget] = useState<Engagement | null>(null)
  const [deleting, setDeleting] = useState(false)

  // Import
  const importRef = useRef<HTMLInputElement>(null)
  const [importing, setImporting] = useState(false)

  const typeLabel  = getTypeLabel(t)
  const statusLabel = getStatusLabel(t)
  const phaseLabel  = getPhaseLabel(t)

  useEffect(() => {
    apiFetch<Engagement[]>('/engagements')
      .then((d) => setEngagements(d))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const handleImport = async (file: File) => {
    if (!file.name.endsWith('.zip')) { toast.error(t('engs.import_zip_error')); return }
    setImporting(true)
    const token = localStorage.getItem('gungnir_token')
    const fd = new FormData()
    fd.append('file', file)
    try {
      const res = await fetch(`${API_BASE}/engagements/import`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: fd,
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
      toast.success(`Engagement importado: ${data.engagement.title}`)
      navigate({ to: '/engagements/$engagementId', params: { engagementId: data.engagement.id } })
    } catch (e: any) {
      toast.error(e.message ?? t('engs.import_error'))
    } finally {
      setImporting(false)
      if (importRef.current) importRef.current.value = ''
    }
  }

  const filtered = engagements.filter((eng) => {
    const matchSearch =
      eng.title.toLowerCase().includes(search.toLowerCase()) ||
      eng.client_name.toLowerCase().includes(search.toLowerCase()) ||
      eng.codename?.toLowerCase().includes(search.toLowerCase())
    const matchStatus = filterStatus === 'all' || eng.status === filterStatus
    return matchSearch && matchStatus
  })

  const handleDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await apiFetch(`/engagements/${deleteTarget.id}`, { method: 'DELETE' })
      setEngagements(prev => prev.filter(eng => eng.id !== deleteTarget.id))
      toast.success(t('eng.deleted'))
      setDeleteTarget(null)
    } catch (e: any) {
      toast.error(e.message ?? t('eng.error_delete'))
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className='space-y-6'>
      <div className='flex items-center justify-between'>
        <div>
          <h1 className='text-2xl font-bold tracking-tight'>{t('engs.title')}</h1>
          <p className='text-sm text-muted-foreground'>{t('engs.subtitle', { count: engagements.length })}</p>
        </div>
        <div className='flex gap-2'>
          <input ref={importRef} type='file' accept='.zip' className='hidden'
            onChange={e => { const f = e.target.files?.[0]; if (f) handleImport(f) }} />
          <Button variant='outline' onClick={() => importRef.current?.click()} disabled={importing}>
            {importing
              ? <><Loader2 className='mr-2 size-4 animate-spin' />{t('engs.importing')}</>
              : <><Upload className='mr-2 size-4' />{t('engs.import')}</>}
          </Button>
          <Button asChild>
            <Link to='/engagements/nuevo'>
              <Plus className='mr-2 size-4' />
              {t('engs.new')}
            </Link>
          </Button>
        </div>
      </div>

      <div className='flex gap-3'>
        <div className='relative flex-1'>
          <Search className='absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground' />
          <Input
            placeholder={t('engs.search_placeholder')}
            className='pl-9'
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className='w-44'>
            <Filter className='mr-2 size-4' />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value='all'>{t('engs.all_statuses')}</SelectItem>
            {Object.entries(statusLabel).map(([v, l]) => (
              <SelectItem key={v} value={v}>{l}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {loading ? (
        <div className='flex h-40 items-center justify-center'>
          <div className='h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent' />
        </div>
      ) : filtered.length === 0 ? (
        <div className='flex flex-col items-center gap-3 py-16 text-center'>
          <ClipboardList className='size-12 text-muted-foreground/40' />
          <p className='text-sm text-muted-foreground'>
            {search || filterStatus !== 'all' ? t('common.no_results') : t('engs.empty')}
          </p>
        </div>
      ) : (
        <div className='space-y-2'>
          {filtered.map((eng) => (
            <div key={eng.id} className='group relative'>
              <Link
                to='/engagements/$engagementId'
                params={{ engagementId: eng.id }}
                className='block'
              >
                <div className='flex items-center gap-4 rounded-lg border border-border px-4 py-3 hover:bg-accent transition-colors pr-12'>
                  <div className='min-w-0 flex-1'>
                    <div className='flex items-center gap-2'>
                      <p className='font-medium text-sm truncate'>{eng.title}</p>
                      {eng.codename && (
                        <span className='text-xs text-muted-foreground font-mono'>({eng.codename})</span>
                      )}
                    </div>
                    <p className='text-xs text-muted-foreground truncate'>
                      {eng.client_name} · {typeLabel[eng.type] ?? eng.type}
                    </p>
                  </div>
                  <div className='flex items-center gap-3 shrink-0'>
                    {eng.critical_count > 0 && (
                      <Badge variant='destructive' className='text-xs'>
                        {eng.critical_count} crít.
                      </Badge>
                    )}
                    {eng.current_phase && (
                      <span className='text-xs text-muted-foreground hidden md:block'>
                        {phaseLabel[eng.current_phase] ?? eng.current_phase}
                      </span>
                    )}
                    <Badge variant={STATUS_VARIANT[eng.status] ?? 'outline'}>
                      {statusLabel[eng.status] ?? eng.status}
                    </Badge>
                  </div>
                </div>
              </Link>

              {/* Delete button - visible on hover, absolute over the card */}
              <button
                onClick={(e) => { e.preventDefault(); e.stopPropagation(); setDeleteTarget(eng) }}
                className='absolute right-3 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity p-1.5 rounded hover:bg-destructive/15 text-muted-foreground hover:text-destructive'
                title={t('eng.delete_tooltip')}
              >
                <Trash2 className='size-3.5' />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Confirmation dialog */}
      <AlertDialog open={!!deleteTarget} onOpenChange={open => { if (!open) setDeleteTarget(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('eng.delete_title')}</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className='space-y-2'>
                <p>
                  {t('eng.delete_desc1')}{' '}
                  <span className='font-semibold text-foreground'>"{deleteTarget?.title}"</span>
                  {deleteTarget?.client_name && (
                    <span className='text-muted-foreground'> - {deleteTarget.client_name}</span>
                  )}
                  .
                </p>
                <p>
                  {t('eng.delete_desc2')}{' '}
                  <span className='text-destructive font-medium'>{t('eng.irreversible')}</span>
                </p>
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              disabled={deleting}
              className='bg-destructive hover:bg-destructive/90 text-destructive-foreground'
            >
              {deleting ? t('eng.deleting') : t('eng.confirm_delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
