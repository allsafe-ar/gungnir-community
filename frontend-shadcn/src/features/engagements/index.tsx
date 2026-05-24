import { useEffect, useState } from 'react'
import { Link } from '@tanstack/react-router'
import { ClipboardList, Plus, Search, Filter } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { apiFetch } from '@/lib/api'

export interface Engagement {
  id: string
  title: string
  codename: string
  client_name: string
  client_id: string
  type: string
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

export const TYPE_LABEL: Record<string, string> = {
  external_pt:   'Externo',
  internal_pt:   'Interno',
  web_app:       'Web App',
  api:           'API',
  mobile:        'Mobile',
  red_team:      'Red Team',
  social_eng:    'Ingeniería Social',
  physical:      'Físico',
}
export const STATUS_LABEL: Record<string, string> = {
  planned:      'Planificado',
  in_progress:  'En curso',
  reporting:    'Reportando',
  qa:           'QA',
  delivered:    'Entregado',
  archived:     'Archivado',
}
export const PHASE_LABEL: Record<string, string> = {
  planning:          'Planificación',
  recon:             'Reconocimiento',
  scanning:          'Escaneo',
  exploitation:      'Explotación',
  post_exploitation: 'Post-explotación',
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
  const [engagements, setEngagements] = useState<Engagement[]>([])
  const [search, setSearch] = useState('')
  const [filterStatus, setFilterStatus] = useState('all')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    apiFetch('/engagements')
      .then((d: Engagement[]) => setEngagements(d))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const filtered = engagements.filter((e) => {
    const matchSearch =
      e.title.toLowerCase().includes(search.toLowerCase()) ||
      e.client_name.toLowerCase().includes(search.toLowerCase()) ||
      e.codename?.toLowerCase().includes(search.toLowerCase())
    const matchStatus = filterStatus === 'all' || e.status === filterStatus
    return matchSearch && matchStatus
  })

  return (
    <div className='space-y-6'>
      <div className='flex items-center justify-between'>
        <div>
          <h1 className='text-2xl font-bold tracking-tight'>Engagements</h1>
          <p className='text-sm text-muted-foreground'>{engagements.length} engagements registrados</p>
        </div>
        <Button asChild>
          <Link to='/engagements/nuevo'>
            <Plus className='mr-2 size-4' />
            Nuevo Engagement
          </Link>
        </Button>
      </div>

      <div className='flex gap-3'>
        <div className='relative flex-1'>
          <Search className='absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground' />
          <Input
            placeholder='Buscar por título, cliente o codename...'
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
            <SelectItem value='all'>Todos los estados</SelectItem>
            {Object.entries(STATUS_LABEL).map(([v, l]) => (
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
            {search || filterStatus !== 'all' ? 'Sin resultados.' : 'No hay engagements aún.'}
          </p>
        </div>
      ) : (
        <div className='space-y-2'>
          {filtered.map((eng) => (
            <Link
              key={eng.id}
              to='/engagements/$engagementId'
              params={{ engagementId: eng.id }}
              className='block'
            >
              <div className='flex items-center gap-4 rounded-lg border border-border px-4 py-3 hover:bg-accent transition-colors'>
                <div className='min-w-0 flex-1'>
                  <div className='flex items-center gap-2'>
                    <p className='font-medium text-sm truncate'>{eng.title}</p>
                    {eng.codename && (
                      <span className='text-xs text-muted-foreground font-mono'>({eng.codename})</span>
                    )}
                  </div>
                  <p className='text-xs text-muted-foreground truncate'>
                    {eng.client_name} · {TYPE_LABEL[eng.type] ?? eng.type}
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
                      {PHASE_LABEL[eng.current_phase] ?? eng.current_phase}
                    </span>
                  )}
                  <Badge variant={STATUS_VARIANT[eng.status] ?? 'outline'}>
                    {STATUS_LABEL[eng.status] ?? eng.status}
                  </Badge>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
