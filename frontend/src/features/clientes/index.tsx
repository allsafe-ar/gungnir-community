import { useEffect, useState } from 'react'
import { Link } from '@tanstack/react-router'
import { Building2, Plus, Search, ClipboardList } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { apiFetch } from '@/lib/api'

interface Cliente {
  id: string
  name: string
  industry: string
  contact_name: string
  contact_email: string
  active_engagements: number
  total_engagements: number
  created_at: string
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export function Clientes() {
  const { t } = useTranslation()
  const [clientes, setClientes] = useState<Cliente[]>([])
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    apiFetch<Cliente[]>('/clientes')
      .then((d) => setClientes(d))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const filtered = clientes.filter(
    (c) =>
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      c.industry?.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className='space-y-6'>
      <div className='flex items-center justify-between gap-3 flex-wrap'>
        <div>
          <h1 className='text-2xl font-bold tracking-tight'>{t('client.title')}</h1>
          <p className='text-sm text-muted-foreground'>{t('client.subtitle', { count: clientes.length })}</p>
        </div>
        <Button asChild>
          <Link to='/clientes/nuevo'>
            <Plus className='mr-2 size-4' />
            {t('client.new')}
          </Link>
        </Button>
      </div>

      <div className='relative'>
        <Search className='absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground' />
        <Input
          placeholder={t('client.search_placeholder')}
          className='pl-9'
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {loading ? (
        <div className='flex h-40 items-center justify-center'>
          <div className='h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent' />
        </div>
      ) : filtered.length === 0 ? (
        <div className='flex flex-col items-center gap-3 py-16 text-center'>
          <Building2 className='size-12 text-muted-foreground/40' />
          <p className='text-sm text-muted-foreground'>
            {search ? t('client.no_search_results') : t('client.empty')}
          </p>
        </div>
      ) : (
        <div className='grid gap-3 md:grid-cols-2 xl:grid-cols-3'>
          {filtered.map((c) => (
            <Link
              key={c.id}
              to='/clientes/$clienteId'
              params={{ clienteId: c.id }}
              className='block'
            >
              <Card className='hover:border-primary/50 transition-colors cursor-pointer h-full'>
                <CardHeader className='pb-2'>
                  <div className='flex items-start justify-between gap-2'>
                    <CardTitle className='text-base leading-tight'>{c.name}</CardTitle>
                    {c.active_engagements > 0 && (
                      <Badge variant='default' className='text-xs shrink-0'>
                        {c.active_engagements} activo{c.active_engagements !== 1 ? 's' : ''}
                      </Badge>
                    )}
                  </div>
                  {c.industry && (
                    <p className='text-xs text-muted-foreground'>{c.industry}</p>
                  )}
                </CardHeader>
                <CardContent>
                  <div className='flex items-center gap-4 text-xs text-muted-foreground'>
                    <span className='flex items-center gap-1'>
                      <ClipboardList className='size-3' />
                      {c.total_engagements} engagement{c.total_engagements !== 1 ? 's' : ''}
                    </span>
                    {c.contact_name && <span className='truncate'>{c.contact_name}</span>}
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
