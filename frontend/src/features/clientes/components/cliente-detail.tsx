import { useEffect, useState } from 'react'
import { Link, useNavigate } from '@tanstack/react-router'
import { Building2, ClipboardList, Edit, Plus, Shield, ArrowLeft, CheckCircle2, XCircle, Trash2 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { apiFetch } from '@/lib/api'
import { toast } from 'sonner'
import { useAuthStore } from '@/stores/auth-store'
import { TYPE_LABEL, STATUS_LABEL, STATUS_VARIANT } from '@/features/engagements'

interface Cliente {
  id: string
  name: string
  industry: string
  size: string
  country: string
  contact_name: string
  contact_email: string
  contact_phone: string
  exec_contact_name: string
  exec_contact_email: string
  nda_signed: boolean
  notes: string
  engagements: {
    id: string; title: string; type: string; status: string
    current_phase: string; start_date: string; end_date: string
  }[]
}

const SIZE_LABEL: Record<string, string> = {
  small: 'Pequeña', medium: 'Mediana', large: 'Grande', enterprise: 'Corporativa',
}

export function ClienteDetail({ clienteId }: { clienteId: string }) {
  const navigate = useNavigate()
  const { auth } = useAuthStore()
  const isAdmin = auth.user?.role === 'admin'
  const [cliente, setCliente] = useState<Cliente | null>(null)
  const [loading, setLoading] = useState(true)
  const [deleting, setDeleting] = useState(false)

  const handleDelete = async () => {
    if (!confirm(`¿Eliminar el cliente "${cliente?.name}"? Esta acción no se puede deshacer.`)) return
    setDeleting(true)
    try {
      await apiFetch(`/clientes/${clienteId}`, { method: 'DELETE' })
      toast.success('Cliente eliminado')
      navigate({ to: '/clientes' })
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Error al eliminar')
      setDeleting(false)
    }
  }

  useEffect(() => {
    apiFetch<Cliente>(`/clientes/${clienteId}`)
      .then(d => setCliente(d as Cliente))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [clienteId])

  if (loading) return <div className='flex h-64 items-center justify-center'><div className='h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent' /></div>
  if (!cliente) return <div className='py-16 text-center text-muted-foreground'>Cliente no encontrado.</div>

  return (
    <div className='space-y-6 max-w-3xl'>
      <div className='flex items-center justify-between'>
        <div className='flex items-center gap-3'>
          <Button variant='ghost' size='sm' className='text-muted-foreground -ml-2'
            onClick={() => navigate({ to: '/clientes' })}>
            <ArrowLeft className='mr-1 size-3' /> Clientes
          </Button>
        </div>
        <div className='flex items-center gap-2'>
          <Button variant='outline' size='sm' asChild>
            <Link to='/clientes/$clienteId/editar' params={{ clienteId }}>
              <Edit className='mr-2 size-3.5' /> Editar
            </Link>
          </Button>
          {isAdmin && (
            <Button
              variant='outline'
              size='sm'
              onClick={handleDelete}
              disabled={deleting}
              className='text-destructive hover:text-destructive border-destructive/30 hover:bg-destructive/10'
            >
              <Trash2 className='mr-2 size-3.5' />
              {deleting ? 'Eliminando...' : 'Eliminar'}
            </Button>
          )}
        </div>
      </div>

      <div className='flex items-start gap-4'>
        <div className='flex size-12 items-center justify-center rounded-lg bg-primary/10 shrink-0'>
          <Building2 className='size-6 text-primary' />
        </div>
        <div>
          <h1 className='text-2xl font-bold leading-tight'>{cliente.name}</h1>
          <div className='flex flex-wrap items-center gap-2 mt-1'>
            {cliente.industry && <span className='text-sm text-muted-foreground'>{cliente.industry}</span>}
            {cliente.size && <Badge variant='outline'>{SIZE_LABEL[cliente.size] ?? cliente.size}</Badge>}
            {cliente.country && <span className='text-sm text-muted-foreground'>{cliente.country}</span>}
            <div className='flex items-center gap-1'>
              {cliente.nda_signed
                ? <><CheckCircle2 className='size-3.5 text-green-500' /><span className='text-xs text-green-500'>NDA firmado</span></>
                : <><XCircle className='size-3.5 text-muted-foreground' /><span className='text-xs text-muted-foreground'>Sin NDA</span></>}
            </div>
          </div>
        </div>
      </div>

      <div className='grid gap-4 sm:grid-cols-2'>
        {cliente.contact_name && (
          <Card>
            <CardHeader className='pb-2'>
              <CardTitle className='text-xs uppercase tracking-wide text-muted-foreground'>Contacto técnico</CardTitle>
            </CardHeader>
            <CardContent className='space-y-1 text-sm'>
              <p className='font-medium'>{cliente.contact_name}</p>
              {cliente.contact_email && <p className='text-muted-foreground'>{cliente.contact_email}</p>}
              {cliente.contact_phone && <p className='text-muted-foreground'>{cliente.contact_phone}</p>}
            </CardContent>
          </Card>
        )}
        {cliente.exec_contact_name && (
          <Card>
            <CardHeader className='pb-2'>
              <CardTitle className='text-xs uppercase tracking-wide text-muted-foreground'>Contacto ejecutivo</CardTitle>
            </CardHeader>
            <CardContent className='space-y-1 text-sm'>
              <p className='font-medium'>{cliente.exec_contact_name}</p>
              {cliente.exec_contact_email && <p className='text-muted-foreground'>{cliente.exec_contact_email}</p>}
            </CardContent>
          </Card>
        )}
      </div>

      {cliente.notes && (
        <Card>
          <CardHeader className='pb-2'><CardTitle className='text-xs uppercase tracking-wide text-muted-foreground'>Notas</CardTitle></CardHeader>
          <CardContent><p className='text-sm whitespace-pre-wrap'>{cliente.notes}</p></CardContent>
        </Card>
      )}

      <Separator />

      <div className='flex items-center justify-between'>
        <h2 className='font-semibold flex items-center gap-2'>
          <ClipboardList className='size-4' />
          Engagements ({cliente.engagements?.length ?? 0})
        </h2>
        <Button size='sm' asChild>
          <Link to='/engagements/nuevo' search={{ client_id: clienteId }}>
            <Plus className='mr-1.5 size-3.5' /> Nuevo
          </Link>
        </Button>
      </div>

      {!cliente.engagements?.length ? (
        <div className='flex flex-col items-center gap-2 py-10 text-center'>
          <Shield className='size-10 text-muted-foreground/30' />
          <p className='text-sm text-muted-foreground'>No hay engagements para este cliente.</p>
        </div>
      ) : (
        <div className='space-y-2'>
          {cliente.engagements.map(eng => (
            <Link key={eng.id} to='/engagements/$engagementId' params={{ engagementId: eng.id }}
              className='flex items-center gap-3 rounded-lg border border-border px-4 py-3 hover:bg-accent transition-colors'>
              <div className='flex-1 min-w-0'>
                <p className='font-medium text-sm truncate'>{eng.title}</p>
                <p className='text-xs text-muted-foreground'>{TYPE_LABEL[eng.type] ?? eng.type}</p>
              </div>
              <Badge variant={STATUS_VARIANT[eng.status] ?? 'outline'}>{STATUS_LABEL[eng.status] ?? eng.status}</Badge>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
