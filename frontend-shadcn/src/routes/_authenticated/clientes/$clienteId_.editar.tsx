import { createFileRoute } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { ClienteForm } from '@/features/clientes/components/cliente-form'
import { apiFetch } from '@/lib/api'

export const Route = createFileRoute('/_authenticated/clientes/$clienteId_/editar')({
  component: EditarCliente,
})

function EditarCliente() {
  const { clienteId } = Route.useParams()
  const [initial, setInitial] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    apiFetch<Record<string, unknown>>(`/clientes/${clienteId}`)
      .then(d => setInitial(d))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [clienteId])

  if (loading) return (
    <div className='flex h-64 items-center justify-center'>
      <div className='h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent' />
    </div>
  )

  return <ClienteForm initial={initial ?? undefined} clienteId={clienteId} />
}
