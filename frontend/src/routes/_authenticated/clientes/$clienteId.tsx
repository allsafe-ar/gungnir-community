import { createFileRoute } from '@tanstack/react-router'
import { ClienteDetail } from '@/features/clientes/components/cliente-detail'

export const Route = createFileRoute('/_authenticated/clientes/$clienteId')({
  component: () => {
    const { clienteId } = Route.useParams()
    return <ClienteDetail clienteId={clienteId} />
  },
})
