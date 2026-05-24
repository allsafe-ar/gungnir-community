import { createFileRoute } from '@tanstack/react-router'
import { ClienteForm } from '@/features/clientes/components/cliente-form'

export const Route = createFileRoute('/_authenticated/clientes/nuevo')({
  component: () => <ClienteForm />,
})
