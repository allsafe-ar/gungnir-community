import { createFileRoute } from '@tanstack/react-router'
import { EngagementForm } from '@/features/engagements/components/engagement-form'

export const Route = createFileRoute('/_authenticated/engagements/nuevo')({
  // `client_id` es opcional: se llega aca con un cliente preseleccionado o sin ninguno.
  // Declararlo obligatorio obligaba a cada <Link> a mandar un search vacio, cuando el
  // formulario ya lo lee como opcional (search?.client_id ?? '').
  validateSearch: (s: Record<string, unknown>): { client_id?: string } => ({
    client_id: typeof s.client_id === 'string' ? s.client_id : undefined,
  }),
  component: () => <EngagementForm />,
})
