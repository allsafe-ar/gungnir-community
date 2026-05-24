import { createFileRoute } from '@tanstack/react-router'
import { EngagementForm } from '@/features/engagements/components/engagement-form'

export const Route = createFileRoute('/_authenticated/engagements/nuevo')({
  validateSearch: (s: Record<string, unknown>) => ({
    client_id: typeof s.client_id === 'string' ? s.client_id : '',
  }),
  component: () => <EngagementForm />,
})
