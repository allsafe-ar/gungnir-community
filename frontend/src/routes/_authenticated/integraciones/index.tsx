import { createFileRoute } from '@tanstack/react-router'
import { IntegracionesPage } from '@/features/integraciones'

export const Route = createFileRoute('/_authenticated/integraciones/')({
  component: IntegracionesPage,
})
