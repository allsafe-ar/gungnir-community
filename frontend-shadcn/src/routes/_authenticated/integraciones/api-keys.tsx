import { createFileRoute } from '@tanstack/react-router'
import { IntegracionesApiKeysPage } from '@/features/integraciones/api-keys'

export const Route = createFileRoute('/_authenticated/integraciones/api-keys')({
  component: IntegracionesApiKeysPage,
})
