import { createFileRoute } from '@tanstack/react-router'
import { Reportes } from '@/features/reportes'

export const Route = createFileRoute('/_authenticated/reportes/')({
  component: Reportes,
})
