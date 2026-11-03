import { createFileRoute } from '@tanstack/react-router'
import { Activos } from '@/features/activos'

export const Route = createFileRoute('/_authenticated/activos/')({
  component: Activos,
})
