import { createFileRoute } from '@tanstack/react-router'
import { Notas } from '@/features/notas'

export const Route = createFileRoute('/_authenticated/notas/')({
  component: Notas,
})
