import { createFileRoute } from '@tanstack/react-router'
import { Vulnerabilidades } from '@/features/vulnerabilidades'

export const Route = createFileRoute('/_authenticated/vulnerabilidades/')({
  component: Vulnerabilidades,
})
