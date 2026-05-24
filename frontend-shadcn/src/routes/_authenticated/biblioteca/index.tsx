import { createFileRoute } from '@tanstack/react-router'
import { Biblioteca } from '@/features/biblioteca'

export const Route = createFileRoute('/_authenticated/biblioteca/')({
  component: Biblioteca,
})
