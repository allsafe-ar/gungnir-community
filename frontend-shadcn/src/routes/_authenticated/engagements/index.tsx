import { createFileRoute } from '@tanstack/react-router'
import { Engagements } from '@/features/engagements'

export const Route = createFileRoute('/_authenticated/engagements/')({
  component: Engagements,
})
