import { createFileRoute } from '@tanstack/react-router'
import { Auditoria } from '@/features/auditoria'

export const Route = createFileRoute('/_authenticated/auditoria/')({
  component: Auditoria,
})
