import { createFileRoute } from '@tanstack/react-router'
import { Scripts } from '@/features/scripts'

export const Route = createFileRoute('/_authenticated/scripts/')({
  component: Scripts,
})
