import { createFileRoute } from '@tanstack/react-router'
import { Papers } from '@/features/papers'

export const Route = createFileRoute('/_authenticated/papers/')({
  component: Papers,
})
