import { createFileRoute } from '@tanstack/react-router'
import { Writeups } from '@/features/writeups'

export const Route = createFileRoute('/_authenticated/writeups/')({
  component: Writeups,
})
