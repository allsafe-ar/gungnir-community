import { createFileRoute } from '@tanstack/react-router'
import { Usuarios } from '@/features/usuarios'

export const Route = createFileRoute('/_authenticated/usuarios/')({
  component: Usuarios,
})
