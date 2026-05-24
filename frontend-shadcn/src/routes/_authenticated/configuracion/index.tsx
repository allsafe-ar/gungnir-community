import { createFileRoute } from '@tanstack/react-router'
import { Configuracion } from '@/features/configuracion'

export const Route = createFileRoute('/_authenticated/configuracion/')({
  component: Configuracion,
})
