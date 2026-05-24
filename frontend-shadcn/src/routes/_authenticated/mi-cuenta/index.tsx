import { createFileRoute } from '@tanstack/react-router'
import { MiCuenta } from '@/features/mi-cuenta'

export const Route = createFileRoute('/_authenticated/mi-cuenta/')({
  component: MiCuenta,
})
