import { createFileRoute } from '@tanstack/react-router'
import { Comandos } from '@/features/comandos'

export const Route = createFileRoute('/_authenticated/comandos/')({
  validateSearch: (s: Record<string, unknown>) => ({
    herramienta: typeof s.herramienta === 'string' ? s.herramienta : '',
  }),
  component: () => {
    const { herramienta } = Route.useSearch()
    return <Comandos initialTool={herramienta} />
  },
})
