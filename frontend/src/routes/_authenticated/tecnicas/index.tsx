import { createFileRoute } from '@tanstack/react-router'
import { Tecnicas } from '@/features/tecnicas'

export const Route = createFileRoute('/_authenticated/tecnicas/')({
  validateSearch: (s: Record<string, unknown>) => ({
    mitre: typeof s.mitre === 'string' ? s.mitre : '',
  }),
  component: () => {
    const { mitre } = Route.useSearch()
    return <Tecnicas initialMitre={mitre} />
  },
})
