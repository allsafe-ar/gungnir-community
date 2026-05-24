import { createFileRoute } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { EngagementForm } from '@/features/engagements/components/engagement-form'
import { apiFetch } from '@/lib/api'

export const Route = createFileRoute('/_authenticated/engagements/$engagementId_/editar')({
  component: EditarEngagement,
})

function EditarEngagement() {
  const { engagementId } = Route.useParams()
  const [initial, setInitial] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    apiFetch<Record<string, unknown>>(`/engagements/${engagementId}`)
      .then(d => setInitial(d))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [engagementId])

  if (loading) return (
    <div className='flex h-64 items-center justify-center'>
      <div className='h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent' />
    </div>
  )

  return <EngagementForm initial={initial ?? undefined} engagementId={engagementId} />
}
