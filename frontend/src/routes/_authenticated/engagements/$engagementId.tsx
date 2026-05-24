import { createFileRoute } from '@tanstack/react-router'
import { EngagementWorkspace } from '@/features/engagements/components/engagement-workspace'

export const Route = createFileRoute('/_authenticated/engagements/$engagementId')({
  component: function EngagementPage() {
    const { engagementId } = Route.useParams()
    return <EngagementWorkspace engagementId={engagementId} />
  },
})
