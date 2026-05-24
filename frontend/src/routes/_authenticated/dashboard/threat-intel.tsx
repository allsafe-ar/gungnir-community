import { createFileRoute } from '@tanstack/react-router'
import { ThreatIntelDashboard } from '@/features/dashboard/threat-intel'

export const Route = createFileRoute('/_authenticated/dashboard/threat-intel')({
  component: ThreatIntelDashboard,
})
