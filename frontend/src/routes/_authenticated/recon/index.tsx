import { createFileRoute } from '@tanstack/react-router'
import { ReconPage } from '@/features/recon'

export const Route = createFileRoute('/_authenticated/recon/')({
  component: ReconPage,
})
