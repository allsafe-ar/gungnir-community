import { createFileRoute, redirect } from '@tanstack/react-router'
import { AuthenticatedLayout } from '@/components/layout/authenticated-layout'
import { useAuthStore, type ArpUser } from '@/stores/auth-store'
import { apiFetch } from '@/lib/api'

export const Route = createFileRoute('/_authenticated')({
  beforeLoad: ({ location }) => {
    const { auth } = useAuthStore.getState()
    if (!auth.accessToken) {
      throw redirect({ to: '/sign-in', search: { redirect: location.href } })
    }
  },
  loader: async () => {
    try {
      const user = await apiFetch<ArpUser>('/auth/me')
      useAuthStore.getState().auth.setUser(user)
    } catch {
      useAuthStore.getState().auth.reset()
      throw redirect({ to: '/sign-in' })
    }
  },
  component: AuthenticatedLayout,
})
