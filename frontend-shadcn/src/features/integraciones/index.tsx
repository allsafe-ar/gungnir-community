import { Navigate } from '@tanstack/react-router'

// In Community Edition, /integraciones redirects to /integraciones/api-keys.
// Live scanner integrations (Nessus, OpenVAS) are available in Gungnir Pro.
export function IntegracionesPage() {
  return <Navigate to='/integraciones/api-keys' replace />
}
