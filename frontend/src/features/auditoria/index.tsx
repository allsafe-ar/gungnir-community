/**
 * Auditoría — Log de actividad del sistema.
 * Tabla plana estándar AllSafe: FECHA | USUARIO | ACCIÓN | DETALLE
 * Solo visible para admin y lead.
 */

import { useQuery } from '@tanstack/react-query'
import { ClipboardList } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'

interface AuditRow {
  id: string
  user_id: string | null
  username: string | null
  action: string
  entity: string | null
  entity_id: string | null
  detail: string | null
  ip: string | null
  created_at: string
}

interface AuditResponse {
  rows: AuditRow[]
  total: number
}

// ─── Color por tipo de acción (estándar AllSafe) ──────────────────────────────
const ACTION_DISPLAY: Record<string, { label: string; color: string }> = {
  // Auth
  login:            { label: 'Inicio de sesión',              color: 'text-green-400' },
  login_2fa:        { label: 'login_2fa',                     color: 'text-cyan-400' },
  // Usuarios
  create_user:      { label: 'Usuario creado',                color: 'text-blue-400' },
  update_user:      { label: 'Usuario actualizado',           color: 'text-blue-400' },
  delete_user:      { label: 'Usuario eliminado',             color: 'text-red-400' },
  toggle_user:      { label: 'Usuario habilitado/bloqueado',  color: 'text-amber-400' },
  // Contraseña
  change_password:  { label: 'Cambio de contraseña',         color: 'text-orange-400' },
  // TOTP
  totp_enabled:     { label: 'totp_enabled',                  color: 'text-cyan-400' },
  totp_disabled:    { label: '2FA desactivado',               color: 'text-cyan-400' },
  reset_totp:       { label: '2FA reseteado',                 color: 'text-amber-400' },
  // Configuración
  update_settings:  { label: 'Configuración actualizada',    color: 'text-yellow-400' },
}

function actionDisplay(action: string) {
  return ACTION_DISPLAY[action] ?? { label: action, color: 'text-muted-foreground' }
}

export function Auditoria() {
  const { data, isLoading } = useQuery<AuditResponse>({
    queryKey: ['gungnir-auditoria'],
    queryFn: () => apiFetch<AuditResponse>('/auditoria?limit=500'),
    staleTime: 30_000,
  })

  const rows = data?.rows ?? []

  return (
    <div className='space-y-5'>
      {/* Header */}
      <div>
        <h1 className='text-xl font-bold tracking-tight flex items-center gap-2'>
          <ClipboardList className='size-5 text-primary' />
          Auditoría
        </h1>
        <p className='text-sm text-muted-foreground mt-0.5'>
          Registro de actividad del sistema — {data?.total ?? 0} entradas
        </p>
      </div>

      {/* Table */}
      <div className='rounded-lg border border-border overflow-hidden'>
        {isLoading ? (
          <div className='flex justify-center py-12'>
            <div className='h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent' />
          </div>
        ) : rows.length === 0 ? (
          <div className='flex flex-col items-center gap-2 py-12 text-center'>
            <ClipboardList className='size-8 text-muted-foreground/30' />
            <p className='text-sm text-muted-foreground'>No hay eventos registrados aún.</p>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className='border-border hover:bg-transparent'>
                <TableHead className='text-[11px] font-semibold uppercase tracking-wider text-muted-foreground w-52'>
                  Fecha
                </TableHead>
                <TableHead className='text-[11px] font-semibold uppercase tracking-wider text-muted-foreground w-32'>
                  Usuario
                </TableHead>
                <TableHead className='text-[11px] font-semibold uppercase tracking-wider text-muted-foreground w-56'>
                  Acción
                </TableHead>
                <TableHead className='text-[11px] font-semibold uppercase tracking-wider text-muted-foreground'>
                  Detalle
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map(row => {
                const { label, color } = actionDisplay(row.action)
                return (
                  <TableRow key={row.id} className='border-border'>
                    <TableCell className='text-sm text-muted-foreground tabular-nums'>
                      {new Date(row.created_at).toLocaleString('es-AR')}
                    </TableCell>
                    <TableCell className='text-sm font-medium'>
                      {row.username ?? '—'}
                    </TableCell>
                    <TableCell className={`text-sm font-medium ${color}`}>
                      {label}
                    </TableCell>
                    <TableCell className='text-sm text-muted-foreground'>
                      {row.detail ?? (row.ip ? `desde ${row.ip}` : '—')}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  )
}
