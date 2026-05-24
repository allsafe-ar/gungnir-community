/**
 * Usuarios — Gestión de usuarios del sistema (solo admins).
 * Estándar AllSafe: mismas columnas y colores que Heimdall, Gjallarhorn, etc.
 */

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Pencil, Trash2, ShieldOff, ToggleLeft, ToggleRight,
  KeyRound, ShieldCheck,
} from 'lucide-react'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { cn } from '@/lib/utils'

// ─── Tipos ────────────────────────────────────────────────────────────────────
interface User {
  id: string
  username: string
  email: string
  full_name: string
  role: 'admin' | 'auditor' | 'pentester' | 'lector'
  is_active: number
  totp_enabled: number
  last_login?: string
  created_at: string
}

type DialogMode = 'create' | 'edit'

// ─── Constantes ───────────────────────────────────────────────────────────────
const ROLES: User['role'][] = ['admin', 'auditor', 'pentester', 'lector']
const ROLE_LABELS: Record<User['role'], string> = {
  admin:     'Admin',
  auditor:   'Auditor',
  pentester: 'Pentester',
  lector:    'Lector',
}

const EMPTY_FORM = { username: '', email: '', full_name: '', role: 'pentester' as User['role'], password: '' }

// ─── Componente ───────────────────────────────────────────────────────────────
export function Usuarios() {
  const qc = useQueryClient()
  const { auth } = useAuthStore()
  const currentId = auth.user?.id

  const [open, setOpen]       = useState(false)
  const [mode, setMode]       = useState<DialogMode>('create')
  const [editing, setEditing] = useState<User | null>(null)
  const [form, setForm]       = useState({ ...EMPTY_FORM })

  // ── Queries ──────────────────────────────────────────────────────────────────
  const { data: users = [], isLoading } = useQuery<User[]>({
    queryKey: ['gungnir-users'],
    queryFn: () => apiFetch<User[]>('/usuarios'),
  })

  // ── Mutations ─────────────────────────────────────────────────────────────────
  const saveMutation = useMutation({
    mutationFn: () => {
      if (mode === 'create') {
        return apiFetch('/usuarios', { method: 'POST', body: JSON.stringify({
          username: form.username, email: form.email,
          full_name: form.full_name, role: form.role, password: form.password,
        }) })
      }
      return apiFetch(`/usuarios/${editing!.id}`, {
        method: 'PUT',
        body: JSON.stringify({
          full_name: form.full_name, email: form.email, role: form.role,
          ...(form.password ? { password: form.password } : {}),
        }),
      })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['gungnir-users'] })
      setOpen(false)
      toast.success(mode === 'create' ? 'Usuario creado' : 'Usuario actualizado')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/usuarios/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['gungnir-users'] })
      toast.success('Usuario eliminado')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/usuarios/${id}/toggle`, { method: 'PUT' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['gungnir-users'] }),
    onError: (e: Error) => toast.error(e.message),
  })

  const resetTotpMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/usuarios/${id}/totp`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['gungnir-users'] })
      toast.success('2FA desactivado para el usuario')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  // ── Handlers ──────────────────────────────────────────────────────────────────
  function openCreate() {
    setMode('create'); setForm({ ...EMPTY_FORM }); setEditing(null); setOpen(true)
  }

  function openEdit(user: User) {
    setMode('edit')
    setForm({ username: user.username, email: user.email, full_name: user.full_name, role: user.role, password: '' })
    setEditing(user)
    setOpen(true)
  }

  function handleDelete(user: User) {
    if (!confirm(`¿Eliminar al usuario "${user.username}"? Esta acción no se puede deshacer.`)) return
    deleteMutation.mutate(user.id)
  }

  function handleResetTotp(user: User) {
    if (!confirm(`¿Desactivar el 2FA de "${user.username}"?`)) return
    resetTotpMutation.mutate(user.id)
  }

  const isBusy = saveMutation.isPending || deleteMutation.isPending || toggleMutation.isPending

  return (
    <div className='space-y-6'>
      {/* Header — estándar AllSafe */}
      <div className='flex items-center justify-between'>
        <div>
          <h1 className='text-xl font-bold'>Usuarios</h1>
          <p className='text-sm text-muted-foreground'>Gestión de acceso al sistema Gungnir</p>
        </div>
        <Button size='sm' onClick={openCreate} disabled={isBusy} className='gap-1.5'>
          <Plus className='h-3.5 w-3.5' />
          Nuevo usuario
        </Button>
      </div>

      {/* Table */}
      <div className='rounded-lg border border-border overflow-hidden'>
        {isLoading ? (
          <div className='flex justify-center py-12'>
            <div className='h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent' />
          </div>
        ) : users.length === 0 ? (
          <div className='flex flex-col items-center py-16 text-center gap-2 text-muted-foreground'>
            <p className='text-sm'>Sin usuarios registrados</p>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className='border-border hover:bg-transparent'>
                <TableHead className='text-xs font-semibold'>Nombre</TableHead>
                <TableHead className='text-xs font-semibold'>Usuario</TableHead>
                <TableHead className='text-xs font-semibold'>Rol</TableHead>
                <TableHead className='text-xs font-semibold'>2FA</TableHead>
                <TableHead className='text-xs font-semibold'>Estado</TableHead>
                <TableHead className='text-xs font-semibold'>Creado</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map(user => {
                const isSelf = user.id === currentId
                return (
                  <TableRow key={user.id} className='border-border'>
                    {/* Nombre */}
                    <TableCell className='font-medium text-sm'>
                      {user.full_name || user.username}
                    </TableCell>

                    {/* Usuario */}
                    <TableCell className='font-mono text-sm text-muted-foreground'>
                      {user.username}
                    </TableCell>

                    {/* Rol — badge outline gris, sin colores por rol */}
                    <TableCell>
                      <span className='rounded border border-border px-1.5 py-0.5 text-[11px] font-medium text-foreground/80'>
                        {ROLE_LABELS[user.role] ?? user.role}
                      </span>
                    </TableCell>

                    {/* 2FA — ícono */}
                    <TableCell>
                      {user.totp_enabled ? (
                        <ShieldCheck className='h-4 w-4 text-green-400' />
                      ) : (
                        <div className='flex items-center gap-1'>
                          <ShieldOff className='h-4 w-4 text-muted-foreground/40' />
                          <span className='text-xs text-muted-foreground/40'>—</span>
                        </div>
                      )}
                    </TableCell>

                    {/* Estado — verde / gris */}
                    <TableCell>
                      {user.is_active ? (
                        <span className='inline-flex items-center rounded-full bg-green-500/20 px-2 py-0.5 text-[11px] font-semibold text-green-400 ring-1 ring-green-500/30'>
                          Activo
                        </span>
                      ) : (
                        <span className='inline-flex items-center rounded-full bg-muted px-2 py-0.5 text-[11px] font-semibold text-muted-foreground'>
                          Inactivo
                        </span>
                      )}
                    </TableCell>

                    {/* Creado */}
                    <TableCell className='text-xs text-muted-foreground'>
                      {new Date(user.created_at).toLocaleDateString('es-AR')}
                    </TableCell>

                    {/* Acciones — solo para otros usuarios */}
                    <TableCell>
                      {!isSelf ? (
                        <div className='flex items-center justify-end gap-0.5'>
                          {/* Editar */}
                          <button
                            onClick={() => openEdit(user)}
                            title='Editar'
                            className='rounded p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors'
                          >
                            <Pencil className='h-3.5 w-3.5' />
                          </button>
                          {/* Toggle activo/inactivo */}
                          <button
                            onClick={() => toggleMutation.mutate(user.id)}
                            title={user.is_active ? 'Desactivar usuario' : 'Activar usuario'}
                            className='rounded p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors'
                          >
                            {user.is_active
                              ? <ToggleRight className='h-3.5 w-3.5 text-muted-foreground' />
                              : <ToggleLeft className='h-3.5 w-3.5 text-muted-foreground/50' />
                            }
                          </button>
                          {/* Reset 2FA — solo si está activo */}
                          {!!user.totp_enabled && (
                            <button
                              onClick={() => handleResetTotp(user)}
                              title='Desactivar 2FA'
                              className='rounded p-1.5 text-amber-500/70 hover:bg-accent hover:text-amber-400 transition-colors'
                            >
                              <ShieldOff className='h-3.5 w-3.5' />
                            </button>
                          )}
                          {/* Eliminar */}
                          <button
                            onClick={() => handleDelete(user)}
                            title='Eliminar usuario'
                            className='rounded p-1.5 text-muted-foreground hover:bg-accent hover:text-destructive transition-colors'
                          >
                            <Trash2 className='h-3.5 w-3.5' />
                          </button>
                        </div>
                      ) : null}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
      </div>

      {/* Dialog Crear / Editar */}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className='sm:max-w-md'>
          <DialogHeader>
            <DialogTitle className='flex items-center gap-2'>
              <KeyRound className='h-4 w-4' />
              {mode === 'create' ? 'Nuevo usuario' : `Editar — @${editing?.username}`}
            </DialogTitle>
          </DialogHeader>

          <div className='space-y-4 py-2'>
            {mode === 'create' && (
              <div className='space-y-1.5'>
                <Label htmlFor='username' className='text-xs'>Usuario *</Label>
                <Input
                  id='username'
                  value={form.username}
                  onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                  placeholder='johndoe'
                  className='h-8 text-sm font-mono'
                />
              </div>
            )}
            <div className='space-y-1.5'>
              <Label htmlFor='full_name' className='text-xs'>Nombre completo</Label>
              <Input
                id='full_name'
                value={form.full_name}
                onChange={e => setForm(f => ({ ...f, full_name: e.target.value }))}
                placeholder='John Doe'
                className='h-8 text-sm'
              />
            </div>
            <div className='space-y-1.5'>
              <Label htmlFor='email' className='text-xs'>Email</Label>
              <Input
                id='email'
                type='email'
                value={form.email}
                onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
                placeholder='john@example.com'
                className='h-8 text-sm'
              />
            </div>
            <div className='space-y-1.5'>
              <Label className='text-xs'>Rol *</Label>
              <Select value={form.role} onValueChange={v => setForm(f => ({ ...f, role: v as User['role'] }))}>
                <SelectTrigger className='h-8 text-sm'>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ROLES.map(r => (
                    <SelectItem key={r} value={r} className='text-sm'>
                      {ROLE_LABELS[r]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className='text-[10px] text-muted-foreground'>
                Admin: acceso total · Auditor: gestiona engagements · Pentester: opera · Lector: solo lectura
              </p>
            </div>
            <div className='space-y-1.5'>
              <Label htmlFor='password' className='text-xs'>
                Contraseña {mode === 'edit' && <span className='text-muted-foreground'>(dejar vacío para no cambiar)</span>}
              </Label>
              <Input
                id='password'
                type='password'
                value={form.password}
                onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                placeholder={mode === 'create' ? 'Mínimo 8 caracteres' : '••••••••'}
                className='h-8 text-sm'
              />
            </div>
          </div>

          <DialogFooter>
            <Button variant='outline' size='sm' onClick={() => setOpen(false)}>
              Cancelar
            </Button>
            <Button
              size='sm'
              onClick={() => saveMutation.mutate()}
              disabled={saveMutation.isPending || (mode === 'create' && (!form.username || !form.password))}
            >
              {saveMutation.isPending ? 'Guardando...' : mode === 'create' ? 'Crear usuario' : 'Guardar cambios'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
