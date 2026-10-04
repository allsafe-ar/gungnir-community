/**
 * Configuracion — Ajustes del sistema Gungnir.
 * Plantilla de reportes PDF.
 * Solo admins pueden guardar cambios.
 */

import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { FileText, Save, Loader2, Bell } from 'lucide-react'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

interface AppSettings {
  report_org_name:    string
  report_org_email:   string
  report_org_website: string
  report_disclaimer:  string
}

interface NotifSettings {
  email_enabled:   boolean
  email_to:        string
  webhook_enabled: boolean
  webhook_url:     string
  min_severity:    string
}

export function Configuracion() {
  const { auth } = useAuthStore()
  const isAdmin = auth.user?.role === 'admin'
  const qc = useQueryClient()

  const { data: settings, isLoading } = useQuery<AppSettings>({
    queryKey: ['gungnir-settings'],
    queryFn:  () => apiFetch<AppSettings>('/settings'),
  })

  const [form, setForm] = useState<AppSettings>({
    report_org_name:    '',
    report_org_email:   '',
    report_org_website: '',
    report_disclaimer:  '',
  })

  useEffect(() => {
    if (settings) setForm(settings)
  }, [settings])

  const saveMutation = useMutation({
    mutationFn: () => apiFetch('/settings', {
      method: 'PUT',
      body: JSON.stringify(form),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['gungnir-settings'] })
      toast.success('Configuración guardada')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const set = (k: keyof AppSettings) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm(p => ({ ...p, [k]: e.target.value }))

  // ── Avisos de hallazgos ──
  const { data: notif } = useQuery<NotifSettings>({
    queryKey: ['gungnir-notifications'],
    queryFn:  () => apiFetch<NotifSettings>('/settings/notifications'),
    enabled:  isAdmin,
  })
  const [notifForm, setNotifForm] = useState<NotifSettings>({
    email_enabled: false, email_to: '', webhook_enabled: false, webhook_url: '', min_severity: 'high',
  })
  useEffect(() => { if (notif) setNotifForm(notif) }, [notif])

  const saveNotif = useMutation({
    mutationFn: () => apiFetch('/settings/notifications', { method: 'PUT', body: JSON.stringify(notifForm) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['gungnir-notifications'] })
      toast.success('Configuración guardada')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  return (
    <div className='space-y-6 max-w-2xl'>
      <div>
        <h1 className='text-xl font-bold tracking-tight flex items-center gap-2'>
          <FileText className='size-5' />
          Plantilla de Reportes
        </h1>
        <p className='text-sm text-muted-foreground mt-0.5'>Datos de la firma para la portada y pie de página de los informes PDF</p>
      </div>

      {/* Plantilla de reportes */}
      <Card>
        <CardHeader>
          <CardTitle className='flex items-center gap-2 text-base'>
            <FileText className='size-4' />
            Plantilla de reportes PDF
          </CardTitle>
          <CardDescription>
            Datos de la firma que aparecen en la portada y pie de página de los informes de pentest.
          </CardDescription>
        </CardHeader>
        <CardContent className='space-y-4'>
          {isLoading ? (
            <div className='flex items-center gap-2 text-muted-foreground text-sm'>
              <Loader2 className='size-4 animate-spin' /> Cargando...
            </div>
          ) : (
            <>
              <div className='grid grid-cols-2 gap-4'>
                <div className='space-y-1.5'>
                  <Label>Nombre de la firma</Label>
                  <Input
                    value={form.report_org_name}
                    onChange={set('report_org_name')}
                    placeholder='AllSafe Security Solutions'
                    disabled={!isAdmin}
                  />
                </div>
                <div className='space-y-1.5'>
                  <Label>Email de contacto</Label>
                  <Input
                    value={form.report_org_email}
                    onChange={set('report_org_email')}
                    placeholder='info@allsafe.com.ar'
                    disabled={!isAdmin}
                  />
                </div>
              </div>
              <div className='space-y-1.5'>
                <Label>Sitio web</Label>
                <Input
                  value={form.report_org_website}
                  onChange={set('report_org_website')}
                  placeholder='www.allsafe.com.ar'
                  disabled={!isAdmin}
                />
              </div>
              <div className='space-y-1.5'>
                <Label>Disclaimer de confidencialidad</Label>
                <Textarea
                  value={form.report_disclaimer}
                  onChange={set('report_disclaimer')}
                  rows={3}
                  placeholder='Este informe contiene información sensible...'
                  disabled={!isAdmin}
                  className='resize-none text-sm'
                />
                <p className='text-xs text-muted-foreground'>
                  Aparece en la portada de cada informe generado.
                </p>
              </div>

              {isAdmin && (
                <Button
                  size='sm'
                  onClick={() => saveMutation.mutate()}
                  disabled={saveMutation.isPending}
                >
                  {saveMutation.isPending
                    ? <><Loader2 className='mr-2 size-3.5 animate-spin' /> Guardando...</>
                    : <><Save className='mr-2 size-3.5' /> Guardar cambios</>
                  }
                </Button>
              )}
              {!isAdmin && (
                <p className='text-xs text-muted-foreground'>Solo los administradores pueden modificar la configuración.</p>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Avisos de hallazgos (solo admin) */}
      {isAdmin && (
        <Card>
          <CardHeader>
            <CardTitle className='flex items-center gap-2 text-base'>
              <Bell className='size-4' />
              Avisos de hallazgos
            </CardTitle>
            <CardDescription>Avisá por correo o webhook cuando entra un hallazgo de severidad relevante.</CardDescription>
          </CardHeader>
          <CardContent className='space-y-5'>
            <div className='space-y-1.5 max-w-xs'>
              <Label>Severidad mínima</Label>
              <Select value={notifForm.min_severity} onValueChange={v => setNotifForm(p => ({ ...p, min_severity: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value='critical'>Crítico</SelectItem>
                  <SelectItem value='high'>Alto y crítico</SelectItem>
                  <SelectItem value='medium'>Medio y superior</SelectItem>
                </SelectContent>
              </Select>
              <p className='text-xs text-muted-foreground'>Solo se avisa de hallazgos de esta severidad o mayor.</p>
            </div>

            <div className='space-y-2'>
              <div className='flex items-center justify-between'>
                <Label htmlFor='notif-email'>Aviso por correo</Label>
                <Switch id='notif-email' checked={notifForm.email_enabled}
                  onCheckedChange={v => setNotifForm(p => ({ ...p, email_enabled: v }))} />
              </div>
              <Input type='email' value={notifForm.email_to}
                onChange={e => setNotifForm(p => ({ ...p, email_to: e.target.value }))}
                placeholder='soc@cliente.com' disabled={!notifForm.email_enabled} />
            </div>

            <div className='space-y-2'>
              <div className='flex items-center justify-between'>
                <Label htmlFor='notif-webhook'>Aviso por webhook</Label>
                <Switch id='notif-webhook' checked={notifForm.webhook_enabled}
                  onCheckedChange={v => setNotifForm(p => ({ ...p, webhook_enabled: v }))} />
              </div>
              <Input value={notifForm.webhook_url}
                onChange={e => setNotifForm(p => ({ ...p, webhook_url: e.target.value }))}
                placeholder='https://hooks.cliente.com/...' disabled={!notifForm.webhook_enabled} />
              <p className='text-xs text-muted-foreground'>Se envía un POST con el hallazgo (Slack, Teams, Mattermost o el endpoint propio del equipo).</p>
            </div>

            <Button size='sm' onClick={() => saveNotif.mutate()} disabled={saveNotif.isPending}>
              {saveNotif.isPending
                ? <><Loader2 className='mr-2 size-3.5 animate-spin' /> Guardando...</>
                : <><Save className='mr-2 size-3.5' /> Guardar cambios</>}
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
