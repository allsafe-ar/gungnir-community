/**
 * Configuracion — Ajustes del sistema Gungnir.
 * Plantilla de reportes PDF.
 * Solo admins pueden guardar cambios.
 */

import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { FileText, Save, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'

interface AppSettings {
  report_org_name:    string
  report_org_email:   string
  report_org_website: string
  report_disclaimer:  string
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
    </div>
  )
}
