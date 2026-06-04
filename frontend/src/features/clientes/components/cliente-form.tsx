import { useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { toast } from 'sonner'
import { Building2, Save, ArrowLeft } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { apiFetch } from '@/lib/api'

interface ClienteFormProps {
  initial?: Partial<ClienteData>
  clienteId?: string   // si hay id → edición
}
interface ClienteData {
  name: string
  industry: string
  size: string
  country: string
  contact_name: string
  contact_email: string
  contact_phone: string
  exec_contact_name: string
  exec_contact_email: string
  notes: string
  nda_signed: boolean
}

export function ClienteForm({ initial, clienteId }: ClienteFormProps) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const isEdit = !!clienteId
  const [saving, setSaving] = useState(false)
  const [form, setForm] = useState<ClienteData>({
    name:               initial?.name               ?? '',
    industry:           initial?.industry            ?? '',
    size:               initial?.size               ?? '',
    country:            initial?.country            ?? 'Argentina',
    contact_name:       initial?.contact_name       ?? '',
    contact_email:      initial?.contact_email      ?? '',
    contact_phone:      initial?.contact_phone      ?? '',
    exec_contact_name:  initial?.exec_contact_name  ?? '',
    exec_contact_email: initial?.exec_contact_email ?? '',
    notes:              initial?.notes              ?? '',
    nda_signed:         initial?.nda_signed         ?? false,
  })

  const SIZES = [
    { value: 'small',      label: t('client.size_small_label') },
    { value: 'medium',     label: t('client.size_medium_label') },
    { value: 'large',      label: t('client.size_large_label') },
    { value: 'enterprise', label: t('client.size_enterprise_label') },
  ]

  const set = (k: keyof ClienteData) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm(prev => ({ ...prev, [k]: e.target.value }))

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.name.trim()) { toast.error(t('client.name_required')); return }
    setSaving(true)
    try {
      if (isEdit) {
        await apiFetch(`/clientes/${clienteId}`, { method: 'PUT', body: form })
        toast.success(t('client.toast_updated'))
        navigate({ to: '/clientes/$clienteId', params: { clienteId } })
      } else {
        const created = await apiFetch<{ id: string }>('/clientes', { method: 'POST', body: form })
        toast.success(t('client.toast_created'))
        navigate({ to: '/clientes/$clienteId', params: { clienteId: created.id } })
      }
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : t('common.error'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className='space-y-6 max-w-2xl'>
      <div className='flex items-center gap-3'>
        <Button type='button' variant='ghost' size='sm' className='text-muted-foreground -ml-2'
          onClick={() => navigate({ to: '/clientes' })}>
          <ArrowLeft className='mr-1 size-3' /> {t('client.title')}
        </Button>
      </div>

      <div className='flex items-center gap-3'>
        <Building2 className='size-6 text-muted-foreground' />
        <h1 className='text-2xl font-bold'>{isEdit ? t('client.title_edit') : t('client.title_new')}</h1>
      </div>

      {/* Datos generales */}
      <Card>
        <CardHeader className='pb-3'>
          <CardTitle className='text-sm font-semibold text-muted-foreground uppercase tracking-wide'>
            {t('client.section_general')}
          </CardTitle>
        </CardHeader>
        <CardContent className='space-y-4'>
          <div className='grid gap-4 sm:grid-cols-2'>
            <div className='space-y-1.5 sm:col-span-2'>
              <Label htmlFor='name'>{t('client.label_name')} <span className='text-destructive'>*</span></Label>
              <Input id='name' value={form.name} onChange={set('name')} placeholder='Empresa S.A.' required />
            </div>
            <div className='space-y-1.5'>
              <Label htmlFor='industry'>{t('client.label_industry')}</Label>
              <Input id='industry' value={form.industry} onChange={set('industry')} placeholder='Finanzas, Salud, Gobierno...' />
            </div>
            <div className='space-y-1.5'>
              <Label htmlFor='country'>{t('client.label_country')}</Label>
              <Input id='country' value={form.country} onChange={set('country')} placeholder='Argentina' />
            </div>
            <div className='space-y-1.5'>
              <Label>{t('client.label_size')}</Label>
              <Select value={form.size} onValueChange={v => setForm(p => ({ ...p, size: v }))}>
                <SelectTrigger><SelectValue placeholder={t('client.select_placeholder')} /></SelectTrigger>
                <SelectContent>
                  {SIZES.map(s => <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className='space-y-1.5'>
              <Label>{t('client.label_nda')}</Label>
              <Select value={form.nda_signed ? 'si' : 'no'} onValueChange={v => setForm(p => ({ ...p, nda_signed: v === 'si' }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value='si'>{t('client.yes')}</SelectItem>
                  <SelectItem value='no'>{t('client.no')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Contacto técnico */}
      <Card>
        <CardHeader className='pb-3'>
          <CardTitle className='text-sm font-semibold text-muted-foreground uppercase tracking-wide'>
            {t('client.tech_contact')}
          </CardTitle>
        </CardHeader>
        <CardContent className='space-y-4'>
          <div className='grid gap-4 sm:grid-cols-2'>
            <div className='space-y-1.5'>
              <Label htmlFor='contact_name'>{t('client.label_contact_name')}</Label>
              <Input id='contact_name' value={form.contact_name} onChange={set('contact_name')} />
            </div>
            <div className='space-y-1.5'>
              <Label htmlFor='contact_email'>{t('client.label_email')}</Label>
              <Input id='contact_email' type='email' value={form.contact_email} onChange={set('contact_email')} />
            </div>
            <div className='space-y-1.5'>
              <Label htmlFor='contact_phone'>{t('client.label_phone')}</Label>
              <Input id='contact_phone' value={form.contact_phone} onChange={set('contact_phone')} />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Contacto ejecutivo */}
      <Card>
        <CardHeader className='pb-3'>
          <CardTitle className='text-sm font-semibold text-muted-foreground uppercase tracking-wide'>
            {t('client.exec_contact_label')}
          </CardTitle>
        </CardHeader>
        <CardContent className='space-y-4'>
          <div className='grid gap-4 sm:grid-cols-2'>
            <div className='space-y-1.5'>
              <Label htmlFor='exec_contact_name'>{t('client.label_contact_name')}</Label>
              <Input id='exec_contact_name' value={form.exec_contact_name} onChange={set('exec_contact_name')} />
            </div>
            <div className='space-y-1.5'>
              <Label htmlFor='exec_contact_email'>{t('client.label_email')}</Label>
              <Input id='exec_contact_email' type='email' value={form.exec_contact_email} onChange={set('exec_contact_email')} />
            </div>
          </div>
        </CardContent>
      </Card>

      <Separator />

      {/* Notas */}
      <Card>
        <CardHeader className='pb-3'>
          <CardTitle className='text-sm font-semibold text-muted-foreground uppercase tracking-wide'>{t('client.notes_label')}</CardTitle>
        </CardHeader>
        <CardContent>
          <Textarea value={form.notes} onChange={set('notes')} rows={3}
            placeholder='Contexto relevante sobre el cliente, restricciones conocidas, historial...' />
        </CardContent>
      </Card>

      <div className='flex gap-3'>
        <Button type='submit' disabled={saving}>
          <Save className='mr-2 size-4' />
          {saving ? t('client.saving') : isEdit ? t('client.btn_update') : t('client.btn_create')}
        </Button>
        <Button type='button' variant='outline' onClick={() => navigate({ to: '/clientes' })}>
          {t('common.cancel')}
        </Button>
      </div>
    </form>
  )
}
