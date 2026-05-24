/**
 * Perfil — Configuración de cuenta del usuario.
 * Cambio de contraseña, 2FA TOTP, idioma.
 */

import { useState, useEffect } from 'react'
import { useMutation } from '@tanstack/react-query'
import { KeyRound, Shield, ShieldCheck, ShieldOff, Loader2, Globe, User2 } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

interface TotpSetupResponse {
  secret: string
  uri: string
}

export function Perfil() {
  const { auth } = useAuthStore()
  const user = auth.user
  const { t, i18n } = useTranslation()
  const [lang, setLang] = useState(localStorage.getItem('lang') || 'es')
  const [has2FA, setHas2FA] = useState(!!user?.totp_enabled)

  // Refresca el estado de 2FA desde el servidor
  useEffect(() => {
    apiFetch<{ totp_enabled: boolean }>('/auth/me')
      .then(d => setHas2FA(!!d.totp_enabled))
      .catch(() => {})
  }, [])

  function handleLangChange(v: string) {
    setLang(v)
    localStorage.setItem('lang', v)
    i18n.changeLanguage(v)
    toast.success(t('perfil.lang.updated'))
  }

  // ── Cambio de contraseña ───────────────────────────────────────────────────
  const [currentPass, setCurrentPass] = useState('')
  const [newPass, setNewPass]         = useState('')
  const [confirmPass, setConfirmPass] = useState('')

  const changePassMutation = useMutation({
    mutationFn: () =>
      apiFetch('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ current_password: currentPass, new_password: newPass }),
      }),
    onSuccess: () => {
      toast.success(t('perfil.password.updated'))
      setCurrentPass(''); setNewPass(''); setConfirmPass('')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  function handleChangePassword(e: React.FormEvent) {
    e.preventDefault()
    if (newPass !== confirmPass) { toast.error(t('perfil.password.mismatch')); return }
    if (newPass.length < 8) { toast.error(t('perfil.password.too_short')); return }
    changePassMutation.mutate()
  }

  // ── 2FA TOTP ──────────────────────────────────────────────────────────────
  const [totpData, setTotpData]   = useState<TotpSetupResponse | null>(null)
  const [totpToken, setTotpToken] = useState('')
  const [totpError, setTotpError] = useState('')

  const totpSetupMutation = useMutation({
    mutationFn: () => apiFetch<TotpSetupResponse>('/auth/totp/setup', { method: 'POST' }),
    onSuccess: (data) => { setTotpData(data); setTotpToken(''); setTotpError('') },
    onError: (e: Error) => toast.error(e.message),
  })

  const totpVerifyMutation = useMutation({
    mutationFn: () =>
      apiFetch('/auth/totp/verify', {
        method: 'POST',
        body: JSON.stringify({ code: totpToken }),
      }),
    onSuccess: () => {
      toast.success(t('perfil.2fa.enabled'))
      setTotpData(null); setTotpToken(''); setHas2FA(true)
    },
    onError: () => { setTotpError(t('perfil.2fa.error')); setTotpToken('') },
  })

  const totpDisableMutation = useMutation({
    mutationFn: () => apiFetch('/auth/totp', { method: 'DELETE', body: JSON.stringify({}) }),
    onSuccess: () => { toast.success(t('perfil.2fa.disabled')); setHas2FA(false) },
    onError: (e: Error) => toast.error(e.message),
  })

  // QR via servicio externo (no requiere dependencia extra)
  const qrUrl = totpData
    ? `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(totpData.uri)}`
    : null

  return (
    <div className='space-y-6 max-w-2xl'>
      <div>
        <h1 className='text-xl font-bold tracking-tight'>Mi perfil</h1>
        <p className='text-sm text-muted-foreground'>Configuración de tu cuenta</p>
      </div>

      {/* Info del usuario */}
      <Card>
        <CardHeader>
          <CardTitle className='flex items-center gap-2 text-base'>
            <User2 className='size-4' />
            Información de cuenta
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className='grid grid-cols-2 gap-3 text-sm'>
            <div className='space-y-0.5'>
              <p className='text-xs text-muted-foreground'>Usuario</p>
              <p className='font-mono font-medium'>@{user?.username}</p>
            </div>
            <div className='space-y-0.5'>
              <p className='text-xs text-muted-foreground'>Nombre</p>
              <p className='font-medium'>{user?.full_name || '—'}</p>
            </div>
            <div className='space-y-0.5'>
              <p className='text-xs text-muted-foreground'>Email</p>
              <p className='font-medium'>{user?.email || '—'}</p>
            </div>
            <div className='space-y-0.5'>
              <p className='text-xs text-muted-foreground'>Rol</p>
              <p className='font-medium capitalize'>{user?.role}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Cambiar contraseña */}
      <Card>
        <CardHeader>
          <CardTitle className='flex items-center gap-2 text-base'>
            <KeyRound className='size-4' />
            {t('perfil.password.title')}
          </CardTitle>
          <CardDescription>{t('perfil.password.desc')}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleChangePassword} className='space-y-4'>
            <div className='space-y-1.5'>
              <Label>{t('perfil.password.current')}</Label>
              <Input type='password' value={currentPass} onChange={(e) => setCurrentPass(e.target.value)} placeholder='••••••••' autoComplete='current-password' />
            </div>
            <div className='grid grid-cols-2 gap-3'>
              <div className='space-y-1.5'>
                <Label>{t('perfil.password.new')}</Label>
                <Input type='password' value={newPass} onChange={(e) => setNewPass(e.target.value)} placeholder='••••••••' autoComplete='new-password' />
              </div>
              <div className='space-y-1.5'>
                <Label>{t('perfil.password.confirm')}</Label>
                <Input type='password' value={confirmPass} onChange={(e) => setConfirmPass(e.target.value)} placeholder='••••••••' autoComplete='new-password' />
              </div>
            </div>
            <Button type='submit' size='sm' disabled={changePassMutation.isPending || !currentPass || !newPass || !confirmPass}>
              {changePassMutation.isPending && <Loader2 className='mr-2 h-3.5 w-3.5 animate-spin' />}
              {t('perfil.password.btn')}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* 2FA */}
      <Card>
        <CardHeader>
          <div className='flex items-center justify-between'>
            <CardTitle className='flex items-center gap-2 text-base'>
              <Shield className='size-4' />
              {t('perfil.2fa.title')}
            </CardTitle>
            <Badge variant={has2FA ? 'default' : 'secondary'} className='text-[10px]'>
              {has2FA ? t('perfil.2fa.active') : t('perfil.2fa.inactive')}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className='space-y-4'>
          {!totpData ? (
            <>
              <p className='text-sm text-muted-foreground'>
                {has2FA ? t('perfil.2fa.desc_active') : t('perfil.2fa.desc_inactive')}
              </p>
              <div className='flex gap-3'>
                {!has2FA && (
                  <Button variant='outline' size='sm' onClick={() => totpSetupMutation.mutate()} disabled={totpSetupMutation.isPending}>
                    {totpSetupMutation.isPending ? <Loader2 className='mr-2 h-3.5 w-3.5 animate-spin' /> : <ShieldCheck className='mr-2 size-4' />}
                    {t('perfil.2fa.enable')}
                  </Button>
                )}
                {has2FA && (
                  <Button
                    variant='outline'
                    size='sm'
                    className='text-destructive hover:text-destructive'
                    onClick={() => { if (confirm(t('perfil.2fa.disable_confirm'))) totpDisableMutation.mutate() }}
                    disabled={totpDisableMutation.isPending}
                  >
                    {totpDisableMutation.isPending && <Loader2 className='mr-2 h-3.5 w-3.5 animate-spin' />}
                    <ShieldOff className='mr-2 size-4' />
                    {t('perfil.2fa.disable')}
                  </Button>
                )}
              </div>
            </>
          ) : (
            <div className='space-y-4'>
              <p className='text-sm text-muted-foreground'>{t('perfil.2fa.scan')}</p>
              <div className='flex justify-center'>
                <img src={qrUrl!} alt='QR Code 2FA' width={180} height={180} className='rounded-lg border p-2 bg-white' />
              </div>
              <p className='text-center text-xs text-muted-foreground font-mono break-all'>{totpData.secret}</p>
              <div className='space-y-1.5'>
                <Label>{t('perfil.2fa.code_label')}</Label>
                <Input
                  placeholder='000000'
                  maxLength={6}
                  inputMode='numeric'
                  autoComplete='one-time-code'
                  value={totpToken}
                  onChange={(e) => setTotpToken(e.target.value.replace(/\D/g, ''))}
                  className='text-center text-2xl tracking-widest font-mono max-w-[140px]'
                />
                {totpError && <p className='text-sm text-destructive'>{totpError}</p>}
              </div>
              <div className='flex gap-2'>
                <Button size='sm' onClick={() => totpVerifyMutation.mutate()} disabled={totpToken.length !== 6 || totpVerifyMutation.isPending}>
                  {totpVerifyMutation.isPending && <Loader2 className='mr-2 h-3.5 w-3.5 animate-spin' />}
                  {t('perfil.2fa.verify')}
                </Button>
                <Button variant='outline' size='sm' onClick={() => setTotpData(null)}>{t('perfil.2fa.cancel')}</Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Idioma */}
      <Card>
        <CardHeader>
          <CardTitle className='flex items-center gap-2 text-base'>
            <Globe className='size-4' />
            {t('perfil.lang.title')}
          </CardTitle>
          <CardDescription>{t('perfil.lang.label')}</CardDescription>
        </CardHeader>
        <CardContent>
          <Select value={lang} onValueChange={handleLangChange}>
            <SelectTrigger className='w-40'><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value='es'>Español</SelectItem>
              <SelectItem value='en'>English</SelectItem>
            </SelectContent>
          </Select>
        </CardContent>
      </Card>
    </div>
  )
}
