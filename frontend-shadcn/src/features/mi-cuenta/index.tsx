/**
 * Mi cuenta — Configuración personal del usuario.
 * Layout: izquierda (password + 2FA + idioma) / derecha (info cuenta + branding logo).
 */

import { useState, useEffect, useRef } from 'react'
import { useMutation } from '@tanstack/react-query'
import { KeyRound, Shield, ShieldCheck, ShieldOff, Loader2, Globe, User2, Upload, ImageIcon } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import allsafeLogo from '@/assets/allsafe-logo.png'

interface TotpSetupResponse {
  secret: string
  uri: string
}

const ROLE_LABEL: Record<string, string> = {
  admin:     'Administrador',
  auditor:   'Auditor',
  pentester: 'Pentester',
  lector:    'Lector',
}

export function MiCuenta() {
  const { auth } = useAuthStore()
  const user = auth.user
  const { t, i18n } = useTranslation()
  const [lang, setLang] = useState(localStorage.getItem('lang') || 'es')
  const [has2FA, setHas2FA] = useState(!!user?.totp_enabled)

  // Logo branding
  const [showLogo, setShowLogo] = useState(
    localStorage.getItem('gungnir_show_logo') !== 'false'
  )
  const logoInputRef = useRef<HTMLInputElement>(null)
  const [customLogo, setCustomLogo] = useState<string | null>(
    localStorage.getItem('gungnir_custom_logo') || null
  )

  useEffect(() => {
    apiFetch<{ totp_enabled: boolean }>('/auth/me')
      .then(d => setHas2FA(!!d.totp_enabled))
      .catch(() => {})
  }, [])

  function handleLangChange(v: string) {
    setLang(v)
    localStorage.setItem('lang', v)
    i18n.changeLanguage(v)
    toast.success(t('mi_cuenta.lang.updated'))
  }

  function handleShowLogoChange(v: boolean) {
    setShowLogo(v)
    localStorage.setItem('gungnir_show_logo', v ? 'true' : 'false')
    window.dispatchEvent(new Event('gungnir_logo_changed'))
  }

  function handleLogoUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    if (file.size > 400 * 1024) { toast.error('El logo no puede superar los 400 KB'); return }
    const reader = new FileReader()
    reader.onload = (ev) => {
      const data = ev.target?.result as string
      setCustomLogo(data)
      localStorage.setItem('gungnir_custom_logo', data)
      window.dispatchEvent(new Event('gungnir_logo_changed'))
      toast.success(t('mi_cuenta.branding.saved'))
    }
    reader.readAsDataURL(file)
    e.target.value = ''
  }

  // ── Cambio de contraseña ─────────────────────────────────────────────────────
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
      toast.success(t('mi_cuenta.password.updated'))
      setCurrentPass(''); setNewPass(''); setConfirmPass('')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  function handleChangePassword(e: React.FormEvent) {
    e.preventDefault()
    if (newPass !== confirmPass) { toast.error(t('mi_cuenta.password.mismatch')); return }
    if (newPass.length < 8) { toast.error(t('mi_cuenta.password.too_short')); return }
    changePassMutation.mutate()
  }

  // ── 2FA TOTP ─────────────────────────────────────────────────────────────────
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
      toast.success(t('mi_cuenta.2fa.enabled'))
      setTotpData(null); setTotpToken(''); setHas2FA(true)
    },
    onError: () => { setTotpError(t('mi_cuenta.2fa.error')); setTotpToken('') },
  })

  const totpDisableMutation = useMutation({
    mutationFn: () => apiFetch('/auth/totp', { method: 'DELETE', body: JSON.stringify({}) }),
    onSuccess: () => { toast.success(t('mi_cuenta.2fa.disabled')); setHas2FA(false) },
    onError: (e: Error) => toast.error(e.message),
  })

  const qrUrl = totpData
    ? `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(totpData.uri)}`
    : null

  const logoSrc = customLogo || allsafeLogo

  return (
    <div className='space-y-6'>
      <h1 className='text-xl font-bold tracking-tight flex items-center gap-2'>
        <User2 className='size-5 text-primary' />
        {t('mi_cuenta.title')}
      </h1>

      <div className='grid grid-cols-1 lg:grid-cols-[1fr_420px] gap-6'>
        {/* ── Columna izquierda ─────────────────────────────────────────── */}
        <div className='space-y-4'>

          {/* Cambiar contraseña */}
          <Card>
            <CardHeader className='pb-3'>
              <CardTitle className='flex items-center gap-2 text-sm font-semibold'>
                <KeyRound className='size-4' />
                {t('mi_cuenta.password.title')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleChangePassword} className='space-y-3'>
                <div className='space-y-1.5'>
                  <Label className='text-xs'>{t('mi_cuenta.password.current')}</Label>
                  <Input type='password' value={currentPass} onChange={(e) => setCurrentPass(e.target.value)}
                    placeholder='••••••••' autoComplete='current-password' className='h-9' />
                </div>
                <div className='space-y-1.5'>
                  <Label className='text-xs'>{t('mi_cuenta.password.new')}</Label>
                  <Input type='password' value={newPass} onChange={(e) => setNewPass(e.target.value)}
                    placeholder='••••••••' autoComplete='new-password' className='h-9' />
                </div>
                <div className='space-y-1.5'>
                  <Label className='text-xs'>{t('mi_cuenta.password.confirm')}</Label>
                  <Input type='password' value={confirmPass} onChange={(e) => setConfirmPass(e.target.value)}
                    placeholder='••••••••' autoComplete='new-password' className='h-9' />
                </div>
                <Button type='submit' size='sm' className='w-full bg-primary hover:bg-primary/90'
                  disabled={changePassMutation.isPending || !currentPass || !newPass || !confirmPass}>
                  {changePassMutation.isPending && <Loader2 className='mr-2 h-3.5 w-3.5 animate-spin' />}
                  {t('mi_cuenta.password.btn')}
                </Button>
              </form>
            </CardContent>
          </Card>

          {/* 2FA */}
          <Card>
            <CardHeader className='pb-3'>
              <div className='flex items-center justify-between'>
                <CardTitle className='flex items-center gap-2 text-sm font-semibold'>
                  <Shield className='size-4' />
                  {t('mi_cuenta.2fa.title')}
                </CardTitle>
                <Badge variant={has2FA ? 'default' : 'secondary'} className='text-[10px]'>
                  {has2FA ? t('mi_cuenta.2fa.active') : t('mi_cuenta.2fa.inactive')}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className='space-y-3'>
              {!totpData ? (
                <>
                  <p className='text-xs text-muted-foreground'>
                    {has2FA ? t('mi_cuenta.2fa.desc_active') : t('mi_cuenta.2fa.desc_inactive')}
                  </p>
                  {!has2FA && (
                    <Button variant='outline' size='sm' className='w-full'
                      onClick={() => totpSetupMutation.mutate()} disabled={totpSetupMutation.isPending}>
                      {totpSetupMutation.isPending ? <Loader2 className='mr-2 h-3.5 w-3.5 animate-spin' /> : <ShieldCheck className='mr-2 size-4' />}
                      {t('mi_cuenta.2fa.enable')}
                    </Button>
                  )}
                  {has2FA && (
                    <Button variant='outline' size='sm' className='w-full text-destructive hover:text-destructive'
                      onClick={() => { if (confirm(t('mi_cuenta.2fa.disable_confirm'))) totpDisableMutation.mutate() }}
                      disabled={totpDisableMutation.isPending}>
                      {totpDisableMutation.isPending && <Loader2 className='mr-2 h-3.5 w-3.5 animate-spin' />}
                      <ShieldOff className='mr-2 size-4' />
                      {t('mi_cuenta.2fa.disable')}
                    </Button>
                  )}
                </>
              ) : (
                <div className='space-y-3'>
                  <p className='text-xs text-muted-foreground'>{t('mi_cuenta.2fa.scan')}</p>
                  <div className='flex justify-center'>
                    <img src={qrUrl!} alt='QR Code 2FA' width={160} height={160}
                      className='rounded-lg border p-2 bg-white' />
                  </div>
                  <p className='text-center text-[10px] text-muted-foreground font-mono break-all'>{totpData.secret}</p>
                  <div className='space-y-1.5'>
                    <Label className='text-xs'>{t('mi_cuenta.2fa.code_label')}</Label>
                    <Input placeholder='000000' maxLength={6} inputMode='numeric' autoComplete='one-time-code'
                      value={totpToken} onChange={(e) => setTotpToken(e.target.value.replace(/\D/g, ''))}
                      className='text-center text-xl tracking-widest font-mono' />
                    {totpError && <p className='text-xs text-destructive'>{totpError}</p>}
                  </div>
                  <div className='flex gap-2'>
                    <Button size='sm' className='flex-1'
                      onClick={() => totpVerifyMutation.mutate()}
                      disabled={totpToken.length !== 6 || totpVerifyMutation.isPending}>
                      {totpVerifyMutation.isPending && <Loader2 className='mr-2 h-3.5 w-3.5 animate-spin' />}
                      {t('mi_cuenta.2fa.verify')}
                    </Button>
                    <Button variant='outline' size='sm' onClick={() => setTotpData(null)}>
                      {t('mi_cuenta.2fa.cancel')}
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Idioma */}
          <Card>
            <CardHeader className='pb-3'>
              <CardTitle className='flex items-center gap-2 text-sm font-semibold'>
                <Globe className='size-4' />
                {t('mi_cuenta.lang.title')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className='space-y-1.5'>
                <Label className='text-xs'>{t('mi_cuenta.lang.label')}</Label>
                <Select value={lang} onValueChange={handleLangChange}>
                  <SelectTrigger className='w-48 h-9'><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value='es'>Español</SelectItem>
                    <SelectItem value='en'>English</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* ── Columna derecha ───────────────────────────────────────────── */}
        <div className='self-start space-y-4'>

          {/* Info de cuenta */}
          <Card>
            <CardHeader className='pb-3'>
              <CardTitle className='flex items-center gap-2 text-sm font-semibold'>
                <User2 className='size-4 text-primary' />
                {t('mi_cuenta.account.title')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className='space-y-3'>
                <div className='flex justify-between items-center py-2 border-b border-border'>
                  <span className='text-xs text-muted-foreground'>{t('mi_cuenta.account.username')}</span>
                  <span className='text-sm font-mono font-medium'>{user?.username}</span>
                </div>
                <div className='flex justify-between items-center py-2 border-b border-border'>
                  <span className='text-xs text-muted-foreground'>{t('mi_cuenta.account.name')}</span>
                  <span className='text-sm font-medium'>{user?.full_name || '—'}</span>
                </div>
                <div className='flex justify-between items-center py-2'>
                  <span className='text-xs text-muted-foreground'>{t('mi_cuenta.account.role')}</span>
                  <span className='text-sm font-medium'>{ROLE_LABEL[user?.role ?? ''] ?? user?.role}</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Branding AllSafe */}
          <Card>
            <CardHeader className='pb-3'>
              <CardTitle className='flex items-center gap-2 text-sm font-semibold'>
                <ImageIcon className='size-4 text-primary' />
                {t('mi_cuenta.branding.title')}
              </CardTitle>
              <p className='text-xs text-muted-foreground'>{t('mi_cuenta.branding.desc')}</p>
            </CardHeader>
            <CardContent className='space-y-3'>
              {/* Logo preview */}
              <div className='rounded-lg border border-border bg-muted/30 p-3 flex items-center justify-center min-h-16'>
                <img
                  src={logoSrc}
                  alt='AllSafe Logo'
                  className='max-h-12 max-w-full object-contain'
                />
              </div>

              {/* Show logo toggle */}
              <label className='flex items-center gap-2 cursor-pointer group'>
                <input
                  type='checkbox'
                  checked={showLogo}
                  onChange={(e) => handleShowLogoChange(e.target.checked)}
                  className='h-4 w-4 rounded border-border text-primary accent-primary cursor-pointer'
                />
                <span className='text-sm group-hover:text-foreground transition-colors'>
                  {t('mi_cuenta.branding.show_logo')}
                </span>
              </label>

              {/* Upload */}
              <div>
                <Button
                  variant='outline'
                  size='sm'
                  onClick={() => logoInputRef.current?.click()}
                  className='gap-2'
                >
                  <Upload className='size-3.5' />
                  {t('mi_cuenta.branding.upload')}
                </Button>
                <p className='text-[10px] text-muted-foreground mt-1.5'>{t('mi_cuenta.branding.upload_hint')}</p>
                <input
                  ref={logoInputRef}
                  type='file'
                  accept='image/png,image/jpeg,image/svg+xml,image/webp'
                  className='hidden'
                  onChange={handleLogoUpload}
                />
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
