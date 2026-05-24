import { useState } from 'react'
import { z } from 'zod'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { useNavigate } from '@tanstack/react-router'
import { Loader2, LogIn, Mail, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'
import { useAuthStore } from '@/stores/auth-store'
import { apiFetch } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import {
  Form, FormControl, FormField, FormItem, FormLabel, FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { PasswordInput } from '@/components/password-input'

interface UserAuthFormProps extends React.HTMLAttributes<HTMLDivElement> {
  redirectTo?: string
}

// Respuesta del backend Gungnir
interface LoginResponse {
  token?: string
  requires_totp?: boolean
  user?: {
    id: string
    username: string
    full_name: string
    role: string
    totp_enabled: boolean
  }
  error?: string
}

type Step = 'login' | 'forgot'

export function UserAuthForm({ className, redirectTo }: UserAuthFormProps) {
  const { t } = useTranslation()
  const [isLoading, setIsLoading]         = useState(false)
  const [step, setStep]                   = useState<Step>('login')
  const [pendingPassword, setPendingPassword] = useState<string>('')
  const [pendingUsername, setPendingUsername] = useState<string | null>(null)
  const [totpCode, setTotpCode]           = useState('')
  const [totpError, setTotpError]         = useState('')
  const [forgotUser, setForgotUser]       = useState('')
  const [forgotSent, setForgotSent]       = useState(false)
  const navigate = useNavigate()
  const { auth } = useAuthStore()

  const loginSchema = z.object({
    username: z.string().min(1, t('auth.username_required')),
    password: z.string().min(1, t('auth.password_required')),
  })

  const loginForm = useForm<z.infer<typeof loginSchema>>({
    resolver: zodResolver(loginSchema),
    defaultValues: { username: '', password: '' },
  })

  function handleLoginSuccess(token: string, user: LoginResponse['user']) {
    auth.setAccessToken(token)
    auth.setUser(user as never)
    toast.success(t('auth.welcome', { name: user?.full_name || user?.username }))
    // Redirect duro en lugar de navigate() para forzar una recarga completa
    // del HTML y CSS. Evita que un CSS cacheado (de algún deploy anterior) quede
    // activo durante la sesión causando estilos incorrectos (bordes blancos, etc.)
    window.location.replace(redirectTo || '/')
  }

  async function onLoginSubmit(data: z.infer<typeof loginSchema>) {
    setIsLoading(true)
    try {
      const res = await apiFetch<LoginResponse>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: data.username, password: data.password }),
      })
      if (res.requires_totp) {
        setPendingUsername(data.username)
        setPendingPassword(data.password)
        setTotpCode('')
        setTotpError('')
        return
      }
      if (res.token && res.user) {
        handleLoginSuccess(res.token, res.user)
      }
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : t('auth.login_error'))
    } finally {
      setIsLoading(false)
    }
  }

  async function onTotpSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!pendingUsername || totpCode.length !== 6) return
    setIsLoading(true)
    setTotpError('')
    try {
      const res = await apiFetch<LoginResponse>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: pendingUsername, password: pendingPassword, totp_token: totpCode }),
      })
      if (res.token && res.user) {
        handleLoginSuccess(res.token, res.user)
      }
    } catch (e: unknown) {
      setTotpError(e instanceof Error ? e.message : t('auth.totp.error'))
      setTotpCode('')
    } finally {
      setIsLoading(false)
    }
  }

  function handleForgot() {
    if (!forgotUser.trim()) return
    const subject = encodeURIComponent('Gungnir - Recuperación de contraseña')
    const body = encodeURIComponent(
      `Estimado Administrador,\n\nEl usuario "${forgotUser.trim()}" solicita la recuperación de su contraseña en Gungnir.\n\nPor favor, restablezca la contraseña del usuario indicado.\n\nGracias.`
    )
    window.location.href = `mailto:alaniz.emiliano@allsafe.com.ar?subject=${subject}&body=${body}`
    setForgotSent(true)
  }

  // ── Forgot password ──────────────────────────────────────────────────────────
  if (step === 'forgot') {
    return (
      <div className={cn('grid gap-4', className)}>
        <div className='flex flex-col items-center gap-2 text-center mb-1'>
          <Mail className='size-10 text-primary' />
          <p className='text-sm font-semibold'>{t('auth.forgot.title')}</p>
        </div>
        {forgotSent ? (
          <div className='rounded-md bg-muted p-3 text-sm text-center text-muted-foreground'>
            {t('auth.forgot.sent_pre')}{' '}
            <strong className='text-foreground'>{forgotUser}</strong>
            {t('auth.forgot.sent_post')}
          </div>
        ) : (
          <>
            <div className='space-y-1.5'>
              <label className='text-sm font-medium'>{t('auth.forgot.username_label')}</label>
              <Input
                placeholder={t('auth.forgot.username_placeholder')}
                value={forgotUser}
                onChange={(e) => setForgotUser(e.target.value)}
                autoFocus
              />
            </div>
            <Button onClick={handleForgot} disabled={!forgotUser.trim()}>
              <Mail />
              {t('auth.forgot.send')}
            </Button>
          </>
        )}
        <button
          type='button'
          className='text-xs text-muted-foreground hover:underline text-center'
          onClick={() => { setStep('login'); setForgotUser(''); setForgotSent(false) }}
        >
          {t('auth.forgot.back')}
        </button>
      </div>
    )
  }

  // ── TOTP step ────────────────────────────────────────────────────────────────
  if (pendingUsername) {
    return (
      <form onSubmit={onTotpSubmit} className={cn('grid gap-4', className)}>
        <div className='flex flex-col items-center gap-2 text-center mb-2'>
          <ShieldCheck className='size-10 text-primary' />
          <p className='text-sm text-muted-foreground'>{t('auth.totp.hint')}</p>
          <p className='text-xs text-muted-foreground font-mono'>{pendingUsername}</p>
        </div>
        <div className='space-y-1.5'>
          <label className='text-sm font-medium'>{t('auth.totp.code_label')}</label>
          <Input
            placeholder='000000'
            maxLength={6}
            inputMode='numeric'
            autoComplete='one-time-code'
            autoFocus
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
            className='text-center text-2xl tracking-widest font-mono'
          />
          {totpError && <p className='text-sm text-destructive'>{totpError}</p>}
        </div>
        <Button type='submit' className='mt-1' disabled={isLoading || totpCode.length !== 6}>
          {isLoading ? <Loader2 className='animate-spin' /> : <ShieldCheck />}
          {t('auth.totp.verify')}
        </Button>
        <button
          type='button'
          className='text-xs text-muted-foreground hover:underline text-center'
          onClick={() => setPendingUsername(null)}
        >
          {t('auth.totp.back')}
        </button>
      </form>
    )
  }

  // ── Login normal ─────────────────────────────────────────────────────────────
  return (
    <Form {...loginForm}>
      <form onSubmit={loginForm.handleSubmit(onLoginSubmit)} className={cn('grid gap-3', className)}>
        <FormField
          control={loginForm.control}
          name='username'
          render={({ field }) => (
            <FormItem>
              <FormLabel>{t('auth.username')}</FormLabel>
              <FormControl>
                <Input placeholder={t('auth.username_placeholder')} autoComplete='username' {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={loginForm.control}
          name='password'
          render={({ field }) => (
            <FormItem>
              <FormLabel>{t('auth.password')}</FormLabel>
              <FormControl>
                <PasswordInput placeholder='••••••••' autoComplete='current-password' {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button className='mt-2' disabled={isLoading}>
          {isLoading ? <Loader2 className='animate-spin' /> : <LogIn />}
          {t('auth.login')}
        </Button>
        <button
          type='button'
          className='text-xs text-muted-foreground hover:underline text-center'
          onClick={() => setStep('forgot')}
        >
          {t('auth.forgot_password')}
        </button>
      </form>
    </Form>
  )
}
