import { useSearch } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'
import { Card, CardContent } from '@/components/ui/card'
import { LOGO_B64 } from '@/lib/logo'
import { AuthLayout } from '../auth-layout'
import { UserAuthForm } from './components/user-auth-form'

export function SignIn() {
  const { t } = useTranslation()
  const { redirect } = useSearch({ from: '/(auth)/sign-in' })

  return (
    <AuthLayout>
      <div className='w-full max-w-md space-y-6 px-4'>
        <div className='flex flex-col items-center gap-3'>
          <img src={LOGO_B64} alt='AllSafe' className='h-32 w-auto mx-auto block' />
          <div className='text-center'>
            <h1 className='text-2xl font-bold tracking-tight'>Gungnir</h1>
            <p className='text-sm text-muted-foreground'>{t('auth.subtitle')}</p>
          </div>
        </div>
        <Card className='w-full'>
          <CardContent className='pt-6'>
            <UserAuthForm redirectTo={redirect} />
          </CardContent>
        </Card>
        <p className='text-center text-xs text-muted-foreground'>
          AllSafe Security Solutions · {t('auth.footer')}
        </p>
      </div>
    </AuthLayout>
  )
}
