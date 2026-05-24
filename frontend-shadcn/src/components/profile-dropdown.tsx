/**
 * ProfileDropdown — Top-right user menu.
 * Shows avatar with initials, name, role. Links to Mi cuenta and logout.
 */

import { Link } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'
import useDialogState from '@/hooks/use-dialog-state'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { SignOutDialog } from '@/components/sign-out-dialog'
import { useAuthStore } from '@/stores/auth-store'

const ROLE_LABEL: Record<string, string> = {
  admin:   'ADMIN',
  lead:    'LEAD',
  analyst: 'ANALYST',
  viewer:  'VIEWER',
}

export function ProfileDropdown() {
  const { t } = useTranslation()
  const [open, setOpen] = useDialogState()
  const { auth } = useAuthStore()
  const user = auth.user
  const displayName = user?.full_name || user?.username || '—'
  const initials = displayName
    .split(' ')
    .map((w: string) => w[0])
    .slice(0, 2)
    .join('')
    .toUpperCase() || '??'
  const roleLabel = ROLE_LABEL[user?.role ?? ''] ?? (user?.role?.toUpperCase() ?? '')

  return (
    <>
      <DropdownMenu modal={false}>
        <DropdownMenuTrigger asChild>
          <button className='flex items-center gap-2 rounded-lg px-2 py-1 hover:bg-accent transition-colors outline-none'>
            <Avatar className='h-8 w-8 rounded-lg'>
              <AvatarFallback className='rounded-lg bg-primary text-primary-foreground text-xs font-bold'>
                {initials}
              </AvatarFallback>
            </Avatar>
            <div className='hidden sm:grid text-start leading-tight'>
              <span className='text-sm font-semibold truncate max-w-36'>{displayName}</span>
              <span className='text-xs text-muted-foreground'>{roleLabel}</span>
            </div>
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent className='w-48' align='end' forceMount>
          <DropdownMenuItem asChild>
            <Link to='/mi-cuenta'>{t('profile.my_account')}</Link>
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem variant='destructive' onClick={() => setOpen(true)}>
            {t('profile.sign_out')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <SignOutDialog open={!!open} onOpenChange={setOpen} />
    </>
  )
}
