import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { ConfirmDialog } from '@/components/confirm-dialog'

interface SignOutDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function SignOutDialog({ open, onOpenChange }: SignOutDialogProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()

  const handleSignOut = () => {
    // Cancelar requests en vuelo para no dejar fetches huérfanos.
    queryClient.cancelQueries()
    queryClient.clear()

    // Borrar SOLO el token del localStorage — sin tocar el estado de Zustand.
    // Si llamáramos auth.reset() primero, React re-renderizaría el árbol con
    // user=null y algún componente montado podría crashear (user.algo → TypeError)
    // mostrando la página de error 500 por un instante antes de navegar.
    localStorage.removeItem('gungnir_token')

    // Redirect duro: el browser destruye todo el árbol de React y cancela
    // cualquier fetch pendiente. El nuevo ciclo de vida arranca con localStorage
    // vacío → el store inicializa sin token → muestra login.
    window.location.replace('/sign-in')
  }

  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('signout.title')}
      desc={t('signout.desc')}
      confirmText={t('signout.confirm')}
      destructive
      handleConfirm={handleSignOut}
      className='sm:max-w-sm'
    />
  )
}
