import { LucideIcon, Telescope } from 'lucide-react'

interface ComingSoonProps {
  title?: string
  description?: string
  icon?: LucideIcon
}

export function ComingSoon({ title, description, icon: Icon = Telescope }: ComingSoonProps) {
  return (
    <div className='flex h-[60vh] flex-col items-center justify-center gap-4 text-center'>
      <Icon className='size-14 text-muted-foreground/40' />
      <div>
        <h2 className='text-xl font-bold'>{title ?? 'Próximamente'}</h2>
        <p className='mt-1 text-sm text-muted-foreground max-w-sm'>
          {description ?? 'Este módulo está en desarrollo.'}
        </p>
      </div>
    </div>
  )
}
