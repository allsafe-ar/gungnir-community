/**
 * HelpPopover - Icono de ayuda con panel flotante al hacer click.
 * Usado en los headers de Arsenal, Scripts, Técnicas, Biblioteca y Templates.
 */

import { CircleHelp } from 'lucide-react'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'

interface HelpPopoverProps {
  title: string
  description: string
  tips?: string[]
}

export function HelpPopover({ title, description, tips }: HelpPopoverProps) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type='button'
          className='text-muted-foreground hover:text-muted-foreground transition-colors flex-shrink-0'
          aria-label={`Ayuda: ${title}`}
        >
          <CircleHelp className='h-3.5 w-3.5' />
        </button>
      </PopoverTrigger>
      <PopoverContent
        side='right'
        align='start'
        sideOffset={8}
        className='w-72 bg-card border-border text-foreground shadow-xl p-0 overflow-hidden'
      >
        {/* Header */}
        <div className='flex items-center gap-2 px-4 py-3 border-b border-border bg-background/60'>
          <CircleHelp className='h-3.5 w-3.5 text-muted-foreground shrink-0' />
          <p className='text-xs font-semibold text-foreground flex-1'>{title}</p>
        </div>

        {/* Body */}
        <div className='px-4 py-3 space-y-3'>
          <p className='text-xs text-muted-foreground leading-relaxed'>{description}</p>

          {tips && tips.length > 0 && (
            <div className='space-y-1.5'>
              <p className='text-[10px] font-bold uppercase tracking-widest text-muted-foreground'>Cómo usarlo</p>
              <ul className='space-y-1'>
                {tips.map((tip, i) => (
                  <li key={i} className='flex items-start gap-2'>
                    <span className='mt-1 h-1 w-1 rounded-full bg-accent shrink-0' />
                    <span className='text-[11px] text-muted-foreground leading-snug'>{tip}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </PopoverContent>
    </Popover>
  )
}
