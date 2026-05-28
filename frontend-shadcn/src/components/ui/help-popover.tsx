/**
 * HelpPopover - Icono de ayuda con panel flotante al hacer click.
 * Usado en los headers de Arsenal, Scripts, Técnicas, Biblioteca y Templates.
 */

import { CircleHelp, X } from 'lucide-react'
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
          className='text-zinc-600 hover:text-zinc-400 transition-colors flex-shrink-0'
          aria-label={`Ayuda: ${title}`}
        >
          <CircleHelp className='h-3.5 w-3.5' />
        </button>
      </PopoverTrigger>
      <PopoverContent
        side='right'
        align='start'
        sideOffset={8}
        className='w-72 bg-zinc-900 border-zinc-700 text-zinc-200 shadow-xl p-0 overflow-hidden'
      >
        {/* Header */}
        <div className='flex items-center gap-2 px-4 py-3 border-b border-zinc-800 bg-zinc-950/60'>
          <CircleHelp className='h-3.5 w-3.5 text-zinc-500 shrink-0' />
          <p className='text-xs font-semibold text-zinc-200 flex-1'>{title}</p>
        </div>

        {/* Body */}
        <div className='px-4 py-3 space-y-3'>
          <p className='text-xs text-zinc-400 leading-relaxed'>{description}</p>

          {tips && tips.length > 0 && (
            <div className='space-y-1.5'>
              <p className='text-[10px] font-bold uppercase tracking-widest text-zinc-600'>Cómo usarlo</p>
              <ul className='space-y-1'>
                {tips.map((tip, i) => (
                  <li key={i} className='flex items-start gap-2'>
                    <span className='mt-1 h-1 w-1 rounded-full bg-zinc-600 shrink-0' />
                    <span className='text-[11px] text-zinc-500 leading-snug'>{tip}</span>
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
