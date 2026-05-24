/**
 * AppTitle — Sidebar header: AllSafe logo + system name + apps switcher.
 * Logo visibility is controlled by the user's branding setting (localStorage).
 */

import { useState, useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { ExternalLink, LayoutGrid, Crosshair } from 'lucide-react'
import { Link } from '@tanstack/react-router'
import {
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  useSidebar,
} from '@/components/ui/sidebar'
import allsafeLogo from '@/assets/allsafe-logo.png'

const ALLSAFE_SYSTEMS = [
  { label: 'SGSI',        url: 'https://sgsi.allsafe.com.ar' },
  { label: 'ARP',         url: 'https://arp.allsafe.com.ar' },
  { label: 'CRM',         url: 'https://crm.allsafe.com.ar' },
  { label: 'Gjallarhorn', url: 'https://gjallarhorn.allsafe.com.ar' },
  { label: 'Heimdall',    url: 'https://heimdall.allsafe.com.ar/heimdall/' },
]

export function AppTitle() {
  const { setOpenMobile } = useSidebar()
  const [showLogo, setShowLogo] = useState(true)
  const [menuOpen, setMenuOpen] = useState(false)
  const [menuPos, setMenuPos] = useState({ top: 0, left: 0 })
  const triggerRef = useRef<HTMLButtonElement>(null)

  // Read logo preference from localStorage (set by Mi cuenta)
  useEffect(() => {
    const stored = localStorage.getItem('gungnir_show_logo')
    if (stored !== null) setShowLogo(stored !== 'false')
    // Listen for changes from Mi cuenta page
    const handler = () => {
      const v = localStorage.getItem('gungnir_show_logo')
      if (v !== null) setShowLogo(v !== 'false')
    }
    window.addEventListener('gungnir_logo_changed', handler)
    return () => window.removeEventListener('gungnir_logo_changed', handler)
  }, [])

  useEffect(() => {
    if (!menuOpen) return
    function handle(e: MouseEvent) {
      const target = e.target as Node
      const menu = document.getElementById('gungnir-apps-menu')
      if (triggerRef.current?.contains(target)) return
      if (menu && menu.contains(target)) return
      setMenuOpen(false)
    }
    document.addEventListener('mousedown', handle)
    return () => document.removeEventListener('mousedown', handle)
  }, [menuOpen])

  function handleToggle() {
    if (!menuOpen && triggerRef.current) {
      const rect = triggerRef.current.getBoundingClientRect()
      setMenuPos({ top: rect.bottom + 4, left: rect.left })
    }
    setMenuOpen(o => !o)
  }

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <div className='flex items-start'>
          <SidebarMenuButton
            className='hover:bg-transparent active:bg-transparent flex-1 min-w-0 h-auto'
            asChild
          >
            <Link to='/' onClick={() => setOpenMobile(false)} className='flex flex-col items-start gap-1 py-1 w-full'>
              {showLogo && (
                <img
                  src={allsafeLogo}
                  alt='AllSafe'
                  className='w-full h-auto max-h-12 object-contain object-left rounded-lg border border-border'
                />
              )}
              <div className='flex items-center gap-2 w-full'>
                {!showLogo && (
                  <div className='flex aspect-square size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground shrink-0'>
                    <Crosshair className='size-4' />
                  </div>
                )}
                <div className='grid text-start leading-tight min-w-0 flex-1'>
                  <span className='truncate font-bold text-primary'>Gungnir</span>
                  <span className='truncate text-xs text-muted-foreground'>Offensive Security Manager</span>
                </div>
              </div>
            </Link>
          </SidebarMenuButton>

          <button
            ref={triggerRef}
            onClick={handleToggle}
            className='h-8 w-8 shrink-0 flex items-center justify-center rounded-md text-muted-foreground hover:text-foreground hover:bg-sidebar-accent transition-colors mt-1'
            title='Sistemas AllSafe'
          >
            <LayoutGrid className='size-4' />
          </button>
        </div>
      </SidebarMenuItem>

      {menuOpen && createPortal(
        <div
          id='gungnir-apps-menu'
          style={{ position: 'fixed', top: menuPos.top, left: menuPos.left, zIndex: 9999, width: 192 }}
        >
          <div className='z-50 rounded-md border border-border bg-popover p-1 text-popover-foreground shadow-md'>
            <div className='px-2 py-1.5 text-xs font-semibold text-muted-foreground uppercase tracking-wide'>
              Sistemas AllSafe
            </div>
            {ALLSAFE_SYSTEMS.map(({ label, url }) => (
              <a
                key={url}
                href={url}
                target='_blank'
                rel='noreferrer'
                onClick={() => setMenuOpen(false)}
                className='relative flex w-full cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none select-none hover:bg-accent hover:text-accent-foreground no-underline text-popover-foreground'
              >
                <ExternalLink className='size-4 text-muted-foreground shrink-0' />
                {label}
              </a>
            ))}
          </div>
        </div>,
        document.body
      )}
    </SidebarMenu>
  )
}
