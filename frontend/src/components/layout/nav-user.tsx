/**
 * NavUser — Sidebar footer: Admin menu (Administración).
 * Opens as a popover with: Usuarios, Auditoría, Configuración, Reportar bug.
 * Only visible to admin/lead roles.
 */

import { useState, useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { useTranslation } from 'react-i18next'
import { ChevronsUpDown, UserCog, ClipboardList, Settings2, Bug, Settings, Key, ScanLine } from 'lucide-react'
import { Link } from '@tanstack/react-router'
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar'
import { useAuthStore } from '@/stores/auth-store'

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function NavUser(_props?: { user?: { name: string; email: string; avatar: string } }) {
  const { t } = useTranslation()
  const { auth } = useAuthStore()
  const role = auth.user?.role

  const [menuOpen, setMenuOpen] = useState(false)
  const [menuPos, setMenuPos] = useState({ bottom: 0, left: 0, width: 260 })
  const triggerRef = useRef<HTMLButtonElement>(null)

  // Only admin and auditor can see this menu
  if (role !== 'admin' && role !== 'auditor') return null

  // Close on outside click
  useEffect(() => {
    if (!menuOpen) return
    function handle(e: MouseEvent) {
      const target = e.target as Node
      const menu = document.getElementById('gungnir-admin-menu')
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
      // Anclado desde abajo (crece hacia arriba), a la derecha del sidebar
      setMenuPos({
        bottom: window.innerHeight - rect.bottom,
        left: rect.right + 8,
        width: 260,
      })
    }
    setMenuOpen(o => !o)
  }

  const ITEMS = [
    ...(role === 'admin' ? [
      { label: t('nav.admin_menu.usuarios'),        url: '/usuarios',                        icon: UserCog },
      { label: t('nav.admin_menu.auditoria'),       url: '/auditoria',                       icon: ClipboardList },
      { label: t('nav.admin_menu.configuracion'),   url: '/configuracion',               icon: Settings },
      { label: t('nav.admin_menu.api_keys'),        url: '/integraciones/api-keys',      icon: Key },
    ] : [
      // auditor: audit log only
      { label: t('nav.admin_menu.auditoria'), url: '/auditoria', icon: ClipboardList },
    ]),
  ]

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <SidebarMenuButton
          ref={triggerRef as React.Ref<HTMLButtonElement>}
          size='lg'
          onClick={handleToggle}
          className='data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground'
        >
          <div className='flex aspect-square size-8 items-center justify-center rounded-lg bg-muted text-muted-foreground shrink-0'>
            <Settings2 className='size-4' />
          </div>
          <div className='grid flex-1 text-start text-sm leading-tight min-w-0'>
            <span className='truncate font-semibold'>{t('nav.admin_menu.title')}</span>
            <span className='truncate text-xs text-muted-foreground'>{t('nav.admin_menu.subtitle')}</span>
          </div>
          <ChevronsUpDown className='ml-auto size-4 shrink-0' />
        </SidebarMenuButton>
      </SidebarMenuItem>

      {menuOpen && createPortal(
        <div
          id='gungnir-admin-menu'
          style={{
            position: 'fixed',
            bottom: menuPos.bottom,
            left: menuPos.left,
            zIndex: 9999,
            width: menuPos.width,
          }}
        >
          <div className='z-50 rounded-md border border-border bg-popover p-1 text-popover-foreground shadow-md'>
            <div className='px-2 py-1.5 text-xs font-semibold text-muted-foreground uppercase tracking-wide'>
              {t('nav.admin_menu.section')}
            </div>

            {ITEMS.map(item => (
              <Link
                key={item.url}
                to={item.url}
                onClick={() => setMenuOpen(false)}
                className='relative flex w-full cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none select-none hover:bg-accent hover:text-accent-foreground no-underline text-popover-foreground'
              >
                <item.icon className='size-4 text-muted-foreground shrink-0' />
                {item.label}
              </Link>
            ))}

            <div className='-mx-1 my-1 h-px bg-border' />

            <a
              href='mailto:info@allsafe.com.ar?subject=Reporte de problema - Gungnir'
              className='relative flex w-full cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none select-none text-muted-foreground hover:bg-accent hover:text-accent-foreground no-underline'
              onClick={() => setMenuOpen(false)}
            >
              <Bug className='size-4 shrink-0' />
              {t('nav.admin_menu.report_bug')}
            </a>
          </div>
        </div>,
        document.body
      )}
    </SidebarMenu>
  )
}
