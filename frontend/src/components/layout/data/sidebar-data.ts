import {
  LayoutDashboard,
  Building2,
  ClipboardList,
  BookOpen,
  FileText,
  Crosshair,
  Terminal,
  BookMarked,
  PenSquare,
  ScrollText,
  Key,
  Globe,
  Brain,
  StickyNote,
  GraduationCap,
} from 'lucide-react'
import { type SidebarData } from '../types'

export const sidebarData: SidebarData = {
  user: { name: '', email: '', avatar: '' },
  teams: [],
  navGroups: [
    {
      title: 'nav.overview',
      items: [
        { title: 'nav.dashboard',         url: '/',                       icon: LayoutDashboard },
        { title: 'nav.threat_intel_dash', url: '/dashboard/threat-intel', icon: Brain },
      ],
    },
    {
      title: 'nav.operations',
      items: [
        { title: 'nav.clients',     url: '/clientes',    icon: Building2 },
        { title: 'nav.engagements', url: '/engagements', icon: ClipboardList },
      ],
    },
    {
      title: 'nav.tools',
      items: [
        { title: 'nav.techniques', url: '/tecnicas',   icon: Crosshair },
        { title: 'nav.arsenal',    url: '/comandos',   icon: Terminal },
        { title: 'nav.scripts',    url: '/scripts',    icon: ScrollText },
        { title: 'nav.library',    url: '/biblioteca', icon: BookOpen },
        { title: 'nav.templates',  url: '/templates',  icon: BookMarked },
        { title: 'nav.reports',    url: '/reportes',   icon: FileText },
        { title: 'nav.writeups',   url: '/writeups',   icon: PenSquare },
        { title: 'nav.notes',      url: '/notas',      icon: StickyNote },
        { title: 'nav.papers',     url: '/papers',     icon: GraduationCap },
      ],
    },
    {
      title: 'nav.integrations',
      items: [
        { title: 'nav.api_keys', url: '/integraciones/api-keys', icon: Key },
        { title: 'nav.recon',    url: '/recon',                   icon: Globe },
      ],
    },
  ],
}
