import { useEffect, useLayoutEffect, useRef, useState, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { useTranslation } from 'react-i18next'
import { Network, DataSet } from 'vis-network/standalone'
import type { Options } from 'vis-network'
import { Button }   from '@/components/ui/button'
import { Badge }    from '@/components/ui/badge'
import { Input }    from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog'
import { Label }    from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Switch }   from '@/components/ui/switch'
import { Plus, Save, RefreshCw, ZoomIn, Trash2, Download, FolderInput, Map as MapIcon, Pencil, Network as NetworkIcon, Zap, Link2, X, Crosshair } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { toast }    from 'sonner'
import { cn }       from '@/lib/utils'

// -- Types ---------------------------------------------------------------------
type OsType = 'windows' | 'windowsserver' | 'linux' | 'ubuntu' | 'debian' | 'kali' | 'parrot' | 'arch'
  | 'fedora' | 'redhat' | 'opensuse' | 'mint' | 'macos' | 'freebsd'
  | 'router' | 'server' | 'firewall' | 'switch' | 'printer'
  | 'nas' | 'iot' | 'camera' | 'android' | 'ios' | 'other'

interface Port { port: number; proto: string; service: string | null }

interface Target {
  id:             string
  engagement_id:  string
  ip_address:     string | null
  fqdn:           string | null
  url_address:    string | null
  os_type:        OsType
  owned:          boolean
  jumped_from_id: string | null
  notes:          string | null
  x_position:     number | null
  y_position:     number | null
}

interface MapNode {
  id: string; label: string
  ip: string | null; fqdn: string | null; url: string | null
  type: OsType; owned: boolean
  x: number | null; y: number | null
  notes?: string | null
  ports?: Port[]
}
interface MapEdge { from: string; to: string }

// -- OS metadata ---------------------------------------------------------------
const OS_COLORS: Record<string, { bg: string; border: string }> = {
  windows:  { bg: '#1a6eb5', border: '#2580cc' },
  linux:    { bg: '#3a3a3a', border: '#666' },
  ubuntu:   { bg: '#c74815', border: '#e05010' },
  debian:   { bg: '#8a0028', border: '#b00034' },
  kali:     { bg: '#2b6679', border: '#3a8aa8' },
  parrot:   { bg: '#0d7a6e', border: '#12a898' },
  arch:     { bg: '#1580b8', border: '#1a95d8' },
  fedora:   { bg: '#3060a0', border: '#3a78c8' },
  redhat:   { bg: '#cc0000', border: '#ee1111' },
  macos:    { bg: '#48484a', border: '#6e6e73' },
  router:   { bg: '#0460a0', border: '#0578c8' },
  server:   { bg: '#0070a0', border: '#0090cc' },
  firewall: { bg: '#b82010', border: '#e02820' },
  switch:   { bg: '#0460a0', border: '#0578c8' },
  printer:  { bg: '#2040a0', border: '#2858c8' },
  nas:      { bg: '#1a5098', border: '#2068c0' },
  iot:      { bg: '#884010', border: '#aa5018' },
  camera:   { bg: '#006880', border: '#00889e' },
  android:  { bg: '#2a7040', border: '#38905a' },
  ios:          { bg: '#48484a', border: '#6e6e73' },
  windowsserver:{ bg: '#1a4a8a', border: '#2060b0' },
  opensuse:     { bg: '#44a73b', border: '#5bc752' },
  mint:         { bg: '#70a833', border: '#8acc3e' },
  freebsd:      { bg: '#ab2222', border: '#d42828' },
  other:        { bg: '#4a4a5a', border: '#6a6a7a' },
}

const OS_LABELS: Record<string, string> = {
  windows:'Windows', windowsserver:'Windows Server', linux:'Linux',
  ubuntu:'Ubuntu', debian:'Debian', kali:'Kali', parrot:'Parrot OS', arch:'Arch',
  fedora:'Fedora', redhat:'Red Hat', opensuse:'openSUSE', mint:'Linux Mint',
  macos:'macOS', freebsd:'FreeBSD',
  router:'Router', server:'Server', firewall:'Firewall', switch:'Switch',
  printer:'Printer', nas:'NAS', iot:'IoT', camera:'Camera',
  android:'Android', ios:'iOS', other:'Other',
}

// -- SVG icon generation -------------------------------------------------------
type IconKey = 'windows' | 'windowsserver' | 'terminal' | 'server' | 'router' | 'firewall'
             | 'macos' | 'camera' | 'phone' | 'printer' | 'nas' | 'iot' | 'globe'
             | 'ubuntu' | 'arch' | 'debian' | 'kali' | 'parrot' | 'fedora' | 'redhat'
             | 'opensuse' | 'mint' | 'freebsd'

// White icon paths on transparent background (64x64 viewBox)
const ICON_SVG: Record<IconKey, string> = {
  windows: `
    <rect x="10" y="10" width="19" height="17" rx="1.5" fill="white" opacity="0.92"/>
    <rect x="35" y="8"  width="19" height="17" rx="1.5" fill="white" opacity="0.92"/>
    <rect x="10" y="33" width="19" height="17" rx="1.5" fill="white" opacity="0.92"/>
    <rect x="35" y="35" width="19" height="17" rx="1.5" fill="white" opacity="0.92"/>`,

  terminal: `
    <polyline points="13,23 26,32 13,41" fill="none" stroke="white" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>
    <line x1="30" y1="41" x2="52" y2="41" stroke="white" stroke-width="4.5" stroke-linecap="round"/>`,

  server: `
    <rect x="10" y="10" width="44" height="12" rx="2" fill="none" stroke="white" stroke-width="2.5"/>
    <circle cx="48" cy="16" r="3" fill="#4ade80"/>
    <rect x="10" y="26" width="44" height="12" rx="2" fill="none" stroke="white" stroke-width="2.5"/>
    <circle cx="48" cy="32" r="3" fill="#4ade80"/>
    <rect x="10" y="42" width="44" height="12" rx="2" fill="none" stroke="white" stroke-width="2.5"/>
    <circle cx="48" cy="48" r="3" fill="white" opacity="0.3"/>`,

  router: `
    <rect x="8" y="24" width="48" height="16" rx="3" fill="white" opacity="0.88"/>
    <rect x="14" y="13" width="8"  height="11" rx="1.5" fill="white" opacity="0.72"/>
    <rect x="28" y="13" width="8"  height="11" rx="1.5" fill="white" opacity="0.72"/>
    <rect x="42" y="13" width="8"  height="11" rx="1.5" fill="white" opacity="0.72"/>
    <circle cx="20" cy="32" r="3.5" fill="#4ade80"/>
    <circle cx="34" cy="32" r="3.5" fill="#4ade80"/>
    <circle cx="48" cy="32" r="3.5" fill="white" opacity="0.3"/>`,

  firewall: `
    <path d="M32,10 L52,18 L52,34 C52,46 43,54 32,56 C21,54 12,46 12,34 L12,18 Z"
          fill="none" stroke="white" stroke-width="2.5" stroke-linejoin="round"/>
    <line x1="20" y1="30" x2="44" y2="30" stroke="white" stroke-width="2.5" stroke-linecap="round"/>
    <line x1="20" y1="38" x2="44" y2="38" stroke="white" stroke-width="2.5" stroke-linecap="round"/>`,

  macos: `
    <path d="M38,12 C38,7 45,8 43,14" fill="white" opacity="0.9"/>
    <path d="M26,15 C20,14 13,20 13,30 C13,44 21,55 29,55 C31,55 33,54 34,54 C35,54 37,55 39,55 C47,55 51,44 51,30 C51,22 46,16 40,15 C38,14.5 36,16 34,16 C32,16 29,15.5 26,15 Z" fill="white" opacity="0.9"/>`,

  camera: `
    <rect x="8"  y="20" width="48" height="32" rx="4" fill="none" stroke="white" stroke-width="2.5"/>
    <circle cx="32" cy="36" r="11" fill="none" stroke="white" stroke-width="2.5"/>
    <circle cx="32" cy="36" r="5"  fill="white" opacity="0.8"/>
    <rect x="22" y="13" width="12" height="9"  rx="2" fill="white" opacity="0.85"/>
    <rect x="42" y="22" width="7"  height="5"  rx="1" fill="white" opacity="0.5"/>`,

  phone: `
    <rect x="18" y="7"  width="28" height="50" rx="5" fill="none" stroke="white" stroke-width="2.5"/>
    <line x1="26" y1="14" x2="38" y2="14" stroke="white" stroke-width="2.5" stroke-linecap="round"/>
    <circle cx="32" cy="50" r="3" fill="white" opacity="0.7"/>
    <rect x="22" y="19" width="20" height="24" rx="2" fill="white" opacity="0.15"/>`,

  printer: `
    <rect x="8"  y="26" width="48" height="22" rx="3" fill="none" stroke="white" stroke-width="2.5"/>
    <rect x="16" y="13" width="32" height="14" rx="2" fill="none" stroke="white" stroke-width="2"/>
    <rect x="18" y="37" width="28" height="7"  rx="1" fill="white" opacity="0.7"/>
    <line x1="22" y1="41" x2="42" y2="41" stroke="white" stroke-width="1.5" opacity="0.4"/>`,

  nas: `
    <rect x="12" y="9"  width="40" height="46" rx="4" fill="none" stroke="white" stroke-width="2.5"/>
    <line x1="12" y1="25" x2="52" y2="25" stroke="white" stroke-width="1.5" opacity="0.5"/>
    <line x1="12" y1="40" x2="52" y2="40" stroke="white" stroke-width="1.5" opacity="0.5"/>
    <circle cx="44" cy="17" r="3" fill="#4ade80"/>
    <circle cx="44" cy="32" r="3" fill="#4ade80"/>
    <circle cx="44" cy="47" r="3" fill="white" opacity="0.3"/>
    <rect x="16" y="12" width="20" height="10" rx="1" fill="white" opacity="0.2"/>
    <rect x="16" y="27" width="20" height="9"  rx="1" fill="white" opacity="0.2"/>`,

  iot: `
    <circle cx="32" cy="32" r="12" fill="none" stroke="white" stroke-width="2.5"/>
    <circle cx="32" cy="32" r="5"  fill="white" opacity="0.7"/>
    <rect x="29" y="12" width="6" height="8" rx="2" fill="white" opacity="0.8"/>
    <rect x="29" y="44" width="6" height="8" rx="2" fill="white" opacity="0.8"/>
    <rect x="12" y="29" width="8" height="6" rx="2" fill="white" opacity="0.8"/>
    <rect x="44" y="29" width="8" height="6" rx="2" fill="white" opacity="0.8"/>`,

  globe: `
    <circle cx="32" cy="32" r="18" fill="none" stroke="white" stroke-width="2.5"/>
    <ellipse cx="32" cy="32" rx="10" ry="18" fill="none" stroke="white" stroke-width="1.5" opacity="0.7"/>
    <line x1="14" y1="32" x2="50" y2="32" stroke="white" stroke-width="1.5" opacity="0.7"/>
    <line x1="17" y1="22" x2="47" y2="22" stroke="white" stroke-width="1"   opacity="0.4"/>
    <line x1="17" y1="42" x2="47" y2="42" stroke="white" stroke-width="1"   opacity="0.4"/>`,

  // Brand OS icons
  ubuntu: `
    <circle cx="32" cy="32" r="15" fill="none" stroke="white" stroke-width="2.5" opacity="0.5"/>
    <circle cx="32" cy="14" r="5.5" fill="white"/>
    <circle cx="47.5" cy="41" r="5.5" fill="white"/>
    <circle cx="16.5" cy="41" r="5.5" fill="white"/>`,

  arch: `
    <path d="M32,8 L54,56 H43 L32,32 L21,56 H10 Z" fill="white" opacity="0.92"/>`,

  debian: `
    <path d="M32,13 C44,13 52,21 52,32 C52,43 44,51 32,51 C20,51 12,43 12,32 C12,25 15,19 21,16" fill="none" stroke="white" stroke-width="3.5" stroke-linecap="round"/>
    <path d="M32,21 C39,21 44,27 43,33" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round"/>`,

  kali: `
    <line x1="18" y1="12" x2="18" y2="52" stroke="white" stroke-width="5.5" stroke-linecap="round"/>
    <line x1="18" y1="32" x2="48" y2="12" stroke="white" stroke-width="4.5" stroke-linecap="round"/>
    <line x1="18" y1="32" x2="48" y2="52" stroke="white" stroke-width="4.5" stroke-linecap="round"/>`,

  parrot: `
    <ellipse cx="30" cy="34" rx="11" ry="14" fill="white" opacity="0.88"/>
    <path d="M30,22 C38,17 50,20 49,31 C44,29 38,26 30,28" fill="white" opacity="0.78"/>
    <path d="M19,36 L10,50 M19,38 L12,54" stroke="white" stroke-width="2.5" stroke-linecap="round" fill="none" opacity="0.65"/>
    <path d="M38,20 L50,14 L42,24" fill="white" opacity="0.9"/>
    <circle cx="34" cy="27" r="2.8" fill="rgba(0,0,0,0.45)"/>`,

  fedora: `
    <path d="M36,22 C36,15 43,11 47,16 C51,21 46,28 40,30 C34,32 26,34 23,38 C19,43 22,50 28,50 C34,50 38,44 38,38" fill="none" stroke="white" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
    <line x1="20" y1="31" x2="45" y2="31" stroke="white" stroke-width="3.5" stroke-linecap="round"/>`,

  redhat: `
    <ellipse cx="32" cy="44" rx="22" ry="5.5" fill="white" opacity="0.9"/>
    <path d="M19,44 C20,36 22,22 32,20 C42,22 44,36 45,44" fill="white" opacity="0.85"/>
    <line x1="18" y1="38" x2="46" y2="38" stroke="rgba(0,0,0,0.2)" stroke-width="3.5"/>`,

  windowsserver: `
    <rect x="9"  y="8"  width="17" height="15" rx="1.5" fill="white" opacity="0.92"/>
    <rect x="31" y="6"  width="17" height="15" rx="1.5" fill="white" opacity="0.92"/>
    <rect x="9"  y="28" width="17" height="15" rx="1.5" fill="white" opacity="0.92"/>
    <rect x="31" y="30" width="17" height="15" rx="1.5" fill="white" opacity="0.92"/>
    <rect x="9"  y="47" width="39" height="9"  rx="2"   fill="white" opacity="0.5"/>
    <circle cx="44" cy="51.5" r="2.5" fill="#4ade80"/>`,

  opensuse: `
    <circle cx="22" cy="22" r="9" fill="none" stroke="white" stroke-width="2.5"/>
    <circle cx="25" cy="20" r="3" fill="white"/>
    <path d="M28,26 C36,24 46,28 48,36 C50,44 46,52 38,52" fill="none" stroke="white" stroke-width="3" stroke-linecap="round"/>
    <path d="M38,52 C30,54 26,48 28,42 C30,36 36,37 34,43" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round"/>`,

  mint: `
    <path d="M32,54 C18,50 10,38 12,26 C14,14 24,8 32,10 C40,8 50,14 52,26 C54,38 46,50 32,54 Z" fill="none" stroke="white" stroke-width="3"/>
    <line x1="32" y1="10" x2="32" y2="54" stroke="white" stroke-width="2.5" stroke-linecap="round"/>
    <path d="M32,32 C24,28 18,22 20,16" fill="none" stroke="white" stroke-width="1.5" opacity="0.6" stroke-linecap="round"/>
    <path d="M32,32 C40,28 46,22 44,16" fill="none" stroke="white" stroke-width="1.5" opacity="0.6" stroke-linecap="round"/>`,

  freebsd: `
    <circle cx="32" cy="34" r="14" fill="white" opacity="0.88"/>
    <path d="M24,22 C20,12 12,14 14,22" fill="none" stroke="white" stroke-width="3.5" stroke-linecap="round"/>
    <path d="M40,22 C44,12 52,14 50,22" fill="none" stroke="white" stroke-width="3.5" stroke-linecap="round"/>
    <circle cx="27" cy="31" r="3" fill="rgba(0,0,0,0.55)"/>
    <circle cx="37" cy="31" r="3" fill="rgba(0,0,0,0.55)"/>
    <path d="M32,48 C32,50 30,57 26,57" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round"/>`,
}

const OS_ICON_KEY: Record<OsType, IconKey> = {
  windows:       'windows',
  windowsserver: 'windowsserver',
  linux:         'terminal',
  ubuntu:        'ubuntu',
  debian:        'debian',
  kali:          'kali',
  parrot:        'parrot',
  arch:          'arch',
  fedora:        'fedora',
  redhat:        'redhat',
  opensuse:      'opensuse',
  mint:          'mint',
  macos:         'macos',
  freebsd:       'freebsd',
  router: 'router', switch: 'router',
  server:   'server',
  firewall: 'firewall',
  camera:   'camera',
  android: 'phone', ios: 'phone',
  printer: 'printer',
  nas:     'nas',
  iot:     'iot',
  other:   'globe',
}

function getNodeImage(type: OsType, owned: boolean): string {
  const c = owned
    ? { bg: '#7a0000', border: '#cc0000' }
    : (OS_COLORS[type] ?? OS_COLORS.other)
  const icon   = ICON_SVG[OS_ICON_KEY[type] ?? 'globe']
  // Small red badge for owned nodes (triangle in top-right corner)
  const badge  = owned
    ? `<polygon points="48,6 58,6 58,16" fill="#ff2222" opacity="0.95"/>` : ''
  const svg = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">`,
    `<rect width="64" height="64" rx="10" fill="${c.bg}" stroke="${c.border}" stroke-width="2"/>`,
    icon,
    badge,
    `</svg>`,
  ].join('')
  return `data:image/svg+xml,${encodeURIComponent(svg)}`
}

// Precompute legend icon (smaller, no label)
function getLegendIcon(type: OsType): string {
  const c   = OS_COLORS[type] ?? OS_COLORS.other
  const icon = ICON_SVG[OS_ICON_KEY[type] ?? 'globe']
  const svg  = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 64 64"><rect width="64" height="64" rx="10" fill="${c.bg}" stroke="${c.border}" stroke-width="2"/>${icon}</svg>`
  return `data:image/svg+xml,${encodeURIComponent(svg)}`
}

// -- Port risk coloring --------------------------------------------------------
const SEV_PORT: Record<number, string> = {
  21: 'text-orange-400', 22: 'text-yellow-400', 23: 'text-red-400',
  25: 'text-orange-400', 80: 'text-blue-400',  135: 'text-yellow-400',
  139: 'text-yellow-400', 443: 'text-green-400', 445: 'text-orange-400',
  3389: 'text-orange-400', 5900: 'text-orange-400',
}

// Hex colors for port severity (used in canvas export)
const SEV_COLOR: Record<string, string> = {
  'text-red-400':    '#f87171',
  'text-orange-400': '#fb923c',
  'text-yellow-400': '#facc15',
  'text-green-400':  '#4ade80',
  'text-blue-400':   '#60a5fa',
}

// -- NodeTooltip ---------------------------------------------------------------
interface TooltipProps { node: MapNode; x: number; y: number }

function NodeTooltip({ node, x, y }: TooltipProps) {
  const { t } = useTranslation()
  const osColor = OS_COLORS[node.type] ?? OS_COLORS.other
  const tipRef = useRef<HTMLDivElement>(null)
  // Portal → use viewport-relative (fixed) coordinates so the tooltip
  // can escape the overflow:hidden graph container without being clipped.
  const [posStyle, setPosStyle] = useState<React.CSSProperties>({
    position: 'fixed', left: x + 14, top: y - 8, visibility: 'hidden',
  })

  useLayoutEffect(() => {
    const el = tipRef.current
    if (!el) return
    const pw = window.innerWidth
    const ph = window.innerHeight
    const ew = el.offsetWidth
    const eh = el.offsetHeight
    let left = x + 14
    let top  = y - 8
    if (left + ew > pw - 4) left = x - ew - 14
    if (top + eh > ph - 4) top = y - eh - 10
    if (top  < 4) top  = 4
    if (left < 4) left = 4
    setPosStyle({ position: 'fixed', left, top, visibility: 'visible' })
  }, [x, y])

  return createPortal(
    <div
      ref={tipRef}
      className="z-[9999] pointer-events-none select-none"
      style={posStyle}
    >
      <div className="rounded-lg border border-border bg-[#161b22] shadow-2xl text-xs w-64 overflow-hidden flex flex-col"
           style={{ maxHeight: 'min(420px, 85vh)' }}>
        {/* Header */}
        <div
          className="px-3 py-2 flex items-center gap-2 shrink-0"
          style={{
            backgroundColor: node.owned ? '#3a0000' : osColor.bg + '44',
            borderBottom: `1px solid ${node.owned ? '#cc000055' : osColor.border + '44'}`,
          }}
        >
          <img
            src={getLegendIcon(node.type)}
            width={18} height={18}
            className="rounded shrink-0"
            alt={node.type}
          />
          <span className="font-semibold text-foreground truncate">
            {node.ip ?? node.fqdn ?? node.url ?? 'Target'}
          </span>
          {node.owned && (
            <Badge variant="destructive" className="ml-auto text-[9px] px-1 py-0 h-4 shrink-0">
              Owned
            </Badge>
          )}
        </div>

        {/* Details */}
        <div className="px-3 py-2 space-y-1 text-muted-foreground shrink-0">
          {node.ip   && <div className="flex gap-1"><span className="w-12 shrink-0 opacity-60">IP</span><span className="font-mono text-foreground">{node.ip}</span></div>}
          {node.fqdn && <div className="flex gap-1"><span className="w-12 shrink-0 opacity-60">FQDN</span><span className="font-mono text-foreground truncate">{node.fqdn}</span></div>}
          {node.url  && <div className="flex gap-1"><span className="w-12 shrink-0 opacity-60">URL</span><span className="font-mono text-foreground truncate">{node.url}</span></div>}
          <div className="flex gap-1"><span className="w-12 shrink-0 opacity-60">OS</span><span className="text-foreground">{OS_LABELS[node.type] ?? node.type}</span></div>
          {node.notes && (
            <div className="pt-1 border-t border-border/40">
              <p className="opacity-70 italic truncate">{node.notes}</p>
            </div>
          )}
        </div>

        {/* Ports — scrollable, unconstrained height so all ports show */}
        {node.ports && node.ports.length > 0 && (
          <div className="border-t border-border/40 px-3 py-2 overflow-y-auto min-h-0 flex-1">
            <div className="flex items-center gap-1 mb-1.5 opacity-60 sticky top-0 bg-[#161b22]">
              <NetworkIcon className="size-3 shrink-0" />
              <span>{t('attack_map.ports_count', { count: node.ports.length })}</span>
            </div>
            <div className="space-y-0.5">
              {node.ports.map(p => (
                <div key={`${p.port}-${p.proto}`} className="flex items-center gap-1.5 min-w-0">
                  <span className={cn('font-mono font-semibold shrink-0 w-20', SEV_PORT[p.port] ?? 'text-foreground')}>
                    {p.port}/{p.proto}
                  </span>
                  {p.service && (
                    <span className="opacity-60 truncate flex-1 min-w-0">
                      {p.service.length > 22 ? p.service.slice(0, 22) + '…' : p.service}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
        {node.ports && node.ports.length === 0 && (
          <div className="border-t border-border/40 px-3 py-1.5 opacity-40 shrink-0">{t('attack_map.no_ports')}</div>
        )}
      </div>
    </div>,
    document.body
  )
}

// -- Legend icon pill ----------------------------------------------------------
function LegendPill({ type, label }: { type: OsType; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <img src={getLegendIcon(type)} width={16} height={16} className="rounded" alt={label} />
      <span>{label}</span>
    </span>
  )
}

// -- IP deduplication ----------------------------------------------------------
// Merges targets that share the same IP — including URLs like http://1.2.3.4:80
// whose host matches a plain IP node. OR-merges `owned`; merges `ports`.
// Prefers nodes with a plain ip_address over URL-only nodes as canonical.
// Remaps edge from/to to the canonical node ID.

function extractIpFromUrl(url: string | null | undefined): string | null {
  if (!url) return null
  try {
    const u = new URL(url)
    const m = u.hostname.match(/^(\d{1,3}(?:\.\d{1,3}){3})$/)
    return m ? m[1] : null
  } catch { return null }
}

function deduplicateNodes(
  nodes: MapNode[],
  edges: MapEdge[],
): { nodes: MapNode[]; edges: MapEdge[] } {
  const groups = new Map<string, MapNode[]>()
  for (const node of nodes) {
    // If node has no direct IP, try to extract one from the URL
    const ipFromUrl = !node.ip ? extractIpFromUrl(node.url) : null
    const key = node.ip?.trim() || node.fqdn?.trim() || ipFromUrl || node.url?.trim() || node.id
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key)!.push(node)
  }

  const idMap = new Map<string, string>()      // oldId → canonicalId
  const dedupedNodes: MapNode[] = []

  for (const [, group] of groups) {
    // Prefer the node with a plain ip_address (not URL-only) as the canonical
    const canonical = group.find(n => n.ip) ?? group[0]
    const owned     = group.some(n => n.owned)
    const type      = group.find(n => n.type !== 'other')?.type ?? canonical.type
    // Merge ports from all nodes in the group
    const allPorts  = group.flatMap(n => n.ports ?? [])
    const portMap   = new Map(allPorts.map(p => [`${p.port}/${p.proto}`, p]))
    const ports     = [...portMap.values()]
    for (const n of group) idMap.set(n.id, canonical.id)
    dedupedNodes.push({ ...canonical, owned, type, ports })
  }

  // Remap and deduplicate edges
  const edgeSet      = new Set<string>()
  const dedupedEdges: MapEdge[] = []
  for (const edge of edges) {
    const from = idMap.get(edge.from) ?? edge.from
    const to   = idMap.get(edge.to)   ?? edge.to
    if (from === to) continue                     // skip self-loops after merge
    const key = `${from}→${to}`
    if (!edgeSet.has(key)) { edgeSet.add(key); dedupedEdges.push({ from, to }) }
  }

  return { nodes: dedupedNodes, edges: dedupedEdges }
}

// -- Component -----------------------------------------------------------------
export function AttackMap({ engagementId }: { engagementId: string }) {
  const { t } = useTranslation()
  const containerRef = useRef<HTMLDivElement>(null)
  const networkRef   = useRef<Network | null>(null)
  const nodesDS      = useRef<DataSet<any>>(new DataSet())
  const edgesDS      = useRef<DataSet<any>>(new DataSet())
  const mapNodesRef  = useRef<MapNode[]>([])

  const [targets,     setTargets]     = useState<Target[]>([])
  const [mapNodes,    setMapNodes]    = useState<MapNode[]>([])
  const [loading,     setLoading]     = useState(true)
  const [debugError,  setDebugError]  = useState<string | null>(null)
  const [saving,      setSaving]      = useState(false)
  const [importing,   setImporting]   = useState(false)
  const [syncing,     setSyncing]     = useState(false)
  const [connectMode,   setConnectMode]   = useState(false)
  const [connectSource, setConnectSource] = useState<string | null>(null)
  const connectSourceRef      = useRef<string | null>(null)
  const hasSavedPositionsRef  = useRef(false)
  useEffect(() => { connectSourceRef.current = connectSource }, [connectSource])
  const [addOpen,       setAddOpen]       = useState(false)
  const [addingAttacker, setAddingAttacker] = useState(false)
  const [editTarget,    setEditTarget]    = useState<Target | null>(null)
  const [hoverTooltip, setHoverTooltip]  = useState<{ node: MapNode; x: number; y: number } | null>(null)

  const emptyForm = { ip_address:'', fqdn:'', url_address:'', os_type:'other' as OsType, notes:'', owned:false, jumped_from_id:'' }
  const [form, setForm] = useState(emptyForm)

  // -- Build graph (defined first so load() can depend on it) ---------------
  const buildGraph = useCallback((rawNodes: MapNode[], rawEdges: MapEdge[]) => {
    // IP deduplication: merge nodes that share the same IP / FQDN / URL
    const { nodes, edges } = deduplicateNodes(rawNodes, rawEdges)

    // If any node has saved positions, skip physics (keeps layout stable)
    hasSavedPositionsRef.current = rawNodes.some(n => n.x !== null && n.y !== null)

    const visNodes = nodes.map(n => ({
      id:    n.id,
      label: n.label,
      title: null,               // null instead of undefined — vis-network safer
      shape: 'image' as const,
      image: getNodeImage(n.type, n.owned),
      size:  28,
      font:  {
        color: '#e6edf3', size: 11, face: 'Inter, sans-serif',
        background: 'rgba(13,17,23,0.72)', strokeWidth: 0,
      },
      borderWidth: 2,
      borderWidthSelected: 3,
      color: {
        border: n.owned ? '#cc0000' : (OS_COLORS[n.type]?.border ?? '#7a7a8a'),
        highlight: { border: '#ffffff', background: 'transparent' },
        hover:     { border: '#ffffff', background: 'transparent' },
      },
      shadow: { enabled: true, color: 'rgba(0,0,0,0.6)', size: 8, x: 2, y: 2 },
      x:     n.x ?? undefined,
      y:     n.y ?? undefined,
      // No `fixed` — physics is disabled after stabilization so nodes stay put;
      // removing fixed lets the user always drag any node freely.
    }))

    const visEdges = edges.map(e => ({
      from:   e.from,
      to:     e.to,
      arrows: { to: { enabled: true, scaleFactor: 0.9 } },
      color:  { color: '#cc2222', highlight: '#ff4444' },
      width:  2,
      dashes: [8, 4],
      smooth: { type: 'cubicBezier', roundness: 0.3 } as any,
      title:  t('attack_map.lateral_movement_edge'),
    }))

    nodesDS.current.clear()
    nodesDS.current.add(visNodes)
    edgesDS.current.clear()
    edgesDS.current.add(visEdges)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []) // nodesDS/edgesDS are stable refs — no deps needed

  // -- Fetch ------------------------------------------------------------------
  const load = useCallback(async () => {
    setLoading(true)
    setDebugError(null)
    try {
      const [tList, mapData] = await Promise.all([
        apiFetch<Target[]>(`/engagements/${engagementId}/targets`),
        apiFetch<{ nodes: MapNode[]; edges: MapEdge[] }>(`/engagements/${engagementId}/attack-map`),
      ])
      const nodes = mapData?.nodes ?? []
      const edges = mapData?.edges ?? []
      setTargets(tList ?? [])
      setMapNodes(nodes)
      mapNodesRef.current = nodes
      buildGraph(nodes, edges)
    } catch (err) {
      const msg = err instanceof Error ? err.message + '\n' + err.stack : String(err)
      console.error('[AttackMap] load error:', err)
      setDebugError(msg)
      toast.error(t('attack_map.error_load'))
    }
    finally { setLoading(false) }
  }, [engagementId, buildGraph])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    if (!containerRef.current || loading) return
    const options: Options = {
      physics: {
        // Skip physics if we have saved positions — keeps layout stable on reload
        enabled: !hasSavedPositionsRef.current,
        solver: 'forceAtlas2Based',
        forceAtlas2Based: { gravitationalConstant: -80, centralGravity: 0.01, springLength: 220, springConstant: 0.05, damping: 0.4, avoidOverlap: 0.9 },
        stabilization: { iterations: 200, updateInterval: 25 },
      },
      interaction: { hover: true, tooltipDelay: 99999, dragNodes: true, zoomView: true },
      layout:      { improvedLayout: true },
    }
    if (!networkRef.current) {
      networkRef.current = new Network(containerRef.current, { nodes: nodesDS.current, edges: edgesDS.current }, options)

      networkRef.current.on('stabilizationIterationsDone', () => {
        networkRef.current?.setOptions({ physics: { enabled: false } })
      })

      networkRef.current.on('dragEnd', (params) => {
        if (!params.nodes?.length) return
        const nodeId = params.nodes[0]
        const pos    = networkRef.current?.getPositions([nodeId])?.[nodeId]
        if (pos) {
          apiFetch(`/engagements/${engagementId}/targets/${nodeId}/position`, {
            method: 'PATCH', body: JSON.stringify({ x: pos.x, y: pos.y }),
          }).catch(() => {})
          // NOTE: do NOT set fixed:true here — that would lock the node permanently
        }
        setHoverTooltip(null)
      })

      networkRef.current.on('hoverNode', (params: any) => {
        const nodeId = params.node
        const node   = mapNodesRef.current.find(n => n.id === nodeId)
        if (!node) return
        const canvasPos = networkRef.current?.getPositions([nodeId])?.[nodeId] ?? { x: 0, y: 0 }
        const domPos    = networkRef.current?.canvasToDOM(canvasPos)
        if (domPos) {
          // Convert to viewport (fixed) coordinates so the portal tooltip
          // renders correctly even when the container uses overflow:hidden
          const rect = containerRef.current?.getBoundingClientRect() ?? { left: 0, top: 0 }
          setHoverTooltip({ node, x: rect.left + domPos.x, y: rect.top + domPos.y })
        }
      })

      networkRef.current.on('blurNode',   () => setHoverTooltip(null))
      networkRef.current.on('dragStart',  () => setHoverTooltip(null))
      networkRef.current.on('zoom',       () => setHoverTooltip(null))

    } else {
      networkRef.current.setData({ nodes: nodesDS.current, edges: edgesDS.current })
    }
  }, [loading, engagementId])

  // -- Actions ---------------------------------------------------------------
  const savePositions = async () => {
    if (!networkRef.current) return
    setSaving(true)
    const positions = networkRef.current.getPositions()
    await Promise.all(Object.entries(positions).map(([id, pos]) =>
      apiFetch(`/engagements/${engagementId}/targets/${id}/position`, {
        method: 'PATCH', body: JSON.stringify({ x: pos.x, y: pos.y }),
      })
    ))
    setSaving(false)
    toast.success(t('attack_map.positions_saved'))
  }

  const openAdd  = () => { setForm(emptyForm); setEditTarget(null); setAddingAttacker(false); setAddOpen(true) }
  const openAddAttacker = () => {
    setForm({ ...emptyForm, os_type: 'parrot', notes: t('attack_map.attacker_default_notes') })
    setEditTarget(null); setAddingAttacker(true); setAddOpen(true)
  }
  const openEdit = (t: Target) => {
    setForm({ ip_address: t.ip_address||'', fqdn: t.fqdn||'', url_address: t.url_address||'', os_type: t.os_type, notes: t.notes||'', owned: t.owned, jumped_from_id: t.jumped_from_id||'' })
    setEditTarget(t); setAddOpen(true)
  }

  const submitTarget = async () => {
    const body = { ...form, owned: form.owned, jumped_from_id: form.jumped_from_id || null }
    if (editTarget) {
      await apiFetch(`/engagements/${engagementId}/targets/${editTarget.id}`, { method:'PUT', body: JSON.stringify(body) })
      toast.success(t('attack_map.target_updated'))
    } else {
      await apiFetch(`/engagements/${engagementId}/targets`, { method:'POST', body: JSON.stringify(body) })
      toast.success(addingAttacker ? t('attack_map.attacker_added') : t('attack_map.target_added'))
    }
    setAddOpen(false); setAddingAttacker(false); load()
  }

  const deleteTarget = async (id: string) => {
    await apiFetch(`/engagements/${engagementId}/targets/${id}`, { method:'DELETE' })
    toast.success(t('attack_map.target_deleted')); load()
  }

  const toggleOwned = async (t: Target) => {
    await apiFetch(`/engagements/${engagementId}/targets/${t.id}/owned`, { method:'PATCH', body: JSON.stringify({ owned: !t.owned }) })
    load()
  }

  const importFromScope = async () => {
    setImporting(true)
    try {
      const res = await apiFetch<{ imported: number; skipped: number }>(
        `/engagements/${engagementId}/targets/import-scope`,
        { method: 'POST', body: JSON.stringify({}) }
      )
      if (res.imported === 0 && res.skipped === 0) {
        toast.info(t('attack_map.import_empty'))
      } else if (res.imported === 0) {
        toast.info(t('attack_map.import_all_exist', { count: res.skipped }))
      } else {
        const skippedStr = res.skipped ? t('attack_map.import_skipped', { count: res.skipped }) : ''
        toast.success(t('attack_map.import_success', { count: res.imported, skipped: skippedStr }))
        load()
      }
    } catch { toast.error(t('attack_map.error_import')) }
    finally { setImporting(false) }
  }

  const syncFromPhases = async () => {
    setSyncing(true)
    try {
      const res = await apiFetch<{ ok: boolean; portsAdded: number; ownedUpdated: number; edgesAdded: number; osUpdated: number }>(
        `/engagements/${engagementId}/attack-map/sync-from-phases`,
        { method: 'POST', body: '{}' }
      )
      const parts: string[] = []
      if (res.portsAdded   > 0) parts.push(t('attack_map.sync_ports',  { count: res.portsAdded }))
      if (res.ownedUpdated > 0) parts.push(t('attack_map.sync_owned',  { count: res.ownedUpdated }))
      if (res.edgesAdded   > 0) parts.push(t('attack_map.sync_edges',  { count: res.edgesAdded }))
      if (res.osUpdated    > 0) parts.push(t('attack_map.sync_os',     { count: res.osUpdated }))
      if (parts.length > 0) {
        toast.success(parts.join(' · '))
        load()
      } else {
        toast.info(t('attack_map.sync_up_to_date'))
      }
    } catch { toast.error(t('attack_map.error_sync')) }
    finally { setSyncing(false) }
  }

  // -- Connect mode -----------------------------------------------------------
  // ESC cancels connection drawing
  useEffect(() => {
    if (!connectMode) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { setConnectSource(null); setConnectMode(false) }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [connectMode])

  const createEdge = useCallback(async (fromId: string, toId: string) => {
    try {
      await apiFetch(`/engagements/${engagementId}/targets/${toId}/pivot`, {
        method: 'PATCH', body: JSON.stringify({ jumped_from_id: fromId }),
      })
      toast.success(t('attack_map.edge_created'))
      setConnectSource(null)
      setConnectMode(false)
      load()
    } catch { toast.error(t('attack_map.error_edge')) }
  }, [engagementId, load])

  const disconnectTarget = useCallback(async (tid: string) => {
    try {
      await apiFetch(`/engagements/${engagementId}/targets/${tid}/pivot`, {
        method: 'PATCH', body: JSON.stringify({ jumped_from_id: null }),
      })
      load()
    } catch { toast.error(t('attack_map.error_disconnect')) }
  }, [engagementId, load])

  // Register click handler on the vis-network graph when connect mode is active
  useEffect(() => {
    if (!networkRef.current || !connectMode) return
    const handleClick = (params: any) => {
      if (!params.nodes?.length) {
        // Click on empty space = cancel source selection (but keep connect mode)
        connectSourceRef.current = null; setConnectSource(null); return
      }
      const nodeId = params.nodes[0]
      if (!connectSourceRef.current) {
        connectSourceRef.current = nodeId; setConnectSource(nodeId)
      } else if (connectSourceRef.current !== nodeId) {
        createEdge(connectSourceRef.current, nodeId)
      }
    }
    networkRef.current.on('click', handleClick)
    return () => { networkRef.current?.off('click', handleClick) }
  }, [connectMode, createEdge])

  const exportPng = () => {
    if (!networkRef.current) return
    const graphCanvas = containerRef.current?.querySelector('canvas') as HTMLCanvasElement | null
    if (!graphCanvas) return

    // Scale factor (vis-network accounts for devicePixelRatio internally)
    const containerEl = containerRef.current
    const cssW  = containerEl?.offsetWidth  || 960
    const dpr   = graphCanvas.width / cssW  // effective DPR (e.g. 2 on retina)

    const px  = (n: number) => Math.round(n * dpr)
    const fs  = (n: number) => `${px(n)}px`
    const PAD   = px(14)
    const PANEL = px(260)

    const composite = document.createElement('canvas')
    composite.width  = graphCanvas.width + PANEL
    composite.height = graphCanvas.height

    const ctx = composite.getContext('2d')!

    // Background
    ctx.fillStyle = '#0d1117'
    ctx.fillRect(0, 0, composite.width, composite.height)

    // Graph canvas
    ctx.drawImage(graphCanvas, 0, 0)

    // Separator line
    ctx.fillStyle = '#30363d'
    ctx.fillRect(graphCanvas.width, 0, px(1), composite.height)

    // ── Right panel ────────────────────────────────────────────
    const panelX = graphCanvas.width + PAD
    let   py     = PAD + px(14)

    // Panel header
    ctx.font      = `bold ${fs(10)} Inter, ui-sans-serif, system-ui, sans-serif`
    ctx.fillStyle = '#8b949e'
    ctx.fillText('TARGETS', panelX, py)
    py += px(6)
    ctx.fillStyle = '#21262d'
    ctx.fillRect(panelX, py, PANEL - PAD * 2, px(1))
    py += px(12)

    for (const tgt of targets) {
      const label     = tgt.ip_address || tgt.fqdn || tgt.url_address || 'Target'
      const truncLbl  = label.length > 22 ? label.slice(0, 22) + '…' : label

      // Owned row highlight + red left bar
      if (tgt.owned) {
        ctx.fillStyle = '#200000'
        ctx.fillRect(graphCanvas.width, py - px(12), PANEL, px(16))
        ctx.fillStyle = '#ef4444'
        ctx.fillRect(graphCanvas.width, py - px(12), px(3), px(16))
      }

      // IP / hostname
      ctx.font      = `bold ${fs(11)} "Courier New", monospace`
      ctx.fillStyle = tgt.owned ? '#f87171' : '#e6edf3'
      ctx.fillText(truncLbl, panelX, py)

      // Owned badge (right-aligned)
      if (tgt.owned) {
        const badge = t('attack_map.compromised').toUpperCase()
        ctx.font      = `bold ${fs(8)} Inter, ui-sans-serif, system-ui, sans-serif`
        ctx.fillStyle = '#ef4444'
        const bw = ctx.measureText(badge).width
        ctx.fillText(badge, graphCanvas.width + PANEL - PAD - bw, py)
      }
      py += px(14)

      // OS label
      ctx.font      = `${fs(9)} Inter, ui-sans-serif, system-ui, sans-serif`
      ctx.fillStyle = '#8b949e'
      ctx.fillText(OS_LABELS[tgt.os_type] ?? tgt.os_type, panelX, py)
      py += px(14)

      // Ports (from deduplicated mapNodes)
      const mapNode = mapNodes.find(n =>
        (tgt.ip_address && n.ip  === tgt.ip_address) ||
        (tgt.fqdn       && n.fqdn === tgt.fqdn)       ||
        (tgt.url_address && n.url === tgt.url_address)
      )
      if (mapNode?.ports?.length) {
        for (const p of mapNode.ports) {
          const portStr = `${p.port}/${p.proto}`
          ctx.font      = `${fs(9)} "Courier New", monospace`
          ctx.fillStyle = SEV_COLOR[SEV_PORT[p.port] ?? ''] ?? '#8b949e'
          ctx.fillText(portStr, panelX + px(4), py)
          if (p.service) {
            const svcX = panelX + px(4) + ctx.measureText(portStr).width + px(6)
            ctx.font      = `${fs(9)} Inter, ui-sans-serif, system-ui, sans-serif`
            ctx.fillStyle = '#6e7681'
            ctx.fillText(p.service.slice(0, 14), svcX, py)
          }
          py += px(13)
        }
      }

      py += px(10)  // gap between targets

      // Stop if we're running out of canvas height
      if (py > composite.height - px(20)) break
    }

    const a = document.createElement('a')
    a.href     = composite.toDataURL('image/png')
    a.download = 'attack-map.png'
    a.click()
  }

  // -- Render ----------------------------------------------------------------
  return (
    <div className="flex flex-col gap-4">
      {/* DEBUG — remove after diagnosing */}
      {debugError && (
        <pre className="bg-red-950 text-red-200 text-[10px] p-2 rounded max-h-40 overflow-auto whitespace-pre-wrap">
          {debugError}
        </pre>
      )}
      {/* Toolbar */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2 flex-wrap">
          <Button size="sm" onClick={openAdd}><Plus className="size-4 mr-1" />{t('attack_map.add_target')}</Button>
          <Button size="sm" variant="outline" onClick={openAddAttacker}
            title={t('attack_map.add_attacker_title')}>
            <Crosshair className="size-4 mr-1" />{t('attack_map.add_attacker')}
          </Button>
          <Button size="sm" variant="outline" onClick={importFromScope} disabled={importing}>
            <FolderInput className="size-4 mr-1" />{importing ? t('attack_map.importing') : t('attack_map.import_from_scope')}
          </Button>
          <Button size="sm" variant="outline" onClick={syncFromPhases} disabled={syncing}
            title={t('attack_map.sync_title')}>
            <Zap className="size-4 mr-1" />{syncing ? t('attack_map.syncing') : t('attack_map.sync')}
          </Button>
          <Button size="sm"
            variant={connectMode ? "default" : "outline"}
            onClick={() => { setConnectMode(m => !m); setConnectSource(null) }}
            className={cn(connectMode && "bg-yellow-600 hover:bg-yellow-700 border-yellow-500 text-white")}
            title={t('attack_map.connect_mode_title')}>
            <Link2 className="size-4 mr-1" />{connectMode ? t('attack_map.connecting') : t('attack_map.connect_nodes')}
          </Button>
          <Button size="sm" variant="outline" onClick={load}><RefreshCw className="size-4 mr-1" />{t('attack_map.refresh')}</Button>
          <Button size="sm" variant="outline" onClick={() => networkRef.current?.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } })}><ZoomIn className="size-4 mr-1" />{t('attack_map.fit')}</Button>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={exportPng}><Download className="size-4 mr-1" />{t('attack_map.export_png')}</Button>
          <Button size="sm" onClick={savePositions} disabled={saving}><Save className="size-4 mr-1" />{saving ? t('attack_map.saving') : t('attack_map.save_positions')}</Button>
        </div>
      </div>

      {/* Banner de modo conexión */}
      {connectMode && (
        <div className="flex items-center gap-2 rounded-md bg-yellow-500/10 border border-yellow-500/20 px-3 py-2 text-xs text-yellow-400">
          <Link2 className="size-3.5 shrink-0" />
          {connectSource
            ? <>{t('attack_map.origin_label')} <strong>{targets.find(tgt => tgt.id === connectSource)?.ip_address ?? targets.find(tgt => tgt.id === connectSource)?.fqdn ?? connectSource}</strong>{t('attack_map.connect_dest_hint')}</>
            : t('attack_map.connect_source_hint')}
          <button onClick={() => { setConnectSource(null); setConnectMode(false) }}
            className="ml-auto hover:text-yellow-200 transition-colors">
            <X className="size-3.5" />
          </button>
        </div>
      )}

      {/* Leyenda con iconos reales */}
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <LegendPill type="windows"       label="Windows" />
        <LegendPill type="windowsserver" label="Win Server" />
        <LegendPill type="macos"         label="macOS" />
        <LegendPill type="linux"         label="Linux" />
        <LegendPill type="ubuntu"        label="Ubuntu" />
        <LegendPill type="debian"        label="Debian" />
        <LegendPill type="kali"          label="Kali" />
        <LegendPill type="parrot"        label="Parrot OS" />
        <LegendPill type="arch"          label="Arch" />
        <LegendPill type="fedora"        label="Fedora" />
        <LegendPill type="redhat"        label="Red Hat" />
        <LegendPill type="opensuse"      label="openSUSE" />
        <LegendPill type="mint"          label="Mint" />
        <LegendPill type="freebsd"       label="FreeBSD" />
        <LegendPill type="server"        label="Server" />
        <LegendPill type="router"        label="Router/SW" />
        <LegendPill type="firewall"      label="Firewall" />
        <LegendPill type="android"       label="Mobile" />
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-4 h-4 rounded-sm bg-[#7a0000] border border-red-600 relative overflow-hidden">
            <span className="absolute top-0 right-0 w-0 h-0 border-t-[6px] border-t-red-500 border-l-[6px] border-l-transparent"/>
          </span>
          <b>{t('attack_map.owned_legend')}</b>
        </span>
        <span className="opacity-50">{t('attack_map.lateral_movement_legend')}</span>
      </div>

      {/* Grafo */}
      <div className="relative border border-border rounded-lg overflow-hidden bg-[#0d1117]" style={{ height: 480 }}>
        {loading && (
          <div className="absolute inset-0 flex items-center justify-center bg-background/60 z-10">
            <span className="text-muted-foreground text-sm">{t('attack_map.loading')}</span>
          </div>
        )}
        {!loading && targets.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-muted-foreground gap-2">
            <MapIcon className="size-16 text-primary opacity-40" />
            <span className="text-sm">{t('attack_map.no_targets')}</span>
          </div>
        )}
        <div ref={containerRef} className="w-full h-full"
          style={{ cursor: connectMode ? (connectSource ? 'crosshair' : 'cell') : 'default' }} />

        {/* Hover tooltip */}
        {hoverTooltip && (
          <NodeTooltip node={hoverTooltip.node} x={hoverTooltip.x} y={hoverTooltip.y} />
        )}
      </div>

      {/* Lista de targets */}
      {targets.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-muted-foreground">
              <tr>
                <th className="text-left px-3 py-2">{t('attack_map.col_host')}</th>
                <th className="text-left px-3 py-2">{t('attack_map.col_os')}</th>
                <th className="text-left px-3 py-2">{t('attack_map.col_pivot')}</th>
                <th className="text-left px-3 py-2">{t('attack_map.col_status')}</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {targets.map(tgt => (
                <tr key={tgt.id} className="border-t border-border hover:bg-muted/20">
                  <td className="px-3 py-2 font-mono text-xs">{tgt.ip_address || tgt.fqdn || tgt.url_address}</td>
                  <td className="px-3 py-2">
                    <span className="flex items-center gap-1.5">
                      <img src={getLegendIcon(tgt.os_type)} width={14} height={14} className="rounded" alt={tgt.os_type} />
                      {OS_LABELS[tgt.os_type] ?? tgt.os_type}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                    {tgt.jumped_from_id
                      ? <span className="flex items-center gap-1">
                          {targets.find(x => x.id === tgt.jumped_from_id)?.ip_address
                           || targets.find(x => x.id === tgt.jumped_from_id)?.fqdn
                           || tgt.jumped_from_id}
                          <button onClick={() => disconnectTarget(tgt.id)}
                            className="opacity-40 hover:opacity-100 hover:text-destructive transition-opacity" title={t('attack_map.remove_connection')}>
                            <X className="size-3" />
                          </button>
                        </span>
                      : '-'}
                  </td>
                  <td className="px-3 py-2">
                    <Badge variant={tgt.owned ? "destructive" : "secondary"} className="cursor-pointer" onClick={() => toggleOwned(tgt)}>
                      {tgt.owned ? t('attack_map.compromised') : t('attack_map.not_compromised')}
                    </Badge>
                  </td>
                  <td className="px-3 py-2 flex gap-1 justify-end">
                    <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => openEdit(tgt)}>
                      <Pencil className="size-4 text-yellow-400" />
                    </Button>
                    <Button size="icon" variant="ghost" className="h-7 w-7 text-destructive" onClick={() => deleteTarget(tgt.id)}>
                      <Trash2 className="size-3.5" />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Dialog agregar/editar */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>
              {editTarget ? t('attack_map.dialog_edit') : addingAttacker ? t('attack_map.dialog_add_attacker') : t('attack_map.dialog_add')}
            </DialogTitle>
            {addingAttacker && !editTarget && (
              <p className="text-xs text-muted-foreground mt-0.5">
                {t('attack_map.attacker_hint')}
              </p>
            )}
          </DialogHeader>
          <div className="grid gap-4 py-2">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>{t('attack_map.label_ip')}</Label>
                <Input placeholder="192.168.1.10" value={form.ip_address} onChange={e=>setForm(f=>({...f,ip_address:e.target.value}))} />
              </div>
              <div className="space-y-1">
                <Label>{t('attack_map.label_fqdn')}</Label>
                <Input placeholder="dc01.corp.local" value={form.fqdn} onChange={e=>setForm(f=>({...f,fqdn:e.target.value}))} />
              </div>
            </div>
            <div className="space-y-1">
              <Label>{t('attack_map.label_url')}</Label>
              <Input placeholder="https://app.example.com" value={form.url_address} onChange={e=>setForm(f=>({...f,url_address:e.target.value}))} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>{t('attack_map.label_os')}</Label>
                <Select value={form.os_type} onValueChange={v=>setForm(f=>({...f,os_type:v as OsType}))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {Object.entries(OS_LABELS).map(([k,v]) => (
                      <SelectItem key={k} value={k}>
                        <span className="flex items-center gap-2">
                          <img src={getLegendIcon(k as OsType)} width={14} height={14} className="rounded" alt={k} />
                          {v}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label>{t('attack_map.label_pivot')}</Label>
                <Select value={form.jumped_from_id} onValueChange={v=>setForm(f=>({...f,jumped_from_id:v==='none'?'':v}))}>
                  <SelectTrigger><SelectValue placeholder={t('attack_map.pivot_none_placeholder')} /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">{t('attack_map.pivot_none')}</SelectItem>
                    {targets.filter(tgt=>!editTarget||tgt.id!==editTarget.id).map(tgt=>(
                      <SelectItem key={tgt.id} value={tgt.id}>{tgt.ip_address||tgt.fqdn||tgt.url_address}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-1">
              <Label>{t('attack_map.label_notes')}</Label>
              <Textarea placeholder={t('attack_map.notes_placeholder')} value={form.notes} onChange={e=>setForm(f=>({...f,notes:e.target.value}))} rows={2} />
            </div>
            <div className="flex items-center gap-3">
              <Switch checked={form.owned} onCheckedChange={v=>setForm(f=>({...f,owned:v}))} id="owned-sw" />
              <Label htmlFor="owned-sw" className="cursor-pointer">{t('attack_map.label_owned')}</Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={()=>setAddOpen(false)}>{t('common.cancel')}</Button>
            <Button onClick={submitTarget}>{editTarget ? t('common.save') : t('common.create')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
