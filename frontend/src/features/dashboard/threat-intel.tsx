/**
 * Threat Intel Dashboard — Estado de fuentes OSINT + acceso rápido a Recon.
 */

import { Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import {
  Brain, CheckCircle2, XCircle, Globe, ExternalLink,
  ArrowRight, Zap, Radar,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { apiFetch } from '@/lib/api'
import { cn } from '@/lib/utils'

// ─── Datos estáticos ──────────────────────────────────────────────────────────
const OSINT_SERVICES = [
  {
    key: 'shodan',
    label: 'Shodan',
    url: 'account.shodan.io',
    capabilities: ['Puertos abiertos', 'Banners de servicios', 'CVEs asociados', 'DNS inverso', 'Enumeración de hostnames'],
    color: '#ef4444',
  },
  {
    key: 'virustotal',
    label: 'VirusTotal',
    url: 'virustotal.com',
    capabilities: ['Passive DNS', 'Historial de resoluciones', 'Reputación de dominios e IPs', 'Detecciones de malware'],
    color: '#3b82f6',
  },
  {
    key: 'censys',
    label: 'Censys',
    url: 'censys.io',
    capabilities: ['Escaneo masivo de internet', 'Certificados TLS', 'Infraestructura expuesta', 'ASN y geolocalización'],
    color: '#8b5cf6',
  },
]

const FREE_SOURCES = [
  { label: 'crt.sh',                          desc: 'Certificados TLS — enumeración de subdominios via CT logs' },
  { label: 'RDAP / WHOIS',                    desc: 'Registro de dominios, registrante, fechas, nameservers' },
  { label: 'DNS Live Lookup',                  desc: 'A, AAAA, MX, NS, TXT, CNAME en tiempo real (Node.js dns)' },
  { label: 'Shodan DNS Resolve (con key)',     desc: 'Dominio → IP a través de la API de Shodan' },
  { label: 'Shodan DNS Reverse (con key)',     desc: 'IP → Dominios alojados (reverse DNS de Shodan)' },
]

// ─── Componente ───────────────────────────────────────────────────────────────
export function ThreatIntelDashboard() {
  const { data: statusRaw } = useQuery<{ status: Record<string, boolean> }>({
    queryKey: ['recon-keys-status'],
    queryFn: () => apiFetch<{ status: Record<string, boolean> }>('/integrations/recon-keys/status'),
    staleTime: 60_000,
  })

  const status = statusRaw?.status ?? {}
  const activeCount = Object.values(status).filter(Boolean).length

  return (
    <div className='p-6 max-w-5xl mx-auto space-y-6'>
      {/* Header */}
      <div>
        <h1 className='text-2xl font-bold flex items-center gap-2'>
          <Brain className='h-5 w-5' style={{ color: '#8b5cf6' }} />
          Threat Intel
        </h1>
        <p className='text-sm text-muted-foreground mt-1'>
          Estado de fuentes OSINT y capacidades de reconocimiento
        </p>
      </div>

      {/* KPIs */}
      <div className='grid grid-cols-3 gap-3'>
        {[
          { label: 'APIs configuradas',  value: `${activeCount}/3`,        color: activeCount > 0 ? '#22c55e' : '#6b7280' },
          { label: 'Fuentes libres',     value: `${FREE_SOURCES.length}`,  color: '#22c55e' },
          { label: 'Cobertura total',    value: `${activeCount + FREE_SOURCES.length}`, color: '#8b5cf6' },
        ].map(k => (
          <div key={k.label} className='relative rounded-lg border bg-card px-4 py-3 overflow-hidden'>
            <div className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1'>{k.label}</div>
            <div className='text-2xl font-black tabular-nums' style={{ color: k.color }}>{k.value}</div>
            <div className='absolute bottom-0 left-0 right-0 h-0.5' style={{ background: k.color, opacity: 0.4 }} />
          </div>
        ))}
      </div>

      {/* Acceso rápido a Recon */}
      <div className='rounded-lg border bg-card p-4 flex items-center gap-4'>
        <div className='flex items-center justify-center h-10 w-10 rounded-lg bg-violet-500/10 shrink-0'>
          <Radar className='h-5 w-5 text-violet-500' />
        </div>
        <div className='flex-1 min-w-0'>
          <p className='text-sm font-semibold'>Módulo de Reconocimiento</p>
          <p className='text-xs text-muted-foreground'>
            Consultá IPs y dominios objetivo contra todas las fuentes configuradas
          </p>
        </div>
        <Link to='/recon'>
          <Button size='sm' className='gap-1.5 shrink-0'>
            <Zap className='h-3.5 w-3.5' />
            Ir a Recon
            <ArrowRight className='h-3.5 w-3.5' />
          </Button>
        </Link>
      </div>

      <div className='grid lg:grid-cols-2 gap-4'>
        {/* APIs de pago */}
        <div className='rounded-lg border bg-card p-4'>
          <div className='flex items-center gap-2 mb-4'>
            <Zap className='h-3.5 w-3.5 text-muted-foreground' />
            <span className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>APIs externas</span>
            <span className='ml-auto text-[10px] text-muted-foreground'>{activeCount}/3 configuradas</span>
          </div>

          <div className='space-y-4'>
            {OSINT_SERVICES.map(svc => {
              const active = status[svc.key]
              return (
                <div key={svc.key} className='flex gap-3'>
                  {active
                    ? <CheckCircle2 className='h-3.5 w-3.5 text-green-500 shrink-0 mt-0.5' />
                    : <XCircle    className='h-3.5 w-3.5 text-muted-foreground/30 shrink-0 mt-0.5' />
                  }
                  <div className='flex-1 min-w-0'>
                    <div className='flex items-center gap-2 mb-1'>
                      <span className='text-sm font-semibold' style={{ color: active ? svc.color : undefined }}>
                        {svc.label}
                      </span>
                      <a href={`https://${svc.url}`} target='_blank' rel='noreferrer'
                        className='text-muted-foreground hover:text-foreground transition-colors'>
                        <ExternalLink className='h-3 w-3' />
                      </a>
                      <Badge
                        variant={active ? 'default' : 'secondary'}
                        className={cn('text-[10px] ml-auto shrink-0', active && 'bg-green-500/15 text-green-500 border-green-500/30')}
                      >
                        {active ? 'Activa' : 'Sin configurar'}
                      </Badge>
                    </div>
                    <div className='flex flex-wrap gap-1'>
                      {svc.capabilities.map(cap => (
                        <span key={cap} className={cn(
                          'text-[10px] rounded px-1.5 py-0.5 border',
                          active
                            ? 'bg-muted/60 text-muted-foreground border-border'
                            : 'bg-muted/20 text-muted-foreground/40 border-border/30',
                        )}>
                          {cap}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>

          {activeCount < 3 && (
            <div className='mt-4 pt-3 border-t'>
              <p className='text-[10px] text-muted-foreground'>
                Configurá las API keys en{' '}
                <Link to='/integraciones/api-keys' className='text-primary hover:underline'>Administración → API Keys</Link>
              </p>
            </div>
          )}
        </div>

        {/* Fuentes libres */}
        <div className='rounded-lg border bg-card p-4'>
          <div className='flex items-center gap-2 mb-4'>
            <Globe className='h-3.5 w-3.5 text-muted-foreground' />
            <span className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>Fuentes libres</span>
            <span className='ml-auto text-[10px] font-semibold text-green-500'>{FREE_SOURCES.length} activas</span>
          </div>

          <div className='space-y-3'>
            {FREE_SOURCES.map(s => (
              <div key={s.label} className='flex gap-3'>
                <CheckCircle2 className='h-3 w-3 text-green-500 shrink-0 mt-0.5' />
                <div className='flex-1 min-w-0'>
                  <p className='text-sm font-medium'>{s.label}</p>
                  <p className='text-xs text-muted-foreground'>{s.desc}</p>
                </div>
              </div>
            ))}
          </div>

          <div className='mt-4 pt-3 border-t flex items-center gap-2'>
            <div className='h-1.5 w-1.5 rounded-full bg-green-500 animate-pulse' />
            <span className='text-[10px] text-muted-foreground'>
              Todas las fuentes libres están siempre disponibles, sin configuración adicional
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
