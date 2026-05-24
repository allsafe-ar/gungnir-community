import { useState, useEffect } from 'react'
import {
  Key, Globe, ScanLine, TriangleAlert, Loader2, Save,
  Eye, EyeOff, CheckCircle2, XCircle,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/stores/auth-store'

const RECON_SERVICES = [
  { key: 'shodan',     label: 'Shodan',     url: 'account.shodan.io', desc: 'IP info, puertos abiertos, CVEs, DNS inverso, enumeración de hostnames' },
  { key: 'virustotal', label: 'VirusTotal', url: 'virustotal.com',     desc: 'Passive DNS, historial de resoluciones, reputación de dominios e IPs' },
  { key: 'censys',     label: 'Censys',     url: 'censys.io',          desc: 'Datos de escaneo masivo de internet, certificados TLS' },
]

const FREE_SOURCES = [
  { label: 'crt.sh (Certificate Transparency)', url: 'crt.sh',        desc: 'Enumeración de subdominios' },
  { label: 'RDAP / WHOIS',                       url: 'rdap.org',      desc: 'Registro de dominios, registrante, fechas' },
  { label: 'DNS Live Lookup',                    url: 'Node.js dns',   desc: 'A, AAAA, MX, NS, TXT, CNAME' },
  { label: 'Shodan DNS Resolve (con key)',        url: 'shodan.io',     desc: 'Dominio → IP (Shodan)' },
  { label: 'Shodan DNS Reverse (con key)',        url: 'shodan.io',     desc: 'IP → Dominios alojados' },
]

export function IntegracionesApiKeysPage() {
  const { t } = useTranslation()
  const { auth } = useAuthStore()
  const isAdmin = auth.user?.role === 'admin'

  const [keys, setKeys]     = useState<Record<string, string>>({ shodan: '', virustotal: '', censys: '' })
  const [status, setStatus] = useState<Record<string, boolean>>({})
  const [platforms, setPlatforms] = useState<Array<{ platform: string; enabled: number; has_key: boolean }>>([])
  const [showKey, setShowKey] = useState<Record<string, boolean>>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving]   = useState(false)

  async function load() {
    setLoading(true)
    try {
      const [statusR, platformsR] = await Promise.allSettled([
        apiFetch<{ status: Record<string, boolean> }>('/integrations/recon-keys/status'),
        Promise.resolve([]),
      ])
      if (statusR.status === 'fulfilled') setStatus(statusR.value.status)
      if (platformsR.status === 'fulfilled') setPlatforms(platformsR.value)

      if (isAdmin) {
        const keysR = await apiFetch<{ keys: Record<string, string> }>('/integrations/recon-keys').catch(() => ({ keys: {} }))
        setKeys(prev => ({ ...prev, ...keysR.keys }))
      }
    } catch { } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  async function saveKeys() {
    setSaving(true)
    try {
      await apiFetch('/integrations/recon-keys', { method: 'PUT', body: { keys } })
      toast.success(t('integrations.apikeys.saved'))
      const s = await apiFetch<{ status: Record<string, boolean> }>('/integrations/recon-keys/status')
      setStatus(s.status)
    } catch (e: any) { toast.error(e.message) } finally { setSaving(false) }
  }

  const PLATFORM_META: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
    openvas: { label: 'OpenVAS / GVM',    color: '#22c55e', icon: <ScanLine className='h-3.5 w-3.5' /> },
    nessus:  { label: 'Nessus (Tenable)', color: '#ef4444', icon: <TriangleAlert className='h-3.5 w-3.5' /> },
  }

  const activeReconCount = Object.values(status).filter(Boolean).length

  if (loading) return (
    <div className='flex items-center gap-2 text-sm text-muted-foreground py-12'>
      <Loader2 className='h-4 w-4 animate-spin' />{t('common.loading')}
    </div>
  )

  return (
    <div className='p-6 max-w-5xl mx-auto'>
      <div className='mb-6'>
        <h1 className='text-2xl font-bold flex items-center gap-2'>
          <Key className='h-5 w-5' style={{ color: '#8b5cf6' }} />
          {t('integrations.apikeys.title')}
        </h1>
        <p className='text-sm text-muted-foreground mt-1'>{t('integrations.apikeys.subtitle')}</p>
      </div>

      {/* KPIs */}
      <div className='grid grid-cols-3 gap-3 mb-6'>
        {[
          { label: t('integrations.apikeys.recon'),   value: `${activeReconCount}/${RECON_SERVICES.length}`, color: activeReconCount > 0 ? '#22c55e' : '#6b7280' },
          { label: t('integrations.apikeys.scanners'), value: 'Pro', color: '#6b7280' },
          { label: t('integrations.apikeys.freeSources'), value: FREE_SOURCES.length, color: '#22c55e' },
        ].map(k => (
          <div key={k.label} className='relative rounded-lg border bg-card px-4 py-3 overflow-hidden'>
            <div className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1'>{k.label}</div>
            <div className='text-2xl font-black tabular-nums' style={{ color: k.color }}>{k.value}</div>
            <div className='absolute bottom-0 left-0 right-0 h-0.5' style={{ background: k.color, opacity: 0.4 }} />
          </div>
        ))}
      </div>

      <div className='grid grid-cols-1 lg:grid-cols-2 gap-4'>
        {/* Recon API keys */}
        <div className='rounded-lg border bg-card p-4'>
          <div className='flex items-center gap-2 mb-4'>
            <Key className='h-3.5 w-3.5 text-muted-foreground' />
            <span className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>{t('integrations.apikeys.recon')}</span>
            <span className='ml-auto text-[10px] text-muted-foreground'>{activeReconCount}/{RECON_SERVICES.length} {t('integrations.apikeys.configured')}</span>
          </div>

          <div className='space-y-4'>
            {RECON_SERVICES.map(svc => (
              <div key={svc.key}>
                <div className='flex items-center gap-2 mb-1'>
                  {status[svc.key]
                    ? <CheckCircle2 className='h-3.5 w-3.5 text-green-500 shrink-0' />
                    : <XCircle className='h-3.5 w-3.5 text-muted-foreground/30 shrink-0' />
                  }
                  <Label className='text-sm font-medium'>{svc.label}</Label>
                  <a href={`https://${svc.url}`} target='_blank' rel='noreferrer' className='text-[10px] text-muted-foreground hover:underline ml-0.5'>{svc.url}</a>
                  <Badge variant={status[svc.key] ? 'default' : 'secondary'}
                    className={cn('text-[10px] ml-auto shrink-0', status[svc.key] && 'bg-green-500/15 text-green-500 border-green-500/30')}
                  >
                    {status[svc.key] ? t('integrations.apikeys.configured') : t('integrations.apikeys.notConfigured')}
                  </Badge>
                </div>
                <p className='text-xs text-muted-foreground mb-1.5 ml-5'>{svc.desc}</p>
                {isAdmin && (
                  <div className='relative ml-5'>
                    <Input
                      type={showKey[svc.key] ? 'text' : 'password'}
                      placeholder={status[svc.key] ? '***configured***' : `API key de ${svc.label}`}
                      value={keys[svc.key] || ''}
                      onChange={e => setKeys(k => ({ ...k, [svc.key]: e.target.value }))}
                      className='h-8 text-sm font-mono pr-8'
                    />
                    <button
                      type='button'
                      onClick={() => setShowKey(s => ({ ...s, [svc.key]: !s[svc.key] }))}
                      className='absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground'
                    >
                      {showKey[svc.key] ? <EyeOff className='h-3.5 w-3.5' /> : <Eye className='h-3.5 w-3.5' />}
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>

          {isAdmin && (
            <div className='flex justify-end mt-4 pt-3 border-t'>
              <Button size='sm' onClick={saveKeys} disabled={saving}>
                {saving ? <Loader2 className='h-3.5 w-3.5 mr-1.5 animate-spin' /> : <Save className='h-3.5 w-3.5 mr-1.5' />}
                {t('common.save')}
              </Button>
            </div>
          )}
        </div>

        <div className='space-y-3'>
          {/* Scanner status — Pro feature */}
          <div className='rounded-lg border border-dashed bg-muted/20 p-4'>
            <div className='flex items-center gap-2 mb-3'>
              <ScanLine className='h-3.5 w-3.5 text-muted-foreground' />
              <span className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>{t('integrations.apikeys.scanners')}</span>
              <Badge variant='outline' className='ml-auto text-[10px] text-muted-foreground'>Pro</Badge>
            </div>
            <div className='space-y-2 text-sm text-muted-foreground'>
              <p>Live scanner feeds (Nessus, OpenVAS) are available in <strong>Gungnir Pro</strong>.</p>
              <p className='text-xs'>XML import from .nessus / .xml files is available in all editions — use it from within any engagement phase.</p>
            </div>
          </div>

          {/* Free sources */}
          <div className='rounded-lg border bg-card p-4'>
            <div className='flex items-center gap-2 mb-3'>
              <Globe className='h-3.5 w-3.5 text-muted-foreground' />
              <span className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>{t('integrations.apikeys.freeSources')}</span>
              <span className='ml-auto text-[10px] text-muted-foreground'>{FREE_SOURCES.length} activas</span>
            </div>
            <div className='space-y-1.5'>
              {FREE_SOURCES.map(s => (
                <div key={s.label} className='flex items-center gap-2 py-0.5'>
                  <CheckCircle2 className='h-3 w-3 text-green-500 shrink-0' />
                  <span className='text-sm flex-1'>{s.label}</span>
                  <span className='text-[10px] text-muted-foreground shrink-0'>{s.desc}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
