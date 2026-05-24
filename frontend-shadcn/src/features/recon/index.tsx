import { useState, useEffect } from 'react'
import {
  Globe, Search, Loader2, Server,
  ChevronDown, ChevronRight,
  Building2, Network, Shield, FileSearch,
  Copy,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { cn } from '@/lib/utils'

// ── Types ───────────────────────────────────────────────────────────────────
type ShodanService = {
  port: number; transport: string; product?: string; version?: string
  banner?: string; http_title?: string; cpe?: string
}

type ShodanResult = {
  ok: boolean; error?: string
  ip?: string; org?: string; isp?: string; country?: string; country_code?: string
  city?: string; region?: string; os?: string; asn?: string; last_update?: string
  ports?: number[]; hostnames?: string[]; domains?: string[]; tags?: string[]
  vulns?: string[]; services?: ShodanService[]
}

type RdapResult = {
  ok: boolean; error?: string
  domain?: string; status?: string[]; registered?: string; expires?: string
  updated?: string; age_days?: number; registrant?: string; registrant_org?: string
  registrant_email?: string; registrar?: string; nameservers?: string[]
}

type CrtResult = { ok: boolean; error?: string; subdomains?: string[]; total?: number }

type DnsResult = {
  ok: boolean; error?: string
  a?: string[]; aaaa?: string[]; mx?: Array<{ exchange: string; priority: number }>
  ns?: string[]; txt?: string[]; cname?: string[]
}

type IPQueryResult = {
  type: 'ip'; target: string
  shodan: ShodanResult
  reverse: { ok: boolean; error?: string; data?: Record<string, string[]> }
}

type DomainQueryResult = {
  type: 'domain'; target: string
  rdap: RdapResult
  crt: CrtResult
  dns: DnsResult
  resolve: { ok: boolean; error?: string; data?: Record<string, string> } | null
  hosts: ShodanResult[]
}

type QueryResult = IPQueryResult | DomainQueryResult

// ── Small helpers ───────────────────────────────────────────────────────────
function fmtDate(val: string | undefined) {
  if (!val) return '—'
  const d = new Date(val)
  return isNaN(d.getTime()) ? val : d.toLocaleDateString('es-AR', { year: 'numeric', month: 'short', day: 'numeric' })
}

function CopyBtn({ text }: { text: string }) {
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); toast.success('Copiado') }}
      className='text-muted-foreground hover:text-foreground transition-colors'
    >
      <Copy className='h-3 w-3' />
    </button>
  )
}

function Tag({ children, color = '#6b7280' }: { children: React.ReactNode; color?: string }) {
  return (
    <span className='inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border' style={{ color, borderColor: `${color}40`, background: `${color}15` }}>
      {children}
    </span>
  )
}

function Section({ icon, title, children, defaultOpen = true }: { icon: React.ReactNode; title: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className='rounded-lg border bg-card overflow-hidden'>
      <button
        onClick={() => setOpen(o => !o)}
        className='w-full flex items-center gap-2 px-4 py-3 text-left hover:bg-muted/20 transition-colors'
      >
        <span className='text-muted-foreground'>{icon}</span>
        <span className='text-sm font-semibold flex-1'>{title}</span>
        {open ? <ChevronDown className='h-3.5 w-3.5 text-muted-foreground' /> : <ChevronRight className='h-3.5 w-3.5 text-muted-foreground' />}
      </button>
      {open && <div className='px-4 pb-4 pt-1'>{children}</div>}
    </div>
  )
}

function Kv({ label, value }: { label: string; value?: string | number | null }) {
  if (!value && value !== 0) return null
  return (
    <div className='flex items-baseline gap-2'>
      <span className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-24 shrink-0'>{label}</span>
      <span className='text-sm font-mono flex items-center gap-1.5'>{String(value)} <CopyBtn text={String(value)} /></span>
    </div>
  )
}

// ── Shodan IP result card ───────────────────────────────────────────────────
function ShodanIPCard({ data }: { data: ShodanResult }) {
  const { t } = useTranslation()

  if (!data.ok) {
    return (
      <div className='rounded-lg border border-destructive/20 bg-destructive/5 px-4 py-3 text-sm text-destructive'>
        Shodan: {data.error}
      </div>
    )
  }

  const sevColor = (data.vulns?.length || 0) > 0 ? '#ef4444' : '#22c55e'

  return (
    <Section icon={<Server className='h-3.5 w-3.5' />} title={`Shodan — ${data.ip}`}>
      <div className='space-y-4'>
        {/* KPIs */}
        <div className='grid grid-cols-2 md:grid-cols-4 gap-2'>
          {[
            { label: 'Puertos abiertos', value: data.ports?.length ?? 0, color: '#3b82f6' },
            { label: 'CVEs', value: data.vulns?.length ?? 0, color: sevColor },
            { label: 'Servicios', value: data.services?.length ?? 0, color: '#8b5cf6' },
            { label: 'Hostnames', value: data.hostnames?.length ?? 0, color: '#f59e0b' },
          ].map(k => (
            <div key={k.label} className='rounded border bg-muted/30 px-3 py-2'>
              <div className='text-[9px] font-semibold uppercase tracking-wider text-muted-foreground mb-0.5'>{k.label}</div>
              <div className='text-xl font-black tabular-nums' style={{ color: k.color }}>{k.value}</div>
            </div>
          ))}
        </div>

        {/* Info */}
        <div className='space-y-1.5'>
          <Kv label='IP' value={data.ip} />
          <Kv label='Organización' value={data.org} />
          <Kv label='ISP' value={data.isp} />
          <Kv label='ASN' value={data.asn} />
          <Kv label='País' value={data.country ? `${data.country} (${data.country_code})` : data.country_code} />
          <Kv label='Ciudad' value={data.city} />
          <Kv label='OS' value={data.os} />
          <Kv label='Última vista' value={data.last_update} />
        </div>

        {/* Ports */}
        {(data.ports || []).length > 0 && (
          <div>
            <div className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5'>Puertos</div>
            <div className='flex flex-wrap gap-1.5'>
              {data.ports!.map(p => <Tag key={p} color='#3b82f6'>{p}</Tag>)}
            </div>
          </div>
        )}

        {/* CVEs */}
        {(data.vulns || []).length > 0 && (
          <div>
            <div className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5'>CVEs detectados</div>
            <div className='flex flex-wrap gap-1.5'>
              {data.vulns!.map(v => (
                <a key={v} href={`https://nvd.nist.gov/vuln/detail/${v}`} target='_blank' rel='noreferrer'>
                  <Tag color='#ef4444'>{v}</Tag>
                </a>
              ))}
            </div>
          </div>
        )}

        {/* Tags */}
        {(data.tags || []).length > 0 && (
          <div>
            <div className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5'>Tags</div>
            <div className='flex flex-wrap gap-1.5'>
              {data.tags!.map(tag => <Tag key={tag}>{tag}</Tag>)}
            </div>
          </div>
        )}

        {/* Hostnames */}
        {(data.hostnames || []).length > 0 && (
          <div>
            <div className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5'>Hostnames</div>
            <div className='flex flex-wrap gap-1.5'>
              {data.hostnames!.map(h => <Tag key={h} color='#f59e0b'>{h}</Tag>)}
            </div>
          </div>
        )}

        {/* Services */}
        {(data.services || []).length > 0 && (
          <div>
            <div className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5'>Servicios ({data.services!.length})</div>
            <div className='space-y-1.5 max-h-64 overflow-y-auto pr-1'>
              {data.services!.map((svc, i) => (
                <div key={i} className='rounded border bg-muted/20 px-2.5 py-1.5 text-xs flex items-start gap-3'>
                  <span className='font-bold font-mono w-16 shrink-0' style={{ color: '#3b82f6' }}>{svc.port}/{svc.transport}</span>
                  <span className='flex-1 text-muted-foreground truncate'>
                    {svc.product ? <span className='text-foreground font-medium'>{svc.product}</span> : null}
                    {svc.version ? ` ${svc.version}` : ''}
                    {svc.http_title ? <span className='ml-2 text-muted-foreground'>— {svc.http_title}</span> : null}
                    {!svc.product && !svc.http_title && svc.banner ? svc.banner.slice(0, 80) : ''}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </Section>
  )
}

// ── IP result view ──────────────────────────────────────────────────────────
function IPResultView({ result }: { result: IPQueryResult }) {
  const reverseDomains = result.reverse?.ok ? Object.values(result.reverse.data || {}).flat() : []

  return (
    <div className='space-y-3'>
      <ShodanIPCard data={result.shodan} />

      {reverseDomains.length > 0 && (
        <Section icon={<Globe className='h-3.5 w-3.5' />} title={`Dominios en ${result.target} (${reverseDomains.length})`}>
          <div className='flex flex-wrap gap-1.5'>
            {reverseDomains.map(d => <Tag key={d} color='#8b5cf6'>{d}</Tag>)}
          </div>
        </Section>
      )}

      {!result.shodan.ok && !result.reverse?.ok && (
        <div className='rounded-lg border px-4 py-6 text-sm text-center text-muted-foreground'>
          Sin datos disponibles. Verificá que la API key de Shodan esté configurada.
        </div>
      )}
    </div>
  )
}

// ── Domain result view ──────────────────────────────────────────────────────
function DomainResultView({ result }: { result: DomainQueryResult }) {
  const { t } = useTranslation()

  return (
    <div className='space-y-3'>
      {/* WHOIS / RDAP */}
      <Section icon={<Building2 className='h-3.5 w-3.5' />} title='WHOIS / RDAP'>
        {result.rdap.ok ? (
          <div className='space-y-1.5'>
            <Kv label='Dominio' value={result.rdap.domain} />
            <Kv label='Registrante' value={result.rdap.registrant} />
            <Kv label='Organización' value={result.rdap.registrant_org} />
            <Kv label='Email' value={result.rdap.registrant_email} />
            <Kv label='Registrar' value={result.rdap.registrar} />
            <Kv label='Registrado' value={result.rdap.registered ? fmtDate(result.rdap.registered) : undefined} />
            <Kv label='Expira' value={result.rdap.expires ? fmtDate(result.rdap.expires) : undefined} />
            {result.rdap.age_days != null && (
              <div className='flex items-baseline gap-2'>
                <span className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-24 shrink-0'>Antigüedad</span>
                <span className='text-sm'>
                  <span className={cn('font-semibold', result.rdap.age_days < 30 ? 'text-red-400' : result.rdap.age_days < 180 ? 'text-amber-400' : 'text-green-400')}>
                    {result.rdap.age_days} días
                  </span>
                  {result.rdap.age_days < 30 && <span className='ml-2 text-[10px] text-red-400'>⚠ Dominio reciente</span>}
                </span>
              </div>
            )}
            {(result.rdap.status || []).length > 0 && (
              <div className='flex items-baseline gap-2'>
                <span className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-24 shrink-0'>Estado</span>
                <div className='flex flex-wrap gap-1'>
                  {result.rdap.status!.map(s => <Tag key={s}>{s}</Tag>)}
                </div>
              </div>
            )}
            {(result.rdap.nameservers || []).length > 0 && (
              <div className='flex items-baseline gap-2'>
                <span className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-24 shrink-0'>Nameservers</span>
                <div className='flex flex-wrap gap-1'>
                  {result.rdap.nameservers!.map(ns => <Tag key={ns} color='#8b5cf6'>{ns}</Tag>)}
                </div>
              </div>
            )}
          </div>
        ) : (
          <p className='text-sm text-muted-foreground'>RDAP no disponible: {result.rdap.error}</p>
        )}
      </Section>

      {/* DNS */}
      <Section icon={<Network className='h-3.5 w-3.5' />} title='DNS'>
        {result.dns.ok ? (
          <div className='space-y-2'>
            {(result.dns.a || []).length > 0 && (
              <div className='flex items-start gap-2'>
                <span className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-10 shrink-0 mt-0.5'>A</span>
                <div className='flex flex-wrap gap-1.5'>{result.dns.a!.map(ip => <Tag key={ip} color='#22c55e'>{ip}</Tag>)}</div>
              </div>
            )}
            {(result.dns.aaaa || []).length > 0 && (
              <div className='flex items-start gap-2'>
                <span className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-10 shrink-0 mt-0.5'>AAAA</span>
                <div className='flex flex-wrap gap-1.5'>{result.dns.aaaa!.map(ip => <Tag key={ip} color='#22c55e'>{ip}</Tag>)}</div>
              </div>
            )}
            {(result.dns.mx || []).length > 0 && (
              <div className='flex items-start gap-2'>
                <span className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-10 shrink-0 mt-0.5'>MX</span>
                <div className='flex flex-wrap gap-1.5'>
                  {result.dns.mx!.map(m => <Tag key={m.exchange} color='#3b82f6'>{m.priority} {m.exchange}</Tag>)}
                </div>
              </div>
            )}
            {(result.dns.ns || []).length > 0 && (
              <div className='flex items-start gap-2'>
                <span className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-10 shrink-0 mt-0.5'>NS</span>
                <div className='flex flex-wrap gap-1.5'>{result.dns.ns!.map(ns => <Tag key={ns} color='#8b5cf6'>{ns}</Tag>)}</div>
              </div>
            )}
            {(result.dns.txt || []).length > 0 && (
              <div className='flex items-start gap-2'>
                <span className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-10 shrink-0 mt-0.5'>TXT</span>
                <div className='space-y-0.5 flex-1'>
                  {result.dns.txt!.map((txt, i) => (
                    <div key={i} className='text-xs font-mono bg-muted/30 rounded px-2 py-0.5 break-all'>{txt}</div>
                  ))}
                </div>
              </div>
            )}
            {(result.dns.cname || []).length > 0 && (
              <div className='flex items-start gap-2'>
                <span className='text-[10px] font-semibold uppercase tracking-wider text-muted-foreground w-10 shrink-0 mt-0.5'>CNAME</span>
                <div className='flex flex-wrap gap-1.5'>{result.dns.cname!.map(c => <Tag key={c} color='#f59e0b'>{c}</Tag>)}</div>
              </div>
            )}
          </div>
        ) : (
          <p className='text-sm text-muted-foreground'>DNS lookup falló: {result.dns.error}</p>
        )}
      </Section>

      {/* Shodan host info for resolved IP */}
      {result.hosts.map((host, i) => (
        <ShodanIPCard key={i} data={host} />
      ))}
      {result.hosts.length === 0 && result.dns.a && result.dns.a.length > 0 && (
        <div className='rounded-lg border px-4 py-3 text-xs text-muted-foreground'>
          <Shield className='h-3.5 w-3.5 inline mr-1.5' />
          IP resuelta: {result.dns.a[0]} — configurá la API key de Shodan para obtener información del host.
        </div>
      )}

      {/* crt.sh subdomains */}
      <Section icon={<FileSearch className='h-3.5 w-3.5' />} title={`Subdominios (crt.sh) — ${result.crt.ok ? result.crt.total ?? 0 : '—'}`} defaultOpen={false}>
        {result.crt.ok ? (
          result.crt.subdomains && result.crt.subdomains.length > 0 ? (
            <div className='flex flex-wrap gap-1.5 max-h-48 overflow-y-auto'>
              {result.crt.subdomains.map(s => <Tag key={s} color='#8b5cf6'>{s}</Tag>)}
            </div>
          ) : (
            <p className='text-sm text-muted-foreground'>Sin subdominios en crt.sh</p>
          )
        ) : (
          <p className='text-sm text-muted-foreground'>crt.sh no disponible: {result.crt.error}</p>
        )}
      </Section>
    </div>
  )
}

// ── REMOVED: ReconKeysPanel moved to /integraciones/api-keys ───────────────
function _unused_ReconKeysPanel_deleted() {
  const { t } = useTranslation()
  const [keys, setKeys] = useState<Record<string, string>>({ shodan: '', virustotal: '', censys: '' })
  const [status, setStatus] = useState<Record<string, boolean>>({})
  const [showKey, setShowKey] = useState<Record<string, boolean>>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  const SERVICES = [
    { key: 'shodan',      label: 'Shodan',     url: 'account.shodan.io',     desc: 'IP info, puertos, CVEs, DNS reverso' },
    { key: 'virustotal',  label: 'VirusTotal', url: 'virustotal.com',         desc: 'Passive DNS, reputación de dominios/IPs' },
    { key: 'censys',      label: 'Censys',     url: 'censys.io',              desc: 'Internet-wide scan data, certificados' },
  ]

  useEffect(() => {
    setLoading(true)
    Promise.all([
      apiFetch<{ keys: Record<string, string> }>('/integrations/recon-keys').catch(() => ({ keys: {} })),
      apiFetch<{ status: Record<string, boolean> }>('/integrations/recon-keys/status').catch(() => ({ status: {} })),
    ]).then(([k, s]) => {
      setKeys(prev => ({ ...prev, ...k.keys }))
      setStatus(s.status)
    }).finally(() => setLoading(false))
  }, [])

  async function save() {
    setSaving(true)
    try {
      await apiFetch('/integrations/recon-keys', { method: 'PUT', body: { keys } })
      toast.success(t('common.success'))
      const s = await apiFetch<{ status: Record<string, boolean> }>('/integrations/recon-keys/status')
      setStatus(s.status)
    } catch (e: any) {
      toast.error(e.message)
    } finally {
      setSaving(false)
    }
  }

  if (loading) return (
    <div className='flex items-center gap-2 text-sm text-muted-foreground py-4'>
      <Loader2 className='h-4 w-4 animate-spin' />{t('common.loading')}
    </div>
  )

  return (
    <div className='space-y-3'>
      <div className='rounded-lg border bg-card p-4'>
        <div className='flex items-center gap-2 mb-4'>
          <Key className='h-3.5 w-3.5 text-muted-foreground' />
          <span className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>{t('recon.keys.title')}</span>
        </div>
        <div className='space-y-4'>
          {SERVICES.map(svc => (
            <div key={svc.key}>
              <div className='flex items-center gap-2 mb-1.5'>
                {status[svc.key]
                  ? <CheckCircle2 className='h-3.5 w-3.5 text-green-500 shrink-0' />
                  : <XCircle className='h-3.5 w-3.5 text-muted-foreground/30 shrink-0' />
                }
                <Label className='text-sm font-medium'>{svc.label}</Label>
                <span className='text-[10px] text-muted-foreground ml-1'>{svc.url}</span>
                <Badge variant={status[svc.key] ? 'default' : 'secondary'}
                  className={cn('text-[10px] ml-auto shrink-0', status[svc.key] && 'bg-green-500/15 text-green-500 border-green-500/30')}
                >
                  {status[svc.key] ? t('recon.keys.configured') : t('recon.keys.notConfigured')}
                </Badge>
              </div>
              <p className='text-xs text-muted-foreground mb-1.5 ml-5'>{svc.desc}</p>
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
            </div>
          ))}
        </div>
        <div className='flex justify-end mt-4'>
          <Button size='sm' onClick={save} disabled={saving}>
            {saving ? <Loader2 className='h-3.5 w-3.5 mr-1.5 animate-spin' /> : <Save className='h-3.5 w-3.5 mr-1.5' />}
            {t('common.save')}
          </Button>
        </div>
      </div>

      {/* Free sources */}
      <div className='rounded-lg border bg-card p-4'>
        <div className='flex items-center gap-2 mb-3'>
          <Globe className='h-3.5 w-3.5 text-muted-foreground' />
          <span className='text-xs font-semibold uppercase tracking-widest text-muted-foreground'>{t('recon.keys.freeSources')}</span>
        </div>
        <div className='space-y-1.5'>
          {[
            { label: 'crt.sh (Certificate Transparency)',  url: 'crt.sh',          desc: 'Enumeración de subdominios' },
            { label: 'RDAP / WHOIS',                        url: 'rdap.org',         desc: 'Información de registro de dominios' },
            { label: 'DNS Live Lookup',                     url: 'Node.js dns',      desc: 'Registros A, AAAA, MX, NS, TXT, CNAME' },
            { label: 'Shodan DNS Reverse (con key)',        url: 'api.shodan.io',    desc: 'Dominios alojados en una IP' },
            { label: 'Shodan DNS Resolve (con key)',        url: 'api.shodan.io',    desc: 'IP de un dominio/hostname' },
          ].map(s => (
            <div key={s.label} className='flex items-center gap-2 py-0.5'>
              <CheckCircle2 className='h-3 w-3 text-green-500 shrink-0' />
              <span className='text-sm flex-1'>{s.label}</span>
              <span className='text-[10px] text-muted-foreground'>{s.desc}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Main recon page ─────────────────────────────────────────────────────────
export function ReconPage() {
  const { t } = useTranslation()

  const [target, setTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<QueryResult | null>(null)
  const [tab, setTab] = useState('search')

  async function query() {
    const t2 = target.trim()
    if (!t2) return
    setLoading(true); setResult(null)
    try {
      const r = await apiFetch<QueryResult>('/integrations/recon/query', { method: 'POST', body: { target: t2 } })
      setResult(r)
      setTab('search')
    } catch (e: any) {
      toast.error(e.message)
    } finally {
      setLoading(false)
    }
  }

  function handleKey(e: React.KeyboardEvent) {
    if (e.key === 'Enter') query()
  }

  return (
    <div className='p-6 max-w-6xl mx-auto'>
      <div className='mb-6'>
        <h1 className='text-2xl font-bold flex items-center gap-2'>
          <Globe className='h-5 w-5' style={{ color: '#3b82f6' }} />
          {t('recon.title')}
        </h1>
        <p className='text-sm text-muted-foreground mt-1'>{t('recon.subtitle')}</p>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className='mb-5'>
          <TabsTrigger value='search' className='gap-1.5'>
            <Search className='h-3.5 w-3.5' />
            {t('recon.tab.search')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value='search'>
          {/* Search bar */}
          <div className='flex gap-2 mb-6'>
            <div className='relative flex-1'>
              <Search className='absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground' />
              <Input
                placeholder={t('recon.search.placeholder')}
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={handleKey}
                className='pl-9 font-mono'
                disabled={loading}
              />
            </div>
            <Button onClick={query} disabled={loading || !target.trim()}>
              {loading ? <Loader2 className='h-4 w-4 animate-spin mr-1.5' /> : <Search className='h-4 w-4 mr-1.5' />}
              {loading ? t('common.loading') : t('recon.search.btn')}
            </Button>
          </div>

          {/* Query type hint */}
          {!result && !loading && (
            <div className='rounded-lg border bg-card p-6 text-center'>
              <Globe className='h-8 w-8 text-muted-foreground/30 mx-auto mb-3' />
              <p className='text-sm font-medium mb-1'>{t('recon.search.hint')}</p>
              <div className='flex justify-center gap-3 flex-wrap mt-3'>
                {[
                  { label: 'IP', ex: '8.8.8.8', color: '#22c55e' },
                  { label: 'Dominio', ex: 'target.com', color: '#3b82f6' },
                  { label: 'Subdominio', ex: 'api.target.com', color: '#8b5cf6' },
                ].map(eg => (
                  <button
                    key={eg.ex}
                    onClick={() => setTarget(eg.ex)}
                    className='px-3 py-1.5 rounded border text-xs font-mono transition-colors hover:bg-muted'
                    style={{ borderColor: `${eg.color}40`, color: eg.color }}
                  >
                    {eg.label}: <strong>{eg.ex}</strong>
                  </button>
                ))}
              </div>
            </div>
          )}

          {loading && (
            <div className='flex flex-col items-center gap-3 py-16 text-muted-foreground'>
              <Loader2 className='h-8 w-8 animate-spin' />
              <p className='text-sm'>{t('recon.search.querying')} <span className='font-mono font-medium'>{target}</span>...</p>
            </div>
          )}

          {result && !loading && (
            <>
              <div className='flex items-center gap-2 mb-4'>
                <Badge variant='outline' className='font-mono text-xs'>
                  {result.type === 'ip' ? '🌐 IP' : '🔗 Dominio'}
                </Badge>
                <span className='font-mono text-sm font-semibold'>{result.target}</span>
                <Button variant='ghost' size='sm' className='ml-auto text-xs h-7' onClick={() => { setResult(null); setTarget('') }}>
                  Nueva búsqueda
                </Button>
              </div>
              {result.type === 'ip'
                ? <IPResultView result={result} />
                : <DomainResultView result={result} />
              }
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}
