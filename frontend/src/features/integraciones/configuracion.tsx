/**
 * Configuración de Scanners — Solo admin.
 * Movido del tab Configuración de IntegracionesPage al menú Administración.
 */

import { useState, useEffect } from 'react'
import { ScanLine, TriangleAlert, Settings2, Loader2, Save, Eye, EyeOff, ShieldOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/stores/auth-store'

type PlatformRow = {
  platform: string
  url: string | null
  has_key: boolean
  api_key?: string
  extra_config?: any
  enabled: number
}

const META: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
  openvas: { label: 'OpenVAS / GVM',    color: '#22c55e', icon: <ScanLine className='h-4 w-4' /> },
  nessus:  { label: 'Nessus (Tenable)', color: '#ef4444', icon: <TriangleAlert className='h-4 w-4' /> },
}

export function ScannersConfigPage() {
  const { t } = useTranslation()
  const { auth } = useAuthStore()
  const isAdmin = auth.user?.role === 'admin'

  const [platforms, setPlatforms] = useState<PlatformRow[]>([])
  const [loading, setLoading]     = useState(true)
  const [saving, setSaving]       = useState<string | null>(null)
  const [form, setForm]           = useState<Record<string, any>>({})
  const [showKey, setShowKey]     = useState<Record<string, boolean>>({})

  useEffect(() => {
    if (!isAdmin) return
    setLoading(true)
    apiFetch<PlatformRow[]>('/integrations/platforms')
      .then(data => {
        setPlatforms(data)
        const init: Record<string, any> = {}
        for (const p of data) {
          init[`${p.platform}_url`]     = p.url || ''
          init[`${p.platform}_api_key`] = p.has_key ? '***configured***' : ''
          init[`${p.platform}_secret`]  = p.extra_config?.secretKey || ''
          init[`${p.platform}_enabled`] = !!(p.enabled)
        }
        setForm(init)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [isAdmin])

  async function savePlatform(platform: string) {
    setSaving(platform)
    try {
      const body: any = {
        url:     form[`${platform}_url`] || null,
        api_key: form[`${platform}_api_key`],
        enabled: form[`${platform}_enabled`] ?? false,
      }
      if (platform === 'nessus') body.extra_config = { secretKey: form[`${platform}_secret`] || '' }
      await apiFetch(`/integrations/platforms/${platform}`, { method: 'PUT', body })
      toast.success(t('integrations.config.saved'))
    } catch (e: any) { toast.error(e.message) } finally { setSaving(null) }
  }

  // ── Guard ──────────────────────────────────────────────────────────────────
  if (!isAdmin) {
    return (
      <div className='p-6 flex flex-col items-center justify-center min-h-64 gap-3'>
        <ShieldOff className='h-10 w-10 text-muted-foreground/30' />
        <p className='text-sm text-muted-foreground'>Acceso restringido — solo administradores</p>
      </div>
    )
  }

  return (
    <div className='p-6 max-w-4xl mx-auto space-y-6'>
      {/* Header */}
      <div>
        <h1 className='text-2xl font-bold flex items-center gap-2'>
          <Settings2 className='h-5 w-5 text-muted-foreground' />
          Configuración de Scanners
        </h1>
        <p className='text-sm text-muted-foreground mt-1'>
          URLs y credenciales de acceso para OpenVAS y Nessus
        </p>
      </div>

      {loading ? (
        <div className='flex items-center gap-2 text-sm text-muted-foreground py-8'>
          <Loader2 className='h-4 w-4 animate-spin' />{t('common.loading')}
        </div>
      ) : (
        <div className='space-y-4'>
          {platforms.map(p => {
            const meta = META[p.platform]
            if (!meta) return null
            const isEnabled = form[`${p.platform}_enabled`]
            return (
              <div key={p.platform} className='rounded-lg border bg-card p-5'>
                <div className='flex items-center gap-3 mb-4'>
                  <span style={{ color: meta.color }}>{meta.icon}</span>
                  <span className='font-semibold text-sm'>{meta.label}</span>
                  <Badge
                    variant={isEnabled ? 'default' : 'secondary'}
                    className={cn('text-[10px] ml-1', isEnabled && 'bg-green-500/15 text-green-500 border-green-500/30')}
                  >
                    {isEnabled ? t('integrations.config.enabled') : t('integrations.config.disabled')}
                  </Badge>
                </div>

                <div className='grid grid-cols-1 md:grid-cols-2 gap-3 mb-4'>
                  {/* URL */}
                  <div>
                    <Label className='text-xs text-muted-foreground mb-1 block'>{t('integrations.config.url')}</Label>
                    <Input
                      placeholder={`https://${p.platform}-server:9390`}
                      value={form[`${p.platform}_url`] || ''}
                      onChange={e => setForm(f => ({ ...f, [`${p.platform}_url`]: e.target.value }))}
                      className='h-8 text-sm font-mono'
                    />
                  </div>

                  {/* Access Key / API Key */}
                  <div>
                    <Label className='text-xs text-muted-foreground mb-1 block'>
                      {p.platform === 'nessus' ? t('integrations.config.accessKey') : t('integrations.config.apiKey')}
                    </Label>
                    <div className='relative'>
                      <Input
                        type={showKey[p.platform] ? 'text' : 'password'}
                        placeholder={t('integrations.config.keyPlaceholder')}
                        value={form[`${p.platform}_api_key`] || ''}
                        onChange={e => setForm(f => ({ ...f, [`${p.platform}_api_key`]: e.target.value }))}
                        className='h-8 text-sm font-mono pr-8'
                      />
                      <button
                        type='button'
                        onClick={() => setShowKey(s => ({ ...s, [p.platform]: !s[p.platform] }))}
                        className='absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground'
                      >
                        {showKey[p.platform] ? <EyeOff className='h-3.5 w-3.5' /> : <Eye className='h-3.5 w-3.5' />}
                      </button>
                    </div>
                  </div>

                  {/* Secret Key (Nessus only) */}
                  {p.platform === 'nessus' && (
                    <div>
                      <Label className='text-xs text-muted-foreground mb-1 block'>{t('integrations.config.secretKey')}</Label>
                      <div className='relative'>
                        <Input
                          type={showKey[`${p.platform}_secret`] ? 'text' : 'password'}
                          placeholder={t('integrations.config.keyPlaceholder')}
                          value={form[`${p.platform}_secret`] || ''}
                          onChange={e => setForm(f => ({ ...f, [`${p.platform}_secret`]: e.target.value }))}
                          className='h-8 text-sm font-mono pr-8'
                        />
                        <button
                          type='button'
                          onClick={() => setShowKey(s => ({ ...s, [`${p.platform}_secret`]: !s[`${p.platform}_secret`] }))}
                          className='absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground'
                        >
                          {showKey[`${p.platform}_secret`] ? <EyeOff className='h-3.5 w-3.5' /> : <Eye className='h-3.5 w-3.5' />}
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                <div className='flex items-center justify-between'>
                  <label className='flex items-center gap-2 cursor-pointer'>
                    <input
                      type='checkbox'
                      checked={!!form[`${p.platform}_enabled`]}
                      onChange={e => setForm(f => ({ ...f, [`${p.platform}_enabled`]: e.target.checked }))}
                      className='accent-primary'
                    />
                    <span className='text-xs'>{t('integrations.config.enabledLabel')}</span>
                  </label>
                  <Button size='sm' onClick={() => savePlatform(p.platform)} disabled={saving === p.platform}>
                    {saving === p.platform
                      ? <Loader2 className='h-3.5 w-3.5 mr-1.5 animate-spin' />
                      : <Save className='h-3.5 w-3.5 mr-1.5' />
                    }
                    {t('common.save')}
                  </Button>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
