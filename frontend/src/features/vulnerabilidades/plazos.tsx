/**
 * Plazos de remediación por severidad (etapa 2): la política del cliente elegido y la global.
 *
 * La del cliente la cambian un administrador o un auditor; la global (la que rige para los clientes
 * sin política propia) es del administrador de la instalación. Un campo vacío es "sin plazo".
 */
import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Loader2, RotateCcw, Save } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { SEVERIDADES, usePermisos, type Severidad } from './comun'

type Politica = Record<Severidad, number | null>
interface RespuestaPlazos {
  defecto: Politica
  global: Politica
  cliente: Politica | null
  efectiva: Politica
  kev_dias_max: number
  por_vencer_dias: number
  puede_editar_global: boolean
}

type Formulario = Record<Severidad, string>
const aFormulario = (p: Politica): Formulario => Object.fromEntries(SEVERIDADES.map((s) => [s, p[s] == null ? '' : String(p[s])])) as Formulario
const aPolitica = (f: Formulario) => Object.fromEntries(SEVERIDADES.map((s) => [s, f[s].trim() === '' ? null : Number(f[s])]))

function EditorPolitica({ inicial, editable, guardando, onGuardar, extra }: {
  inicial: Politica; editable: boolean; guardando: boolean; onGuardar: (p: ReturnType<typeof aPolitica>) => void; extra?: React.ReactNode
}) {
  const { t } = useTranslation()
  const [f, setF] = useState<Formulario>(() => aFormulario(inicial))
  const valido = SEVERIDADES.every((s) => f[s].trim() === '' || (/^\d{1,4}$/.test(f[s].trim()) && Number(f[s]) >= 1 && Number(f[s]) <= 3650))
  return (
    <div className='space-y-3'>
      <div className='grid grid-cols-2 gap-3 sm:grid-cols-5'>
        {SEVERIDADES.map((s) => (
          <div key={s} className='space-y-1'>
            <Label>{t(`finding.sev_${s}`)}</Label>
            <Input value={f[s]} inputMode='numeric' disabled={!editable} placeholder={t('vulns.plazos.sinPlazoCorto')}
              onChange={(e) => setF((x) => ({ ...x, [s]: e.target.value }))} />
          </div>
        ))}
      </div>
      {editable ? (
        <div className='flex flex-wrap items-center gap-2'>
          <Button size='sm' onClick={() => onGuardar(aPolitica(f))} disabled={!valido || guardando}>
            {guardando ? <Loader2 className='mr-1 size-4 animate-spin' /> : <Save className='mr-1 size-4' />}{t('common.save')}
          </Button>
          {extra}
          {!valido ? <span className='text-sm text-red-600 dark:text-red-400'>{t('vulns.plazos.invalido')}</span> : null}
        </div>
      ) : null}
    </div>
  )
}

export function ConfigPlazos({ cliente }: { cliente: string }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const puede = usePermisos()
  const [guardando, setGuardando] = useState(false)
  const { data, isLoading } = useQuery<RespuestaPlazos>({
    queryKey: ['vulnerabilidades', 'plazos', cliente],
    queryFn: () => apiFetch(`/vulnerabilidades/plazos?cliente=${encodeURIComponent(cliente)}`),
  })
  const refrescar = () => qc.invalidateQueries({ queryKey: ['vulnerabilidades'] })
  const pedir = async (fn: () => Promise<unknown>, ok: string) => {
    setGuardando(true)
    try { await fn(); toast.success(ok); refrescar() } catch (e) { toast.error(e instanceof Error ? e.message : t('vulns.errorGenerico')) } finally { setGuardando(false) }
  }
  if (isLoading || !data) return <Loader2 className='size-5 animate-spin' />
  const q = `?cliente=${encodeURIComponent(cliente)}`

  return (
    <div className='space-y-4'>
      <Card>
        <CardHeader>
          <CardTitle className='text-base'>{t('vulns.plazos.delCliente')}</CardTitle>
          <CardDescription>
            {data.cliente ? t('vulns.plazos.tienePropia') : t('vulns.plazos.usaGlobal')} {t('vulns.plazos.reglaKev', { dias: data.kev_dias_max, porVencer: data.por_vencer_dias })}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <EditorPolitica key={`c-${JSON.stringify(data.efectiva)}`} inicial={data.efectiva} editable={puede.administrar} guardando={guardando}
            onGuardar={(p) => pedir(() => apiFetch(`/vulnerabilidades/plazos${q}`, { method: 'PUT', body: { politica: p } }), t('vulns.plazos.guardados'))}
            extra={data.cliente ? (
              <Button size='sm' variant='outline' disabled={guardando}
                onClick={() => pedir(() => apiFetch(`/vulnerabilidades/plazos${q}`, { method: 'DELETE' }), t('vulns.plazos.vuelveGlobal'))}>
                <RotateCcw className='mr-1 size-4' />{t('vulns.plazos.usarGlobal')}
              </Button>
            ) : null} />
          {!puede.administrar ? <p className='text-muted-foreground mt-2 text-sm'>{t('vulns.plazos.soloConduce')}</p> : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className='text-base'>{t('vulns.plazos.global')}</CardTitle>
          <CardDescription>{t('vulns.plazos.globalAyuda', { c: data.defecto.critical, h: data.defecto.high, m: data.defecto.medium, l: data.defecto.low })}</CardDescription>
        </CardHeader>
        <CardContent>
          <EditorPolitica key={`g-${JSON.stringify(data.global)}`} inicial={data.global} editable={data.puede_editar_global} guardando={guardando}
            onGuardar={(p) => pedir(() => apiFetch('/vulnerabilidades/plazos/global', { method: 'PUT', body: { politica: p } }), t('vulns.plazos.guardados'))} />
          {!data.puede_editar_global ? <p className='text-muted-foreground mt-2 text-sm'>{t('vulns.plazos.globalSoloStaff')}</p> : null}
        </CardContent>
      </Card>
    </div>
  )
}
