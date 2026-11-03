/**
 * Métricas del seguimiento continuo (etapa 2): abiertas por prioridad, plazos, KEV, tiempo medio de
 * remediación, antigüedad y tendencia de 12 semanas, más el estado de la actualización de KEV y EPSS.
 */
import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip as TooltipGrafico, XAxis, YAxis } from 'recharts'
import { AlertTriangle, Flame, Loader2, RefreshCw } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { PRIORIDAD_CLASE, PRIORIDADES, SEVERIDADES, diaLocal, useFecha, usePermisos, type Prioridad, type Severidad } from './comun'
import { AyudaPrioridad } from './componentes'

interface EstadoFuente {
  ultima_ok?: string | null
  ultimo_intento?: string | null
  error?: string | null
  cantidad: number
  version?: string | null
  fecha_modelo?: string | null
}

export interface Metricas {
  hoy: string
  por_prioridad: Record<Prioridad, number>
  vencidas: number
  por_vencer: number
  en_kev: number
  kev_ransomware: number
  antiguedad: Record<'0-30' | '31-90' | '91-180' | '180+', number>
  mttr: Record<Severidad, { dias: number | null; cerradas: number }>
  tendencia: { semana: string; abiertas: number }[]
  politica: { efectiva: Record<Severidad, number | null>; propia: boolean }
  enriquecimiento: { kev: EstadoFuente; epss: EstadoFuente; habilitada: boolean; en_curso: boolean }
}

const TRAMOS = ['0-30', '31-90', '91-180', '180+'] as const

function Tarjeta({ valor, etiqueta, clase, icono }: { valor: number | string; etiqueta: string; clase?: string; icono?: React.ReactNode }) {
  return (
    <Card className={cn('border', clase)}>
      <CardContent className='p-3'>
        <p className='flex items-center gap-1 text-2xl font-bold'>{icono}{valor}</p>
        <p className='text-sm'>{etiqueta}</p>
      </CardContent>
    </Card>
  )
}

/** Estado de KEV y EPSS: cuándo se actualizó, cuántos datos hay y, para el administrador, "Actualizar ahora". */
function EstadoEnriquecimiento({ e }: { e: Metricas['enriquecimiento'] }) {
  const { t } = useTranslation()
  const { fechaHora, dia } = useFecha()
  const puede = usePermisos()
  const qc = useQueryClient()
  const [pidiendo, setPidiendo] = useState(false)
  const fh = (s?: string | null) => (s ? fechaHora(s.replace(' ', 'T')) : t('vulns.enriquecimiento.nunca'))
  const actualizar = async () => {
    setPidiendo(true)
    try {
      await apiFetch('/vulnerabilidades/enriquecimiento/actualizar', { method: 'POST' })
      toast.success(t('vulns.enriquecimiento.iniciada'))
      // Corre en segundo plano: se vuelve a mirar en un rato.
      setTimeout(() => qc.invalidateQueries({ queryKey: ['vulnerabilidades'] }), 15000)
    } catch (err) { toast.error(err instanceof Error ? err.message : t('vulns.errorGenerico')) } finally { setPidiendo(false) }
  }
  return (
    <div className='text-muted-foreground flex flex-wrap items-center gap-x-4 gap-y-1 text-xs'>
      <span>
        {t('vulns.enriquecimiento.kev', { fecha: fh(e.kev.ultima_ok), cantidad: e.kev.cantidad })}
        {e.kev.error ? <span className='ml-1 text-amber-700 dark:text-amber-400'>({t('vulns.enriquecimiento.error', { error: e.kev.error })})</span> : null}
      </span>
      <span>
        {t('vulns.enriquecimiento.epss', { fecha: fh(e.epss.ultima_ok), cantidad: e.epss.cantidad, modelo: dia(e.epss.fecha_modelo) })}
        {e.epss.error ? <span className='ml-1 text-amber-700 dark:text-amber-400'>({t('vulns.enriquecimiento.error', { error: e.epss.error })})</span> : null}
      </span>
      {!e.habilitada ? <span>{t('vulns.enriquecimiento.deshabilitada')}</span> : null}
      {e.en_curso ? <span className='flex items-center gap-1'><Loader2 className='size-3 animate-spin' />{t('vulns.enriquecimiento.enCurso')}</span> : null}
      {puede.staff && e.habilitada ? (
        <Button size='sm' variant='outline' onClick={actualizar} disabled={pidiendo || e.en_curso}>
          {pidiendo ? <Loader2 className='mr-1 size-4 animate-spin' /> : <RefreshCw className='mr-1 size-4' />}{t('vulns.enriquecimiento.actualizar')}
        </Button>
      ) : null}
    </div>
  )
}

export function PanelMetricas({ cliente }: { cliente: string }) {
  const { t } = useTranslation()
  const { loc } = useFecha()
  const { data: m } = useQuery<Metricas>({
    queryKey: ['vulnerabilidades', 'metricas', cliente], enabled: !!cliente,
    queryFn: () => apiFetch(`/vulnerabilidades/metricas?cliente=${encodeURIComponent(cliente)}`),
  })
  if (!m) return null
  const corto = (s: string) => diaLocal(s)?.toLocaleDateString(loc, { day: '2-digit', month: '2-digit' }) ?? s
  const tendencia = m.tendencia.map((p) => ({ ...p, etiqueta: corto(p.semana) }))
  const antiguedad = TRAMOS.map((k) => ({ tramo: t(`vulns.metricas.tramo.${k}`), cantidad: m.antiguedad[k] }))
  const ejes = { fontSize: 12, fill: 'currentColor' }

  return (
    <div className='space-y-3'>
      <div className='flex items-center gap-2'>
        <p className='text-sm font-semibold'>{t('vulns.metricas.titulo')}</p>
        <AyudaPrioridad />
      </div>
      <div className='grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7'>
        {PRIORIDADES.map((p) => <Tarjeta key={p} valor={m.por_prioridad[p] ?? 0} etiqueta={t('vulns.metricas.abiertasPrioridad', { prioridad: t(`vulns.prioridad.${p}`) })} clase={PRIORIDAD_CLASE[p]} />)}
        <Tarjeta valor={m.vencidas} etiqueta={t('vulns.metricas.vencidas')} clase='border-red-500/40 text-red-700 dark:text-red-300' icono={<AlertTriangle className='size-5' />} />
        <Tarjeta valor={m.por_vencer} etiqueta={t('vulns.metricas.porVencer')} clase='border-amber-500/40 text-amber-800 dark:text-amber-300' />
        <Tarjeta valor={m.en_kev} etiqueta={m.kev_ransomware ? t('vulns.metricas.enKevRansomware', { count: m.kev_ransomware }) : t('vulns.metricas.enKev')}
          clase='border-red-600/40' icono={m.kev_ransomware ? <Flame className='size-5 text-red-600' /> : null} />
      </div>

      <div className='grid gap-3 lg:grid-cols-3'>
        <Card>
          <CardHeader className='pb-0'><CardTitle className='text-sm'>{t('vulns.metricas.tendencia')}</CardTitle></CardHeader>
          <CardContent className='text-muted-foreground h-48 pt-2'>
            <ResponsiveContainer width='100%' height='100%'>
              <AreaChart data={tendencia} margin={{ top: 5, right: 8, left: -16, bottom: 0 }}>
                <CartesianGrid strokeDasharray='3 3' strokeOpacity={0.3} />
                <XAxis dataKey='etiqueta' tick={ejes} tickLine={false} interval='preserveStartEnd' />
                <YAxis allowDecimals={false} tick={ejes} tickLine={false} />
                <TooltipGrafico formatter={(v) => [v, t('vulns.metricas.abiertas')]} labelFormatter={(l) => t('vulns.metricas.semanaAl', { fecha: l })}
                  contentStyle={{ fontSize: 12 }} />
                <Area type='monotone' dataKey='abiertas' stroke='#ea580c' fill='#ea580c' fillOpacity={0.15} strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className='pb-0'><CardTitle className='text-sm'>{t('vulns.metricas.antiguedad')}</CardTitle></CardHeader>
          <CardContent className='text-muted-foreground h-48 pt-2'>
            <ResponsiveContainer width='100%' height='100%'>
              <BarChart data={antiguedad} margin={{ top: 5, right: 8, left: -16, bottom: 0 }}>
                <CartesianGrid strokeDasharray='3 3' strokeOpacity={0.3} />
                <XAxis dataKey='tramo' tick={ejes} tickLine={false} />
                <YAxis allowDecimals={false} tick={ejes} tickLine={false} />
                <TooltipGrafico formatter={(v) => [v, t('vulns.metricas.abiertas')]} contentStyle={{ fontSize: 12 }} />
                <Bar dataKey='cantidad' fill='#64748b' radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className='pb-0'><CardTitle className='text-sm'>{t('vulns.metricas.mttr')}</CardTitle></CardHeader>
          <CardContent className='pt-2'>
            <table className='w-full text-sm'>
              <thead>
                <tr className='text-muted-foreground text-xs'>
                  <th className='py-1 text-left font-normal'>{t('vulns.col.severidad')}</th>
                  <th className='py-1 text-right font-normal'>{t('vulns.metricas.dias')}</th>
                  <th className='py-1 text-right font-normal'>{t('vulns.metricas.cerradas')}</th>
                  <th className='py-1 text-right font-normal'>{t('vulns.metricas.plazoPolitica')}</th>
                </tr>
              </thead>
              <tbody>
                {SEVERIDADES.map((s) => {
                  const r = m.mttr[s], plazo = m.politica.efectiva[s]
                  const fuera = r.dias != null && plazo != null && r.dias > plazo
                  return (
                    <tr key={s} className='border-t'>
                      <td className='py-1'>{t(`finding.sev_${s}`)}</td>
                      <td className={cn('py-1 text-right font-medium', fuera && 'text-red-600 dark:text-red-400')}>
                        {r.dias == null ? '-' : r.dias.toLocaleString(loc, { maximumFractionDigits: 1 })}
                      </td>
                      <td className='text-muted-foreground py-1 text-right'>{r.cerradas}</td>
                      <td className='text-muted-foreground py-1 text-right'>{plazo == null ? t('vulns.plazos.sinPlazoCorto') : plazo}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            <p className='text-muted-foreground mt-2 text-xs'>{t('vulns.metricas.mttrAyuda')}</p>
          </CardContent>
        </Card>
      </div>
      <EstadoEnriquecimiento e={m.enriquecimiento} />
    </div>
  )
}
