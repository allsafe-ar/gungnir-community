/**
 * Lo propio de Gungnir en la ficha del activo del inventario: sus vulnerabilidades y desde cuándo
 * están. Es la pestaña extra de `InventarioBase` (como el monitoreo en Gjallarhorn).
 */
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Loader2 } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { nombreFuente, useFecha, type Vulnerabilidad } from './comun'
import { BadgeEstado, BadgeKev, BadgePrioridad, BadgeSeveridad, Plazo } from './componentes'
import { FichaVulnerabilidadSheet } from './ficha-vulnerabilidad'

export function VulnsDelActivo({ activoId }: { activoId: string }) {
  const { t } = useTranslation()
  const { fecha, antiguedad } = useFecha()
  const [ficha, setFicha] = useState<string | null>(null)
  const { data = [], isLoading } = useQuery<Vulnerabilidad[]>({
    queryKey: ['vulnerabilidades', 'activo', activoId],
    queryFn: () => apiFetch<Vulnerabilidad[]>(`/vulnerabilidades/activo/${activoId}`),
  })
  if (isLoading) return <Loader2 className='size-4 animate-spin' />
  if (!data.length) return <p className='text-muted-foreground text-sm'>{t('vulns.activoSinVulns')}</p>
  const abiertas = data.filter((v) => ['abierto', 'en_remediacion', 'reabierto'].includes(v.estado)).length
  return (
    <div className='space-y-2'>
      <p className='text-muted-foreground text-sm'>{t('vulns.activoResumen', { abiertas, total: data.length })}</p>
      {data.map((v) => (
        <button key={v.id} type='button' onClick={() => setFicha(v.id)}
          className='hover:bg-muted/50 w-full rounded-md border p-2 text-left transition-colors'>
          <div className='flex flex-wrap items-center gap-2'>
            <BadgePrioridad p={v.prioridad} />
            <BadgeSeveridad s={v.severidad} />
            <BadgeEstado e={v.estado} />
            {Number(v.kev) === 1 ? <BadgeKev ransomware={Number(v.kev_ransomware) === 1} /> : null}
            <span className='flex-1 text-sm font-medium'>{v.titulo}</span>
            {v.estado_plazo !== 'no_aplica' && v.fecha_limite ? <Plazo fecha={v.fecha_limite} estado={v.estado_plazo} compacto /> : null}
          </div>
          <p className='text-muted-foreground mt-1 text-xs'>
            {v.puerto ? `${v.puerto}/${v.protocolo || 'tcp'} · ` : ''}
            {t('vulns.desde', { fecha: fecha(v.primera_vez), hace: antiguedad(v.primera_vez) })}
            {' · '}{nombreFuente(v.fuente, t)}
            {v.estado === 'remediado' && v.fecha_cierre ? ` · ${t('vulns.cerradaEl', { fecha: fecha(v.fecha_cierre) })}` : ''}
          </p>
        </button>
      ))}
      <FichaVulnerabilidadSheet id={ficha} onClose={() => setFicha(null)} />
    </div>
  )
}
