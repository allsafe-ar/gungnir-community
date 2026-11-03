/**
 * Componentes comunes de Vulnerabilidades y Activos: insignias de severidad, estado, prioridad, KEV,
 * EPSS y plazo, la ayuda de la regla de prioridad y el selector de cliente.
 */
import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Building2, CircleHelp, Flame } from 'lucide-react'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { cn } from '@/lib/utils'
import {
  ESTADO_CLASE, PLAZO_CLASE, PRIORIDAD_CLASE, SEV_CLASE, diasHasta, formatoEpss, recordarCliente, useClientes, useFecha,
  type Estado, type EstadoPlazo, type KevDetalle, type Prioridad, type Severidad,
} from './comun'

export function BadgeSeveridad({ s }: { s: Severidad }) {
  const { t } = useTranslation()
  return <Badge variant='outline' className={cn('text-xs', SEV_CLASE[s])}>{t(`finding.sev_${s}`)}</Badge>
}

export function BadgeEstado({ e }: { e: Estado }) {
  const { t } = useTranslation()
  return <Badge variant='outline' className={cn('text-xs whitespace-nowrap', ESTADO_CLASE[e])}>{t(`vulns.estado.${e}`)}</Badge>
}

/** Selector de cliente. Si el recordado ya no es visible (otra organización), se descarta. */
export function SelectorCliente({ valor, onCambio }: { valor: string; onCambio: (id: string) => void }) {
  const { t } = useTranslation()
  const { data: clientes = [], isSuccess } = useClientes()
  useEffect(() => {
    if (isSuccess && valor && !clientes.some((c) => c.id === valor)) onCambio('')
  }, [isSuccess, clientes, valor, onCambio])
  return (
    <div className='flex items-center gap-2'>
      <Building2 className='text-muted-foreground size-4' />
      <Select value={valor || undefined} onValueChange={(v) => { recordarCliente(v); onCambio(v) }}>
        <SelectTrigger className='w-72'><SelectValue placeholder={t('vulns.elegirCliente')} /></SelectTrigger>
        <SelectContent>
          {clientes.map((c) => <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>)}
        </SelectContent>
      </Select>
      {isSuccess && !clientes.length ? <span className='text-muted-foreground text-sm'>{t('vulns.sinClientes')}</span> : null}
    </div>
  )
}

/** Prioridad calculada, con la regla en el tooltip. */
export function BadgePrioridad({ p }: { p: Prioridad | null }) {
  const { t } = useTranslation()
  if (!p) return <span className='text-muted-foreground text-xs'>-</span>
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant='outline' className={cn('cursor-help text-xs whitespace-nowrap', PRIORIDAD_CLASE[p])}>{t(`vulns.prioridad.${p}`)}</Badge>
      </TooltipTrigger>
      <TooltipContent className='max-w-xs'>{t(`vulns.prioridadRegla.${p}`)}</TooltipContent>
    </Tooltip>
  )
}

/** Insignia KEV: explotada activamente según CISA, con nombre y uso en ransomware. */
export function BadgeKev({ detalle, ransomware }: { detalle?: KevDetalle[]; ransomware?: boolean }) {
  const { t } = useTranslation()
  const { dia } = useFecha()
  const conRansomware = ransomware || !!detalle?.some((d) => d.ransomware)
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant='outline' className='cursor-help gap-1 border-red-600/50 bg-red-600/10 text-xs whitespace-nowrap text-red-700 dark:text-red-300'>
          {conRansomware ? <Flame className='size-3' /> : null}KEV
        </Badge>
      </TooltipTrigger>
      <TooltipContent className='max-w-sm space-y-1 text-left'>
        <p className='font-semibold'>{t('vulns.kev.titulo')}</p>
        {(detalle || []).map((d) => (
          <div key={d.cve}>
            <p>{d.cve}{d.nombre ? `: ${d.nombre}` : ''}</p>
            <p>{t('vulns.kev.altaCisa', { fecha: dia(d.alta) })}{d.ransomware ? ` · ${t('vulns.kev.ransomware')}` : ''}</p>
          </div>
        ))}
        {!detalle?.length && conRansomware ? <p>{t('vulns.kev.ransomware')}</p> : null}
      </TooltipContent>
    </Tooltip>
  )
}

/** EPSS: probabilidad de explotación en 30 días (porcentaje) y su percentil. */
export function TextoEpss({ epss, percentil, className }: { epss: number | string | null | undefined; percentil: number | string | null | undefined; className?: string }) {
  const { t } = useTranslation()
  const { loc } = useFecha()
  const f = formatoEpss(epss, percentil, loc)
  if (!f) return <span className={cn('text-muted-foreground text-xs', className)}>-</span>
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={cn('cursor-help text-sm whitespace-nowrap', className)}>
          {f.pct}{f.percentil != null ? <span className='text-muted-foreground text-xs'> · p{f.percentil}</span> : null}
        </span>
      </TooltipTrigger>
      <TooltipContent className='max-w-xs'>{t('vulns.epssAyuda', { pct: f.pct, percentil: f.percentil ?? '-' })}</TooltipContent>
    </Tooltip>
  )
}

/** Plazo: día límite y su estado con color (vencida, por vencer, en plazo). */
export function Plazo({ fecha, estado, compacto = false }: { fecha: string | null; estado: EstadoPlazo; compacto?: boolean }) {
  const { t } = useTranslation()
  const { dia } = useFecha()
  if (estado === 'no_aplica') return <span className='text-muted-foreground text-xs'>{fecha ? dia(fecha) : '-'}</span>
  if (!fecha) return <span className='text-muted-foreground text-xs'>{t('vulns.plazo.sin_plazo')}</span>
  const faltan = diasHasta(fecha) ?? 0
  const detalle = estado === 'vencida' ? t('vulns.plazo.vencidaHace', { count: -faltan }) : t('vulns.plazo.faltan', { count: faltan })
  return (
    <div className={cn('text-sm whitespace-nowrap', PLAZO_CLASE[estado])}>
      <span className='font-medium'>{dia(fecha)}</span>
      {compacto ? null : <p className='text-xs'>{t(`vulns.plazo.${estado}`)} · {detalle}</p>}
    </div>
  )
}

/** Ayuda con la regla de prioridad y la de plazos, para que se entienda de dónde sale cada valor. */
export function AyudaPrioridad() {
  const { t } = useTranslation()
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button type='button' className='text-muted-foreground hover:text-foreground inline-flex items-center' aria-label={t('vulns.ayudaPrioridad.titulo')}>
          <CircleHelp className='size-4' />
        </button>
      </PopoverTrigger>
      <PopoverContent className='w-96 space-y-2 text-sm' align='start'>
        <p className='font-semibold'>{t('vulns.ayudaPrioridad.titulo')}</p>
        <p className='text-muted-foreground'>{t('vulns.ayudaPrioridad.intro')}</p>
        <ul className='space-y-1'>
          {(['urgente', 'alta', 'media', 'baja'] as Prioridad[]).map((p) => (
            <li key={p} className='flex gap-2'>
              <Badge variant='outline' className={cn('h-fit text-xs', PRIORIDAD_CLASE[p])}>{t(`vulns.prioridad.${p}`)}</Badge>
              <span className='text-muted-foreground'>{t(`vulns.prioridadRegla.${p}`)}</span>
            </li>
          ))}
        </ul>
        <p className='text-muted-foreground'>{t('vulns.ayudaPrioridad.fuentes')}</p>
        <p className='font-semibold'>{t('vulns.ayudaPrioridad.plazosTitulo')}</p>
        <p className='text-muted-foreground'>{t('vulns.ayudaPrioridad.plazos')}</p>
      </PopoverContent>
    </Popover>
  )
}
