/**
 * Ficha de una vulnerabilidad: datos del escáner, desde cuándo está, su historial y los cambios de
 * estado con motivo. Lo que se ve en el historial se arma por idioma con el evento; el texto guardado
 * queda para la auditoría.
 */
import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ArrowRight, Briefcase, History, Loader2, Server } from 'lucide-react'
import { Link } from '@tanstack/react-router'
import { apiFetch } from '@/lib/api'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { ESTADOS_ABIERTOS, MANUALES, nombreFuente, useFecha, usePermisos, type EnlaceEngagement, type Estado, type EventoHistorial, type FichaVulnerabilidad } from './comun'
import { BadgeEstado, BadgeKev, BadgePrioridad, BadgeSeveridad, Plazo, TextoEpss } from './componentes'
import { DialogoLlevarEngagement } from './llevar-engagement'

function Dato({ etiqueta, children }: { etiqueta: string; children: React.ReactNode }) {
  return (
    <div>
      <p className='text-muted-foreground text-xs'>{etiqueta}</p>
      <div className='text-sm break-words'>{children}</div>
    </div>
  )
}

function Texto({ titulo, texto }: { titulo: string; texto: string | null }) {
  if (!texto) return null
  return (
    <div className='space-y-1'>
      <p className='text-sm font-semibold'>{titulo}</p>
      <p className='text-muted-foreground text-sm whitespace-pre-wrap'>{texto}</p>
    </div>
  )
}

/** Una línea del historial, en el idioma de quien la lee. */
function LineaHistorial({ e }: { e: EventoHistorial }) {
  const { t } = useTranslation()
  const { fechaHora } = useFecha()
  const codigo = e.importacion_id ? e.importacion_id.slice(0, 8).toUpperCase() : ''
  const fuente = nombreFuente(e.fuente, t)
  const porPersona = e.evento === 'manual' || e.evento === 'alta_manual' || e.evento === 'a_engagement' || e.evento === 'retest'
  const texto = porPersona
    ? t(`vulns.historial.${e.evento}`, { usuario: e.usuario || '-' })
    : t(`vulns.historial.${e.evento}`, { fuente, codigo })
  return (
    <div className='border-b py-2 last:border-0'>
      <div className='flex flex-wrap items-center gap-2'>
        <span className='text-muted-foreground text-xs'>{fechaHora(e.created_at)}</span>
        {e.estado_antes ? <BadgeEstado e={e.estado_antes} /> : null}
        {e.estado_antes ? <ArrowRight className='text-muted-foreground size-3' /> : null}
        {e.estado_despues ? <BadgeEstado e={e.estado_despues} /> : null}
      </div>
      <p className='mt-1 text-sm'>{texto}</p>
      {(e.evento === 'manual' || e.evento === 'a_engagement' || e.evento === 'retest') && e.motivo ? <p className='text-muted-foreground mt-0.5 text-sm italic'>{e.motivo}</p> : null}
    </div>
  )
}

export function DialogoEstado({ abierto, onClose, actual, id, onListo, estadoInicial, motivoInicial }: {
  abierto: boolean; onClose: () => void; actual: Estado; id: string; onListo: () => void
  /** Para el atajo "cerrar por retest": el estado y el motivo ya escritos (se pueden cambiar). */
  estadoInicial?: Estado; motivoInicial?: string
}) {
  // El cuerpo se monta al abrir: cada apertura empieza vacía (o con lo que pide el atajo).
  return (
    <Dialog open={abierto} onOpenChange={(v) => !v && onClose()}>
      {abierto ? <CuerpoEstado onClose={onClose} actual={actual} id={id} onListo={onListo} estadoInicial={estadoInicial} motivoInicial={motivoInicial} /> : null}
    </Dialog>
  )
}

function CuerpoEstado({ onClose, actual, id, onListo, estadoInicial, motivoInicial }: {
  onClose: () => void; actual: Estado; id: string; onListo: () => void; estadoInicial?: Estado; motivoInicial?: string
}) {
  const { t } = useTranslation()
  const puede = usePermisos()
  const [estado, setEstado] = useState<Estado | ''>(estadoInicial && estadoInicial !== actual ? estadoInicial : '')
  const [motivo, setMotivo] = useState(motivoInicial || '')
  const [enviando, setEnviando] = useState(false)
  const opciones = MANUALES.filter((e) => e !== actual && (e !== 'riesgo_aceptado' || puede.aceptarRiesgo))

  const guardar = async () => {
    if (!estado) return
    setEnviando(true)
    try {
      await apiFetch(`/vulnerabilidades/${id}/estado`, { method: 'PUT', body: { estado, motivo } })
      toast.success(t('vulns.estadoCambiado'))
      onListo()
      onClose()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('vulns.errorGenerico'))
    } finally { setEnviando(false) }
  }

  return (
    <DialogContent className='sm:max-w-md'>
      <DialogHeader>
        <DialogTitle>{t('vulns.cambiarEstado')}</DialogTitle>
        <DialogDescription>{t('vulns.cambiarEstadoAyuda')}</DialogDescription>
      </DialogHeader>
      <div className='space-y-3'>
        <div className='space-y-1'>
          <Label>{t('vulns.nuevoEstado')}</Label>
          <Select value={estado || undefined} onValueChange={(v) => setEstado(v as Estado)}>
            <SelectTrigger><SelectValue placeholder={t('vulns.elegirEstado')} /></SelectTrigger>
            <SelectContent>{opciones.map((e) => <SelectItem key={e} value={e}>{t(`vulns.estado.${e}`)}</SelectItem>)}</SelectContent>
          </Select>
          {!puede.aceptarRiesgo ? <p className='text-muted-foreground text-xs'>{t('vulns.riesgoSoloConduce')}</p> : null}
        </div>
        <div className='space-y-1'>
          <Label>{t('vulns.motivo')}</Label>
          <Textarea value={motivo} onChange={(e) => setMotivo(e.target.value)} rows={3} maxLength={1000} placeholder={t('vulns.motivoAyuda')} />
        </div>
      </div>
      <DialogFooter>
        <Button variant='outline' onClick={onClose}>{t('common.cancel')}</Button>
        <Button onClick={guardar} disabled={!estado || motivo.trim().length < 3 || enviando}>
          {enviando ? <Loader2 className='mr-1 size-4 animate-spin' /> : null}{t('common.save')}
        </Button>
      </DialogFooter>
    </DialogContent>
  )
}

/**
 * El hallazgo del engagement al que se llevó. El retest NO cierra la vulnerabilidad continua (la
 * cierra la fuente que la creó cuando deja de verla): se muestra, y si se aprobó hay un atajo para
 * cerrarla a mano con el motivo ya escrito.
 */
function EnlaceConEngagement({ e, abierta, onCerrar }: { e: EnlaceEngagement; abierta: boolean; onCerrar: () => void }) {
  const { t } = useTranslation()
  const { fecha } = useFecha()
  const puede = usePermisos()
  if (e.roto) return <p className='text-muted-foreground text-sm'>{t('vulns.engagement.roto')}</p>
  if (e.sin_acceso) return <p className='text-muted-foreground text-sm'>{t('vulns.engagement.sinAcceso')}</p>
  return (
    <div className='space-y-2 rounded-md border p-3'>
      <p className='flex items-center gap-1 text-sm font-semibold'><Briefcase className='size-4' />{t('vulns.engagement.enlace')}</p>
      <div className='grid grid-cols-2 gap-3'>
        <Dato etiqueta={t('vulns.engagement.engagement')}>
          {e.engagement_id ? (
            <Link to='/engagements/$engagementId' params={{ engagementId: e.engagement_id }} className='text-primary hover:underline'>
              {e.engagement_titulo}
            </Link>
          ) : '-'}
        </Dato>
        <Dato etiqueta={t('vulns.engagement.estadoHallazgo')}>{e.estado ? t(`vulns.engagement.hallazgo.${e.estado}`) : '-'}</Dato>
        <Dato etiqueta={t('vulns.engagement.retest')}>
          {t(`vulns.engagement.retestEstado.${e.retest || 'not_retested'}`)}
          {e.retest_fecha ? <span className='text-muted-foreground text-xs'> · {fecha(e.retest_fecha)}</span> : null}
        </Dato>
      </div>
      {e.retest === 'passed' && abierta ? (
        <div className='space-y-1'>
          <p className='text-muted-foreground text-xs'>{t('vulns.engagement.retestAyuda')}</p>
          {puede.editar ? <Button size='sm' variant='outline' onClick={onCerrar}>{t('vulns.engagement.cerrarPorRetest')}</Button> : null}
        </div>
      ) : null}
    </div>
  )
}

/** Responsable y notas. Se monta con la ficha (key por id): arranca con lo guardado. */
function Seguimiento({ v, onGuardado }: { v: FichaVulnerabilidad; onGuardado: () => void }) {
  const { t } = useTranslation()
  const puede = usePermisos()
  const [responsable, setResponsable] = useState(v.responsable || '')
  const [notas, setNotas] = useState(v.notas || '')
  const guardar = async () => {
    try {
      await apiFetch(`/vulnerabilidades/${v.id}`, { method: 'PUT', body: { responsable, notas } })
      toast.success(t('common.success'))
      onGuardado()
    } catch (e) { toast.error(e instanceof Error ? e.message : t('vulns.errorGenerico')) }
  }
  return (
    <div className='space-y-2 rounded-md border p-3'>
      <p className='text-sm font-semibold'>{t('vulns.seguimiento')}</p>
      <div className='space-y-1'>
        <Label>{t('vulns.responsable')}</Label>
        <Input value={responsable} onChange={(e) => setResponsable(e.target.value)} disabled={!puede.editar} maxLength={120} />
      </div>
      <div className='space-y-1'>
        <Label>{t('vulns.notas')}</Label>
        <Textarea value={notas} onChange={(e) => setNotas(e.target.value)} disabled={!puede.editar} rows={3} />
      </div>
      {puede.editar ? <Button size='sm' variant='outline' onClick={guardar}>{t('common.save')}</Button> : null}
    </div>
  )
}

export function FichaVulnerabilidadSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const puede = usePermisos()
  const { fecha, fechaHora, antiguedad } = useFecha()
  const [cambiar, setCambiar] = useState(false)
  const [porRetest, setPorRetest] = useState(false)
  const [llevar, setLlevar] = useState(false)
  const { data: v, isLoading } = useQuery<FichaVulnerabilidad>({
    queryKey: ['vulnerabilidades', 'ficha', id], queryFn: () => apiFetch<FichaVulnerabilidad>(`/vulnerabilidades/${id}`), enabled: !!id,
  })
  const recargar = () => qc.invalidateQueries({ queryKey: ['vulnerabilidades'] })

  return (
    <Sheet open={!!id} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className='w-full overflow-y-auto sm:max-w-2xl'>
        {isLoading || !v ? (
          <div className='flex h-40 items-center justify-center'><Loader2 className='size-6 animate-spin' /></div>
        ) : (
          <>
            <SheetHeader>
              <SheetTitle className='pr-6'>{v.titulo}</SheetTitle>
              <SheetDescription asChild>
                <div className='flex flex-wrap items-center gap-2'>
                  <BadgePrioridad p={v.prioridad} />
                  <BadgeSeveridad s={v.severidad} />
                  <BadgeEstado e={v.estado} />
                  {Number(v.kev) === 1 ? <BadgeKev detalle={v.kev_detalle} ransomware={Number(v.kev_ransomware) === 1} /> : null}
                  {v.reaperturas > 0 ? <span className='text-xs text-purple-600 dark:text-purple-400'>{t('vulns.reaperturasN', { count: v.reaperturas })}</span> : null}
                </div>
              </SheetDescription>
            </SheetHeader>
            <div className='space-y-5 px-4 pb-6'>
              {puede.editar ? (
                <div className='flex flex-wrap gap-2'>
                  <Button size='sm' onClick={() => setCambiar(true)}>{t('vulns.cambiarEstado')}</Button>
                  {!v.engagement || v.engagement.roto ? (
                    <Button size='sm' variant='outline' onClick={() => setLlevar(true)}><Briefcase className='mr-1 size-4' />{t('vulns.engagement.llevar')}</Button>
                  ) : null}
                </div>
              ) : null}

              <div className='grid grid-cols-2 gap-3 rounded-md border p-3'>
                <Dato etiqueta={t('vulns.col.activo')}>
                  <span className='flex items-center gap-1'><Server className='size-3.5' />{v.activo?.nombre || '-'}</span>
                  {v.activo?.ip ? <span className='text-muted-foreground text-xs'>{v.activo.ip}</span> : null}
                </Dato>
                {v.ubicacion ? (
                  <Dato etiqueta={t('vulns.col.ubicacion')}><span className='font-mono text-xs break-all'>{v.ubicacion}</span></Dato>
                ) : (
                  <Dato etiqueta={t('vulns.col.puerto')}>{v.puerto ? `${v.puerto}/${v.protocolo || 'tcp'}${v.servicio ? ` (${v.servicio})` : ''}` : '-'}</Dato>
                )}
                <Dato etiqueta={t('vulns.col.plazo')}>
                  <Plazo fecha={v.fecha_limite} estado={v.estado_plazo} />
                  {v.plazo_desde && v.plazo_desde !== v.primera_vez ? <span className='text-muted-foreground text-xs'>{t('vulns.plazoDesdeReapertura', { fecha: fecha(v.plazo_desde) })}</span> : null}
                </Dato>
                <Dato etiqueta='EPSS'><TextoEpss epss={v.epss} percentil={v.epss_percentil} /></Dato>
                <Dato etiqueta={t('vulns.primeraVez')}>{fecha(v.primera_vez)} <span className='text-muted-foreground text-xs'>({antiguedad(v.primera_vez)})</span></Dato>
                <Dato etiqueta={t('vulns.ultimaVez')}>{fechaHora(v.ultima_vez)}</Dato>
                <Dato etiqueta={t('vulns.fechaCierre')}>{fecha(v.fecha_cierre)}</Dato>
                <Dato etiqueta={t('vulns.col.fuente')}>
                  {nombreFuente(v.fuente, t)}
                  {v.fuente_ultima && v.fuente_ultima !== v.fuente ? <span className='text-muted-foreground text-xs'> · {t('vulns.ultimaFuente', { fuente: nombreFuente(v.fuente_ultima, t) })}</span> : null}
                </Dato>
                <Dato etiqueta='CVSS'>{v.cvss ?? '-'}{v.cvss_vector ? <span className='text-muted-foreground block text-xs'>{v.cvss_vector}</span> : null}</Dato>
                <Dato etiqueta='CVE'>{v.cves ? v.cves.split(',').join(', ') : '-'}</Dato>
                <Dato etiqueta='CWE'>{v.cwe || '-'}</Dato>
                <Dato etiqueta={t('vulns.regla')}>{v.regla || '-'}</Dato>
              </div>

              {v.cves_detalle?.length ? (
                <div className='space-y-1'>
                  <p className='text-sm font-semibold'>{t('vulns.inteligencia')}</p>
                  <div className='rounded-md border'>
                    {v.cves_detalle.map((c) => (
                      <div key={c.cve} className='flex flex-wrap items-center gap-x-3 gap-y-1 border-b px-3 py-2 text-sm last:border-0'>
                        <span className='w-36 font-medium'>{c.cve}</span>
                        <span className='flex items-center gap-1'><span className='text-muted-foreground text-xs'>EPSS</span><TextoEpss epss={c.epss} percentil={c.percentil} /></span>
                        {c.kev ? <BadgeKev detalle={[c.kev]} /> : <span className='text-muted-foreground text-xs'>{t('vulns.kev.noEsta')}</span>}
                        {c.kev?.nombre ? <span className='text-muted-foreground w-full text-xs'>{c.kev.nombre}{c.kev.ransomware ? ` · ${t('vulns.kev.ransomware')}` : ''}</span> : null}
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              <Texto titulo={t('vulns.descripcion')} texto={v.descripcion} />
              <Texto titulo={t('vulns.solucion')} texto={v.solucion} />
              <Texto titulo={t('vulns.evidencia')} texto={v.evidencia} />

              {v.engagement ? (
                <EnlaceConEngagement e={v.engagement} abierta={ESTADOS_ABIERTOS.includes(v.estado)} onCerrar={() => setPorRetest(true)} />
              ) : null}

              <Seguimiento key={v.id} v={v} onGuardado={recargar} />

              <div className='space-y-1'>
                <p className='flex items-center gap-1 text-sm font-semibold'><History className='size-4' />{t('vulns.historialTitulo')}</p>
                {v.historial.length ? v.historial.map((e) => <LineaHistorial key={e.id} e={e} />) : <p className='text-muted-foreground text-sm'>{t('vulns.sinHistorial')}</p>}
              </div>
            </div>
            <DialogoEstado abierto={cambiar} onClose={() => setCambiar(false)} actual={v.estado} id={v.id} onListo={recargar} />
            <DialogoEstado abierto={porRetest} onClose={() => setPorRetest(false)} actual={v.estado} id={v.id} onListo={recargar}
              estadoInicial='remediado' motivoInicial={t('vulns.engagement.motivoRetest', { titulo: v.engagement?.engagement_titulo || '' })} />
            <DialogoLlevarEngagement abierto={llevar} onClose={() => setLlevar(false)} cliente={v.cliente_id} ids={[v.id]} />
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}
