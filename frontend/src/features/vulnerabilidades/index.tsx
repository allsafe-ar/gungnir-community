/**
 * Vulnerabilidades: seguimiento continuo por cliente, separado de los engagements.
 *
 * Lo que llega de los escaneos periódicos se sigue en el tiempo: qué está abierto, qué se arregló,
 * qué volvió. Arriba los números que importan (abiertas por severidad, reabiertas, remediadas en 30
 * días) y las métricas de la etapa 2 (prioridad, plazos, KEV, MTTR, antigüedad y tendencia); abajo
 * el listado ordenado por prioridad, el historial de importaciones y los plazos.
 *
 * Copia de Gungnir Pro sin la pestaña de conectores y API (son de la edición Pro): en su lugar, una
 * línea discreta en el historial de importaciones, como el aviso de escáneres en vivo de Integraciones.
 */
import { useCallback, useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ChevronLeft, ChevronRight, Loader2, Plus, Search, ShieldAlert, Upload } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { cn } from '@/lib/utils'
import {
  ESTADOS, FUENTES, PRIORIDADES, SEV_CLASE, SEVERIDADES, clienteRecordado, nombreFuente, useFecha, usePermisos,
  type Delta, type Severidad, type Vulnerabilidad,
} from './comun'
import { AyudaPrioridad, BadgeEstado, BadgeKev, BadgePrioridad, BadgeSeveridad, Plazo, SelectorCliente, TextoEpss } from './componentes'
import { PanelMetricas } from './metricas'
import { ConfigPlazos } from './plazos'
import { FichaVulnerabilidadSheet } from './ficha-vulnerabilidad'
import { DialogoImportar, VistaDelta } from './importar-escaneo'

interface Resumen {
  abiertas: Record<Severidad, number>
  total_abiertas: number
  reabiertas: number
  remediadas_30d: number
  estados: Record<string, number>
  fuentes: string[]
}

interface Importacion {
  id: string; fuente: string; origen: string; archivo: string | null; alcance_cantidad: number; items: number
  nuevos: number; cerrados: number; reabiertos: number; sin_cambios: number; activos_nuevos: number; usuario: string | null; created_at: string
}

const TODOS = '_todos'

function Contadores({ r }: { r: Resumen | undefined }) {
  const { t } = useTranslation()
  if (!r) return null
  return (
    <div className='grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8'>
      {SEVERIDADES.map((s) => (
        <Card key={s} className={cn('border', SEV_CLASE[s])}>
          <CardContent className='p-3'>
            <p className='text-2xl font-bold'>{r.abiertas[s] ?? 0}</p>
            <p className='text-sm'>{t('vulns.abiertasSev', { sev: t(`finding.sev_${s}`) })}</p>
          </CardContent>
        </Card>
      ))}
      <Card><CardContent className='p-3'><p className='text-2xl font-bold'>{r.total_abiertas}</p><p className='text-muted-foreground text-sm'>{t('vulns.totalAbiertas')}</p></CardContent></Card>
      <Card className='border-purple-500/30'><CardContent className='p-3'><p className='text-2xl font-bold text-purple-600 dark:text-purple-400'>{r.reabiertas}</p><p className='text-muted-foreground text-sm'>{t('vulns.reabiertas')}</p></CardContent></Card>
      <Card className='border-green-500/30'><CardContent className='p-3'><p className='text-2xl font-bold text-green-700 dark:text-green-400'>{r.remediadas_30d}</p><p className='text-muted-foreground text-sm'>{t('vulns.remediadas30')}</p></CardContent></Card>
    </div>
  )
}

function Listado({ cliente, fuentes, abrir }: { cliente: string; fuentes: string[]; abrir: (id: string) => void }) {
  const { t } = useTranslation()
  const { fecha, antiguedad } = useFecha()
  const [estado, setEstadoF] = useState('abiertas')
  const [severidad, setSeveridadF] = useState(TODOS)
  const [fuente, setFuenteF] = useState(TODOS)
  const [prioridad, setPrioridadF] = useState(TODOS)
  const [kev, setKevF] = useState(TODOS)
  const [plazo, setPlazoF] = useState(TODOS)
  const [texto, setTexto] = useState('')
  const [buscar, setBuscar] = useState('')
  const [pagina, setPagina] = useState(1)
  const limite = 50
  // Cambiar un filtro vuelve a la primera página. El cliente no: el listado se monta de nuevo (key).
  const filtro = (set: (v: string) => void) => (v: string) => { set(v); setPagina(1) }
  const setEstado = filtro(setEstadoF), setSeveridad = filtro(setSeveridadF), setFuente = filtro(setFuenteF)
  const setPrioridad = filtro(setPrioridadF), setKev = filtro(setKevF), setPlazo = filtro(setPlazoF)
  useEffect(() => {
    const h = setTimeout(() => { setBuscar(texto); setPagina(1) }, 300)
    return () => clearTimeout(h)
  }, [texto])

  const params = new URLSearchParams({ cliente, pagina: String(pagina), limite: String(limite) })
  if (estado !== TODOS) params.set('estado', estado)
  if (severidad !== TODOS) params.set('severidad', severidad)
  if (fuente !== TODOS) params.set('fuente', fuente)
  if (prioridad !== TODOS) params.set('prioridad', prioridad)
  if (kev !== TODOS) params.set('kev', kev)
  if (plazo !== TODOS) params.set('plazo', plazo)
  if (buscar.trim()) params.set('q', buscar.trim())
  const { data, isLoading } = useQuery<{ filas: Vulnerabilidad[]; total: number }>({
    queryKey: ['vulnerabilidades', 'lista', params.toString()],
    queryFn: () => apiFetch(`/vulnerabilidades?${params.toString()}`),
  })
  const paginas = Math.max(1, Math.ceil((data?.total || 0) / limite))

  return (
    <div className='space-y-3'>
      <div className='flex flex-wrap items-end gap-2'>
        <div className='relative'>
          <Search className='text-muted-foreground absolute top-2.5 left-2 size-4' />
          <Input className='w-64 pl-8' value={texto} onChange={(e) => setTexto(e.target.value)} placeholder={t('vulns.buscar')} />
        </div>
        <Select value={estado} onValueChange={setEstado}>
          <SelectTrigger className='w-48'><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value='abiertas'>{t('vulns.filtro.abiertas')}</SelectItem>
            <SelectItem value='cerradas'>{t('vulns.filtro.cerradas')}</SelectItem>
            <SelectItem value={TODOS}>{t('vulns.filtro.todosEstados')}</SelectItem>
            {ESTADOS.map((e) => <SelectItem key={e} value={e}>{t(`vulns.estado.${e}`)}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={severidad} onValueChange={setSeveridad}>
          <SelectTrigger className='w-40'><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value={TODOS}>{t('vulns.filtro.todasSeveridades')}</SelectItem>
            {SEVERIDADES.map((s) => <SelectItem key={s} value={s}>{t(`finding.sev_${s}`)}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={fuente} onValueChange={setFuente}>
          <SelectTrigger className='w-40'><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value={TODOS}>{t('vulns.filtro.todasFuentes')}</SelectItem>
            {FUENTES.filter((f) => fuentes.includes(f)).map((f) => <SelectItem key={f} value={f}>{t(`vulns.fuente.${f}`)}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={prioridad} onValueChange={setPrioridad}>
          <SelectTrigger className='w-40'><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value={TODOS}>{t('vulns.filtro.todasPrioridades')}</SelectItem>
            {PRIORIDADES.map((p) => <SelectItem key={p} value={p}>{t(`vulns.prioridad.${p}`)}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={kev} onValueChange={setKev}>
          <SelectTrigger className='w-36'><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value={TODOS}>{t('vulns.filtro.kevTodas')}</SelectItem>
            <SelectItem value='1'>{t('vulns.filtro.kevSolo')}</SelectItem>
          </SelectContent>
        </Select>
        <Select value={plazo} onValueChange={setPlazo}>
          <SelectTrigger className='w-40'><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value={TODOS}>{t('vulns.filtro.todosPlazos')}</SelectItem>
            {(['vencida', 'por_vencer', 'en_plazo'] as const).map((p) => <SelectItem key={p} value={p}>{t(`vulns.plazo.${p}`)}</SelectItem>)}
          </SelectContent>
        </Select>
        <span className='text-muted-foreground ml-auto text-sm'>{t('vulns.resultados', { count: data?.total || 0 })}</span>
      </div>

      <div className='rounded-md border'>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead><span className='flex items-center gap-1'>{t('vulns.col.prioridad')}<AyudaPrioridad /></span></TableHead>
              <TableHead>{t('vulns.col.severidad')}</TableHead>
              <TableHead>{t('vulns.col.titulo')}</TableHead>
              <TableHead>EPSS</TableHead>
              <TableHead>{t('vulns.col.activo')}</TableHead>
              <TableHead>{t('vulns.col.estado')}</TableHead>
              <TableHead>{t('vulns.col.plazo')}</TableHead>
              <TableHead>{t('vulns.col.desde')}</TableHead>
              <TableHead>{t('vulns.col.fuente')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow><TableCell colSpan={9} className='py-8 text-center'><Loader2 className='mx-auto size-5 animate-spin' /></TableCell></TableRow>
            ) : !data?.filas.length ? (
              <TableRow><TableCell colSpan={9} className='text-muted-foreground py-8 text-center'>{t('vulns.sinResultados')}</TableCell></TableRow>
            ) : data.filas.map((v) => (
              <TableRow key={v.id} className='cursor-pointer' onClick={() => abrir(v.id)}>
                <TableCell><BadgePrioridad p={v.prioridad} /></TableCell>
                <TableCell><BadgeSeveridad s={v.severidad} /></TableCell>
                <TableCell className='max-w-md'>
                  <p className='truncate text-sm font-medium'>{v.titulo}</p>
                  <div className='flex items-center gap-1'>
                    {Number(v.kev) === 1 ? <BadgeKev detalle={v.kev_detalle} ransomware={Number(v.kev_ransomware) === 1} /> : null}
                    {v.cves ? <p className='text-muted-foreground truncate text-xs'>{v.cves.split(',').join(', ')}</p> : null}
                  </div>
                </TableCell>
                <TableCell><TextoEpss epss={v.epss} percentil={v.epss_percentil} /></TableCell>
                <TableCell>
                  <p className='text-sm'>{v.activo_nombre}</p>
                  <p className='text-muted-foreground text-xs'>
                    {[v.activo_ip && v.activo_ip !== v.activo_nombre ? v.activo_ip : null, v.puerto ? `${v.puerto}/${v.protocolo || 'tcp'}` : null].filter(Boolean).join(' · ')}
                  </p>
                </TableCell>
                <TableCell>
                  <BadgeEstado e={v.estado} />
                  {v.reaperturas > 0 ? <p className='mt-0.5 text-xs text-purple-600 dark:text-purple-400'>{t('vulns.reaperturasN', { count: v.reaperturas })}</p> : null}
                </TableCell>
                <TableCell><Plazo fecha={v.fecha_limite} estado={v.estado_plazo} /></TableCell>
                <TableCell className='text-sm whitespace-nowrap'>{fecha(v.primera_vez)}<p className='text-muted-foreground text-xs'>{antiguedad(v.primera_vez)}</p></TableCell>
                <TableCell className='text-sm'>{nombreFuente(v.fuente, t)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {paginas > 1 ? (
        <div className='flex items-center justify-end gap-2'>
          <Button variant='outline' size='sm' disabled={pagina <= 1} onClick={() => setPagina((p) => p - 1)}><ChevronLeft className='size-4' /></Button>
          <span className='text-sm'>{t('vulns.pagina', { pagina, paginas })}</span>
          <Button variant='outline' size='sm' disabled={pagina >= paginas} onClick={() => setPagina((p) => p + 1)}><ChevronRight className='size-4' /></Button>
        </div>
      ) : null}
    </div>
  )
}

function DetalleImportacion({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { t } = useTranslation()
  const { data } = useQuery<Importacion & { alcance: { id: string; nombre: string }[]; cambios: { hallazgo_id: string; evento: string; titulo: string; severidad: Severidad; activo_nombre: string }[] }>({
    queryKey: ['vulnerabilidades', 'importacion', id], queryFn: () => apiFetch(`/vulnerabilidades/importaciones/${id}`), enabled: !!id,
  })
  const delta: Delta | null = data ? {
    importacion_id: data.id, codigo: data.id.slice(0, 8).toUpperCase(), fuente: data.fuente, nuevos: data.nuevos, cerrados: data.cerrados,
    reabiertos: data.reabiertos, sin_cambios: data.sin_cambios, decisiones_mantenidas: 0, total: data.items,
    activos_nuevos: data.activos_nuevos, alcance: data.alcance_cantidad, sin_activo: 0, alcance_no_reconocido: [],
  } : null
  return (
    <Dialog open={!!id} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className='max-h-[85vh] overflow-y-auto sm:max-w-2xl'>
        <DialogHeader>
          <DialogTitle>{data ? t('vulns.importacionDe', { fuente: nombreFuente(data.fuente, t), codigo: data.id.slice(0, 8).toUpperCase() }) : '...'}</DialogTitle>
          <DialogDescription>{data?.archivo || ''}</DialogDescription>
        </DialogHeader>
        {delta ? <VistaDelta d={delta} /> : <Loader2 className='size-5 animate-spin' />}
        {data?.alcance?.length ? (
          <div className='space-y-1'>
            <p className='text-sm font-semibold'>{t('vulns.alcanceCubierto')}</p>
            <p className='text-muted-foreground text-sm'>{data.alcance.map((a) => a.nombre).join(', ')}</p>
          </div>
        ) : null}
        {data?.cambios?.length ? (
          <div className='space-y-1'>
            <p className='text-sm font-semibold'>{t('vulns.cambiosImportacion')}</p>
            {data.cambios.map((c) => (
              <div key={`${c.hallazgo_id}-${c.evento}`} className='flex flex-wrap items-center gap-2 border-b py-1 text-sm last:border-0'>
                <span className='w-24 text-xs font-medium'>{t(`vulns.eventoCorto.${c.evento}`)}</span>
                <BadgeSeveridad s={c.severidad} />
                <span className='flex-1'>{c.titulo}</span>
                <span className='text-muted-foreground text-xs'>{c.activo_nombre}</span>
              </div>
            ))}
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

/** Lo que hace la edición Pro con las importaciones: una línea discreta, sin pantalla. */
function AvisoPro() {
  const { t } = useTranslation()
  return (
    <div className='text-muted-foreground flex items-center gap-2 rounded-md border border-dashed px-3 py-2 text-sm'>
      <Badge variant='outline' className='text-muted-foreground text-xs'>Pro</Badge>
      <span>{t('vulns.enPro')}</span>
    </div>
  )
}

function Importaciones({ cliente }: { cliente: string }) {
  const { t } = useTranslation()
  const { fechaHora } = useFecha()
  const [detalle, setDetalle] = useState<string | null>(null)
  const { data = [], isLoading } = useQuery<Importacion[]>({
    queryKey: ['vulnerabilidades', 'importaciones', cliente], queryFn: () => apiFetch(`/vulnerabilidades/importaciones?cliente=${encodeURIComponent(cliente)}`),
  })
  return (
    <div className='space-y-3'>
      <AvisoPro />
      <div className='rounded-md border'>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('vulns.col.fecha')}</TableHead>
              <TableHead>{t('vulns.col.fuente')}</TableHead>
              <TableHead>{t('vulns.col.archivo')}</TableHead>
              <TableHead className='text-right'>{t('vulns.col.alcance')}</TableHead>
              <TableHead className='text-right'>{t('vulns.delta.nuevos')}</TableHead>
              <TableHead className='text-right'>{t('vulns.delta.cerrados')}</TableHead>
              <TableHead className='text-right'>{t('vulns.delta.reabiertos')}</TableHead>
              <TableHead className='text-right'>{t('vulns.delta.sinCambios')}</TableHead>
              <TableHead>{t('vulns.col.usuario')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow><TableCell colSpan={9} className='py-8 text-center'><Loader2 className='mx-auto size-5 animate-spin' /></TableCell></TableRow>
            ) : !data.length ? (
              <TableRow><TableCell colSpan={9} className='text-muted-foreground py-8 text-center'>{t('vulns.sinImportaciones')}</TableCell></TableRow>
            ) : data.map((i) => (
              <TableRow key={i.id} className='cursor-pointer' onClick={() => setDetalle(i.id)}>
                <TableCell className='text-sm whitespace-nowrap'>{fechaHora(i.created_at)}</TableCell>
                <TableCell className='text-sm'>{nombreFuente(i.fuente, t)}</TableCell>
                <TableCell className='max-w-xs text-sm'>
                  <p className='truncate'>{i.archivo || '-'}</p>
                  {i.origen && i.origen !== 'manual' ? <p className='text-muted-foreground text-xs'>{t(`vulns.origen.${i.origen}`)}</p> : null}
                </TableCell>
                <TableCell className='text-right text-sm'>{i.alcance_cantidad}</TableCell>
                <TableCell className='text-right text-sm'>{i.nuevos}</TableCell>
                <TableCell className='text-right text-sm'>{i.cerrados}</TableCell>
                <TableCell className='text-right text-sm'>{i.reabiertos}</TableCell>
                <TableCell className='text-right text-sm'>{i.sin_cambios}</TableCell>
                <TableCell className='text-sm'>{i.usuario || '-'}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <DetalleImportacion id={detalle} onClose={() => setDetalle(null)} />
      </div>
    </div>
  )
}

/** Alta a mano: lo que no salió de un escáner (un hallazgo de una revisión, un aviso del proveedor). */
const ALTA_VACIA = { activo_id: '', titulo: '', severidad: 'medium', puerto: '', cves: '', cvss: '', descripcion: '', solucion: '' }

function DialogoAlta({ abierto, onClose, cliente, onCreada }: { abierto: boolean; onClose: () => void; cliente: string; onCreada: (id: string) => void }) {
  // El cuerpo se monta al abrir: cada alta empieza vacía.
  return (
    <Dialog open={abierto} onOpenChange={(v) => !v && onClose()}>
      {abierto ? <CuerpoAlta onClose={onClose} cliente={cliente} onCreada={onCreada} /> : null}
    </Dialog>
  )
}

function CuerpoAlta({ onClose, cliente, onCreada }: { onClose: () => void; cliente: string; onCreada: (id: string) => void }) {
  const { t } = useTranslation()
  const vacio = ALTA_VACIA
  const [f, setF] = useState(vacio)
  const [enviando, setEnviando] = useState(false)
  const { data: activos } = useQuery<{ filas: { id: string; nombre: string; ip: string | null }[] }>({
    queryKey: ['inventario', 'para-vulns', cliente], enabled: !!cliente,
    queryFn: () => apiFetch(`/inventario?cliente=${encodeURIComponent(cliente)}&limite=500`),
  })
  const set = (k: keyof typeof vacio) => (v: string) => setF((x) => ({ ...x, [k]: v }))
  const guardar = async () => {
    setEnviando(true)
    try {
      const r = await apiFetch<{ id: string }>('/vulnerabilidades', { method: 'POST', body: { ...f, cliente } })
      toast.success(t('vulns.creada'))
      onCreada(r.id)
    } catch (e) { toast.error(e instanceof Error ? e.message : t('vulns.errorGenerico')) } finally { setEnviando(false) }
  }
  return (
    <DialogContent className='max-h-[90vh] overflow-y-auto sm:max-w-lg'>
      <DialogHeader>
        <DialogTitle>{t('vulns.nueva')}</DialogTitle>
        <DialogDescription>{t('vulns.nuevaAyuda')}</DialogDescription>
      </DialogHeader>
      <div className='space-y-3'>
        <div className='space-y-1'>
          <Label>{t('vulns.col.activo')}</Label>
          <Select value={f.activo_id || undefined} onValueChange={set('activo_id')}>
            <SelectTrigger><SelectValue placeholder={t('vulns.elegirActivo')} /></SelectTrigger>
            <SelectContent>{(activos?.filas || []).map((a) => <SelectItem key={a.id} value={a.id}>{a.nombre}{a.ip && a.ip !== a.nombre ? ` (${a.ip})` : ''}</SelectItem>)}</SelectContent>
          </Select>
          {activos && !activos.filas.length ? <p className='text-muted-foreground text-xs'>{t('vulns.sinActivos')}</p> : null}
        </div>
        <div className='space-y-1'><Label>{t('vulns.col.titulo')}</Label><Input value={f.titulo} onChange={(e) => set('titulo')(e.target.value)} maxLength={500} /></div>
        <div className='grid grid-cols-3 gap-2'>
          <div className='space-y-1'>
            <Label>{t('vulns.col.severidad')}</Label>
            <Select value={f.severidad} onValueChange={set('severidad')}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>{SEVERIDADES.map((s) => <SelectItem key={s} value={s}>{t(`finding.sev_${s}`)}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          <div className='space-y-1'><Label>CVSS</Label><Input value={f.cvss} onChange={(e) => set('cvss')(e.target.value)} inputMode='decimal' /></div>
          <div className='space-y-1'><Label>{t('vulns.col.puerto')}</Label><Input value={f.puerto} onChange={(e) => set('puerto')(e.target.value)} inputMode='numeric' /></div>
        </div>
        <div className='space-y-1'><Label>CVE</Label><Input value={f.cves} onChange={(e) => set('cves')(e.target.value)} placeholder='CVE-2024-0001, CVE-2024-0002' /></div>
        <div className='space-y-1'><Label>{t('vulns.descripcion')}</Label><Textarea rows={3} value={f.descripcion} onChange={(e) => set('descripcion')(e.target.value)} /></div>
        <div className='space-y-1'><Label>{t('vulns.solucion')}</Label><Textarea rows={2} value={f.solucion} onChange={(e) => set('solucion')(e.target.value)} /></div>
      </div>
      <DialogFooter>
        <Button variant='outline' onClick={onClose}>{t('common.cancel')}</Button>
        <Button onClick={guardar} disabled={!f.activo_id || !f.titulo.trim() || enviando}>{enviando ? <Loader2 className='mr-1 size-4 animate-spin' /> : null}{t('common.create')}</Button>
      </DialogFooter>
    </DialogContent>
  )
}

export function Vulnerabilidades() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const puede = usePermisos()
  const [cliente, setClienteEstado] = useState<string>(clienteRecordado)
  const setCliente = useCallback((id: string) => setClienteEstado(id), [])
  const [ficha, setFicha] = useState<string | null>(null)
  const [importar, setImportar] = useState(false)
  const [alta, setAlta] = useState(false)
  const { data: resumen } = useQuery<Resumen>({
    queryKey: ['vulnerabilidades', 'resumen', cliente], enabled: !!cliente,
    queryFn: () => apiFetch(`/vulnerabilidades/resumen?cliente=${encodeURIComponent(cliente)}`),
  })

  return (
    <div className='space-y-5'>
      <div className='flex flex-wrap items-center justify-between gap-3'>
        <div>
          <h1 className='flex items-center gap-2 text-2xl font-bold tracking-tight'><ShieldAlert className='size-6' />{t('vulns.titulo')}</h1>
          <p className='text-muted-foreground text-sm'>{t('vulns.subtitulo')}</p>
        </div>
        <div className='flex flex-wrap items-center gap-2'>
          <SelectorCliente valor={cliente} onCambio={setCliente} />
          {puede.editar && cliente ? <Button variant='outline' onClick={() => setAlta(true)}><Plus className='mr-1 size-4' />{t('vulns.nueva')}</Button> : null}
          {puede.importar ? <Button onClick={() => setImportar(true)}><Upload className='mr-1 size-4' />{t('vulns.importarEscaneo')}</Button> : null}
        </div>
      </div>

      {!cliente ? (
        <Card><CardContent className='text-muted-foreground py-10 text-center'>{t('vulns.elegiClienteAviso')}</CardContent></Card>
      ) : (
        <>
          <Contadores r={resumen} />
          <PanelMetricas cliente={cliente} />
          <Tabs defaultValue='listado'>
            <TabsList>
              <TabsTrigger value='listado'>{t('vulns.tabListado')}</TabsTrigger>
              <TabsTrigger value='importaciones'>{t('vulns.tabImportaciones')}</TabsTrigger>
              <TabsTrigger value='plazos'>{t('vulns.tabPlazos')}</TabsTrigger>
            </TabsList>
            <TabsContent value='listado' className='pt-2'>
              <Listado key={cliente} cliente={cliente} fuentes={resumen?.fuentes || []} abrir={setFicha} />
            </TabsContent>
            <TabsContent value='importaciones' className='pt-2'>
              <Importaciones cliente={cliente} />
            </TabsContent>
            <TabsContent value='plazos' className='pt-2'>
              <ConfigPlazos key={cliente} cliente={cliente} />
            </TabsContent>
          </Tabs>
        </>
      )}

      <FichaVulnerabilidadSheet id={ficha} onClose={() => setFicha(null)} />
      <DialogoImportar abierto={importar} onClose={() => setImportar(false)} clienteInicial={cliente} />
      <DialogoAlta abierto={alta} onClose={() => setAlta(false)} cliente={cliente}
        onCreada={(id) => { setAlta(false); qc.invalidateQueries({ queryKey: ['vulnerabilidades'] }); setFicha(id) }} />
    </div>
  )
}
