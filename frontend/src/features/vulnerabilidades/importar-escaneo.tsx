/**
 * Importar un escaneo: se elige el cliente y la herramienta, se sube el archivo y se ve el delta
 * (nuevas, cerradas, reabiertas, sin cambios). Un escaneo cierra solo lo que estaba en su alcance.
 */
import { useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { AlertTriangle, FileUp, Loader2 } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { cn } from '@/lib/utils'
import { IMPORTABLES, type Delta } from './comun'
import { SelectorCliente } from './componentes'

const EXTENSION: Record<string, string> = { nessus: '.nessus,.xml', openvas: '.xml', nmap: '.xml', zap: '.xml', burp: '.xml' }

export function NumeroDelta({ valor, etiqueta, clase }: { valor: number; etiqueta: string; clase?: string }) {
  return (
    <div className={cn('rounded-lg border p-3 text-center', clase)}>
      <p className='text-2xl font-bold'>{valor}</p>
      <p className='text-muted-foreground mt-0.5 text-xs'>{etiqueta}</p>
    </div>
  )
}

export function VistaDelta({ d }: { d: Delta }) {
  const { t } = useTranslation()
  return (
    <div className='space-y-3'>
      <div className='grid grid-cols-2 gap-2 sm:grid-cols-4'>
        <NumeroDelta valor={d.nuevos} etiqueta={t('vulns.delta.nuevos')} clase='border-red-500/30 bg-red-500/5' />
        <NumeroDelta valor={d.cerrados} etiqueta={t('vulns.delta.cerrados')} clase='border-green-500/30 bg-green-500/5' />
        <NumeroDelta valor={d.reabiertos} etiqueta={t('vulns.delta.reabiertos')} clase='border-purple-500/30 bg-purple-500/5' />
        <NumeroDelta valor={d.sin_cambios} etiqueta={t('vulns.delta.sinCambios')} />
      </div>
      <ul className='text-muted-foreground space-y-1 text-sm'>
        <li>{t('vulns.delta.alcance', { count: d.alcance })}</li>
        {d.activos_nuevos ? <li>{t('vulns.delta.activosNuevos', { count: d.activos_nuevos })}</li> : null}
        {d.decisiones_mantenidas ? <li>{t('vulns.delta.decisiones', { count: d.decisiones_mantenidas })}</li> : null}
        {d.sin_activo ? <li>{t('vulns.delta.sinActivo', { count: d.sin_activo })}</li> : null}
      </ul>
      {d.alcance_no_reconocido?.length ? (
        <p className='flex items-start gap-1 text-sm text-yellow-700 dark:text-yellow-400'>
          <AlertTriangle className='mt-0.5 size-4 shrink-0' />
          {t('vulns.delta.noReconocidos', { lista: d.alcance_no_reconocido.join(', ') })}
        </p>
      ) : null}
    </div>
  )
}

export function DialogoImportar({ abierto, onClose, clienteInicial }: { abierto: boolean; onClose: () => void; clienteInicial: string }) {
  // El cuerpo se monta al abrir: cada importación empieza de cero.
  return (
    <Dialog open={abierto} onOpenChange={(v) => !v && onClose()}>
      {abierto ? <CuerpoImportar onClose={onClose} clienteInicial={clienteInicial} /> : null}
    </Dialog>
  )
}

function CuerpoImportar({ onClose, clienteInicial }: { onClose: () => void; clienteInicial: string }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const archivoRef = useRef<HTMLInputElement>(null)
  const [cliente, setCliente] = useState(clienteInicial)
  const [fuente, setFuente] = useState<string>('openvas')
  const [archivo, setArchivo] = useState<File | null>(null)
  const [alcance, setAlcance] = useState('')
  const [enviando, setEnviando] = useState(false)
  const [delta, setDelta] = useState<Delta | null>(null)

  const importar = async () => {
    if (!cliente || !archivo) return
    setEnviando(true)
    try {
      const fd = new FormData()
      fd.append('cliente', cliente)
      fd.append('fuente', fuente)
      fd.append('alcance', alcance)
      fd.append('archivo', archivo)
      const r = await apiFetch<Delta>('/vulnerabilidades/importar', { method: 'POST', body: fd })
      setDelta(r)
      qc.invalidateQueries({ queryKey: ['vulnerabilidades'] })
      qc.invalidateQueries({ queryKey: ['inventario'] })
      toast.success(t('vulns.importada'))
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('vulns.errorGenerico'))
    } finally { setEnviando(false) }
  }

  return (
    <DialogContent className='sm:max-w-lg'>
      <DialogHeader>
        <DialogTitle>{delta ? t('vulns.resultadoImportacion') : t('vulns.importarEscaneo')}</DialogTitle>
        <DialogDescription>{delta ? t('vulns.resultadoAyuda') : t('vulns.importarAyuda')}</DialogDescription>
      </DialogHeader>
      {delta ? <VistaDelta d={delta} /> : (
        <div className='space-y-4'>
          <div className='space-y-1'>
            <Label>{t('vulns.cliente')}</Label>
            <SelectorCliente valor={cliente} onCambio={setCliente} />
          </div>
          <div className='space-y-1'>
            <Label>{t('vulns.herramienta')}</Label>
            <Select value={fuente} onValueChange={setFuente}>
              <SelectTrigger className='w-72'><SelectValue /></SelectTrigger>
              <SelectContent>{IMPORTABLES.map((f) => <SelectItem key={f} value={f}>{t(`vulns.fuente.${f}`)}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          <div className='space-y-1'>
            <Label>{t('vulns.archivo')}</Label>
            <div
              className='hover:border-primary/50 cursor-pointer rounded-lg border-2 border-dashed p-6 text-center transition-colors'
              onClick={() => archivoRef.current?.click()}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => { e.preventDefault(); const f = e.dataTransfer.files?.[0]; if (f) setArchivo(f) }}
            >
              <input ref={archivoRef} type='file' accept={EXTENSION[fuente]} className='hidden' onChange={(e) => setArchivo(e.target.files?.[0] || null)} />
              <FileUp className='text-muted-foreground mx-auto mb-1 size-6' />
              <p className='text-sm'>{archivo ? archivo.name : t('vulns.soltarArchivo')}</p>
            </div>
          </div>
          <div className='space-y-1'>
            <Label>{t('vulns.alcanceExtra')}</Label>
            <Textarea value={alcance} onChange={(e) => setAlcance(e.target.value)} rows={2} placeholder='10.0.0.5, srv-archivos' />
            <p className='text-muted-foreground text-xs'>{t('vulns.alcanceExtraAyuda')}</p>
          </div>
        </div>
      )}
      <DialogFooter>
        {delta ? <Button onClick={onClose}>{t('common.close')}</Button> : (
          <>
            <Button variant='outline' onClick={onClose}>{t('common.cancel')}</Button>
            <Button onClick={importar} disabled={!cliente || !archivo || enviando}>
              {enviando ? <Loader2 className='mr-1 size-4 animate-spin' /> : null}{t('vulns.importar')}
            </Button>
          </>
        )}
      </DialogFooter>
    </DialogContent>
  )
}
