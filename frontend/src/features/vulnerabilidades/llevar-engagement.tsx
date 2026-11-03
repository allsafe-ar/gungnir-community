/**
 * Pase a engagement (etapa 4): una o varias vulnerabilidades del seguimiento continuo pasan a ser
 * hallazgos de un engagement del MISMO cliente, para verificarlas, ponerlas en un informe o hacer el
 * retest. Lo que ya se llevó no se duplica: vuelve como "ya llevada".
 */
import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Loader2 } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'

interface EngagementCliente { id: string; titulo: string; codigo: string | null; estado: string }
interface Resultado {
  engagement_id: string
  creados: { id: string; finding_id: string }[]
  ya_llevadas: { id: string; finding_id: string; engagement_id: string }[]
  no_encontradas: string[]
}

export function DialogoLlevarEngagement({ abierto, onClose, cliente, ids, onListo }: {
  abierto: boolean; onClose: () => void; cliente: string; ids: string[]; onListo?: (r: Resultado) => void
}) {
  // El cuerpo se monta al abrir: cada pase empieza sin engagement elegido.
  return (
    <Dialog open={abierto} onOpenChange={(v) => !v && onClose()}>
      {abierto ? <CuerpoLlevar onClose={onClose} cliente={cliente} ids={ids} onListo={onListo} /> : null}
    </Dialog>
  )
}

function CuerpoLlevar({ onClose, cliente, ids, onListo }: { onClose: () => void; cliente: string; ids: string[]; onListo?: (r: Resultado) => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [engagement, setEngagement] = useState('')
  const [enviando, setEnviando] = useState(false)
  const { data: engagements, isLoading } = useQuery<EngagementCliente[]>({
    queryKey: ['vulnerabilidades', 'engagements', cliente],
    queryFn: () => apiFetch(`/vulnerabilidades/engagements?cliente=${encodeURIComponent(cliente)}`),
  })

  const llevar = async () => {
    if (!engagement) return
    setEnviando(true)
    try {
      const r = await apiFetch<Resultado>('/vulnerabilidades/a-engagement', { method: 'POST', body: { cliente, engagement_id: engagement, ids } })
      if (r.creados.length) toast.success(t('vulns.engagement.llevadas', { count: r.creados.length }))
      if (r.ya_llevadas.length) toast.info(t('vulns.engagement.yaLlevadas', { count: r.ya_llevadas.length }))
      if (r.no_encontradas.length) toast.warning(t('vulns.engagement.noEncontradas', { count: r.no_encontradas.length }))
      qc.invalidateQueries({ queryKey: ['vulnerabilidades'] })
      onListo?.(r)
      onClose()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('vulns.errorGenerico'))
    } finally { setEnviando(false) }
  }

  return (
    <DialogContent className='sm:max-w-md'>
      <DialogHeader>
        <DialogTitle>{ids.length > 1 ? t('vulns.engagement.llevarN', { count: ids.length }) : t('vulns.engagement.llevar')}</DialogTitle>
        <DialogDescription>{t('vulns.engagement.ayuda')}</DialogDescription>
      </DialogHeader>
      <div className='space-y-1'>
        <Label>{t('vulns.engagement.elegir')}</Label>
        {isLoading ? <Loader2 className='size-4 animate-spin' /> : !engagements?.length ? (
          <p className='text-muted-foreground text-sm'>{t('vulns.engagement.sinEngagements')}</p>
        ) : (
          <Select value={engagement || undefined} onValueChange={setEngagement}>
            <SelectTrigger><SelectValue placeholder={t('vulns.engagement.elegirPlaceholder')} /></SelectTrigger>
            <SelectContent>
              {engagements.map((e) => (
                <SelectItem key={e.id} value={e.id}>{e.titulo}{e.codigo ? ` (${e.codigo})` : ''}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>
      <DialogFooter>
        <Button variant='outline' onClick={onClose}>{t('common.cancel')}</Button>
        <Button onClick={llevar} disabled={!engagement || enviando}>
          {enviando ? <Loader2 className='mr-1 size-4 animate-spin' /> : null}{t('vulns.engagement.confirmar')}
        </Button>
      </DialogFooter>
    </DialogContent>
  )
}
