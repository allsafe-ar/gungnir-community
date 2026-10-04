/**
 * AnnotateDialog - Editor liviano de anotaciones sobre una captura.
 * Carga la imagen en un canvas, deja dibujar rectángulos, flechas y trazo libre con color, y al
 * guardar rasteriza a PNG y lo sube como una evidencia nueva (reusa el pipeline de evidencias, sin
 * cambios en el backend). Canvas nativo, sin dependencias (React 19).
 */

import { useRef, useState, useEffect, useCallback } from 'react'
import { Square, ArrowUpRight, Pen, Undo2, Loader2, Save } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { API_BASE } from '@/lib/api'

type Tool = 'rect' | 'arrow' | 'pen'
interface Shape { tool: Tool; color: string; points: { x: number; y: number }[] }

const COLORS = ['#ef4444', '#f59e0b', '#22c55e', '#3b82f6', '#ffffff', '#111111']
const MAX_W = 760

export function AnnotateDialog({ open, onOpenChange, srcUrl, engagementId, phase, onSaved }: {
  open: boolean
  onOpenChange: (v: boolean) => void
  srcUrl: string
  engagementId: string
  phase: string
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const imgRef = useRef<HTMLImageElement | null>(null)
  const [tool, setTool] = useState<Tool>('rect')
  const [color, setColor] = useState('#ef4444')
  const [shapes, setShapes] = useState<Shape[]>([])
  const [drawing, setDrawing] = useState<Shape | null>(null)
  const [ready, setReady] = useState(false)
  const [saving, setSaving] = useState(false)
  const [dims, setDims] = useState({ w: MAX_W, h: 400 })

  // Cargar la imagen y dimensionar el canvas (escalado para caber).
  useEffect(() => {
    if (!open) return
    setShapes([]); setDrawing(null); setReady(false)
    const img = new window.Image()
    img.onload = () => {
      imgRef.current = img
      const scale = Math.min(1, MAX_W / img.naturalWidth)
      setDims({ w: Math.round(img.naturalWidth * scale), h: Math.round(img.naturalHeight * scale) })
      setReady(true)
    }
    img.onerror = () => toast.error(t('annotate.load_error'))
    img.src = srcUrl
  }, [open, srcUrl, t])

  const redraw = useCallback(() => {
    const canvas = canvasRef.current, img = imgRef.current
    if (!canvas || !img) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    ctx.clearRect(0, 0, canvas.width, canvas.height)
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
    const all = drawing ? [...shapes, drawing] : shapes
    for (const s of all) drawShape(ctx, s)
  }, [shapes, drawing])

  useEffect(() => { if (ready) redraw() }, [ready, redraw, dims])

  const pos = (e: React.PointerEvent) => {
    const r = canvasRef.current!.getBoundingClientRect()
    return { x: ((e.clientX - r.left) / r.width) * dims.w, y: ((e.clientY - r.top) / r.height) * dims.h }
  }

  const onDown = (e: React.PointerEvent) => {
    e.currentTarget.setPointerCapture(e.pointerId)
    setDrawing({ tool, color, points: [pos(e)] })
  }
  const onMove = (e: React.PointerEvent) => {
    if (!drawing) return
    const p = pos(e)
    setDrawing(d => {
      if (!d) return d
      if (d.tool === 'pen') return { ...d, points: [...d.points, p] }
      return { ...d, points: [d.points[0], p] } // rect y arrow: inicio + actual
    })
  }
  const onUp = () => {
    if (drawing && drawing.points.length > 1) setShapes(s => [...s, drawing])
    setDrawing(null)
  }

  const save = async () => {
    const canvas = canvasRef.current
    if (!canvas) return
    setSaving(true)
    try {
      const blob: Blob = await new Promise((res, rej) => canvas.toBlob(b => b ? res(b) : rej(), 'image/png'))
      const form = new FormData()
      form.append('file', blob, `anotada-${Date.now()}.png`)
      form.append('phase_type', phase)
      form.append('caption', t('annotate.caption'))
      const token = localStorage.getItem('gungnir_token')
      const r = await fetch(`${API_BASE}/engagements/${engagementId}/evidences`, {
        method: 'POST', headers: token ? { Authorization: `Bearer ${token}` } : {}, body: form,
      })
      if (!r.ok) throw new Error()
      toast.success(t('annotate.saved'))
      onSaved(); onOpenChange(false)
    } catch { toast.error(t('annotate.save_error')) } finally { setSaving(false) }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className='max-w-3xl'>
        <DialogHeader><DialogTitle className='text-sm'>{t('annotate.title')}</DialogTitle></DialogHeader>
        <div className='flex items-center gap-2 flex-wrap'>
          <div className='flex items-center gap-1 rounded-md border border-border p-0.5'>
            {([['rect', Square], ['arrow', ArrowUpRight], ['pen', Pen]] as const).map(([tk, Icon]) => (
              <button key={tk} onClick={() => setTool(tk)}
                className={cn('p-1.5 rounded', tool === tk ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent')}>
                <Icon className='size-3.5' />
              </button>
            ))}
          </div>
          <div className='flex items-center gap-1'>
            {COLORS.map(c => (
              <button key={c} onClick={() => setColor(c)}
                className={cn('size-5 rounded-full border-2', color === c ? 'border-foreground' : 'border-transparent')}
                style={{ background: c }} />
            ))}
          </div>
          <Button size='sm' variant='ghost' className='h-7 gap-1 text-xs' disabled={!shapes.length}
            onClick={() => setShapes(s => s.slice(0, -1))}>
            <Undo2 className='size-3.5' /> {t('annotate.undo')}
          </Button>
          <Button size='sm' className='h-7 gap-1 text-xs ml-auto' onClick={save} disabled={saving || !ready}>
            {saving ? <Loader2 className='size-3.5 animate-spin' /> : <Save className='size-3.5' />} {t('annotate.save')}
          </Button>
        </div>
        <div className='rounded-lg border border-border bg-muted/20 overflow-auto max-h-[60vh] flex justify-center'>
          {ready ? (
            <canvas ref={canvasRef} width={dims.w} height={dims.h}
              style={{ width: dims.w, height: dims.h, maxWidth: '100%', touchAction: 'none', cursor: 'crosshair' }}
              onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp} />
          ) : (
            <div className='py-16'><Loader2 className='size-5 animate-spin text-muted-foreground' /></div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}

function drawShape(ctx: CanvasRenderingContext2D, s: Shape) {
  ctx.strokeStyle = s.color
  ctx.lineWidth = 3
  ctx.lineJoin = 'round'
  ctx.lineCap = 'round'
  const p = s.points
  if (p.length < 1) return
  if (s.tool === 'rect' && p.length >= 2) {
    ctx.strokeRect(p[0].x, p[0].y, p[1].x - p[0].x, p[1].y - p[0].y)
  } else if (s.tool === 'arrow' && p.length >= 2) {
    const [a, b] = [p[0], p[1]]
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke()
    const ang = Math.atan2(b.y - a.y, b.x - a.x), h = 14
    ctx.beginPath()
    ctx.moveTo(b.x, b.y)
    ctx.lineTo(b.x - h * Math.cos(ang - Math.PI / 6), b.y - h * Math.sin(ang - Math.PI / 6))
    ctx.moveTo(b.x, b.y)
    ctx.lineTo(b.x - h * Math.cos(ang + Math.PI / 6), b.y - h * Math.sin(ang + Math.PI / 6))
    ctx.stroke()
  } else if (s.tool === 'pen') {
    ctx.beginPath(); ctx.moveTo(p[0].x, p[0].y)
    for (let i = 1; i < p.length; i++) ctx.lineTo(p[i].x, p[i].y)
    ctx.stroke()
  }
}
