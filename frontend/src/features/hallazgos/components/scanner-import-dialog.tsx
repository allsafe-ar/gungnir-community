/**
 * ScannerImportDialog — Importa hallazgos desde archivos de scanners.
 * Soporta: Nessus (.nessus), Burp Suite (.xml), OpenVAS (.xml)
 */

import { useState, useRef } from 'react'
import { Upload, FileUp, CheckCircle2, AlertCircle, X } from 'lucide-react'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'

interface ImportResult {
  imported: number
  findings: { id: string; title: string; severity: string }[]
}

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500',
  low: 'bg-blue-500', info: 'bg-muted-foreground',
}

const PHASES = [
  { value: 'scanning',          label: 'Escaneo' },
  { value: 'recon',             label: 'Reconocimiento' },
  { value: 'exploitation',      label: 'Explotación' },
  { value: 'post_exploitation', label: 'Post-explotación' },
]

interface Props {
  open: boolean
  onOpenChange: (v: boolean) => void
  engagementId: string
  onImported?: () => void
}

export function ScannerImportDialog({ open, onOpenChange, engagementId, onImported }: Props) {
  const { auth } = useAuthStore()
  const role = auth.user?.role
  const fileRef = useRef<HTMLInputElement>(null)

  const [file, setFile]               = useState<File | null>(null)
  const [scannerType, setScannerType] = useState('nessus')
  const [phase, setPhase]             = useState('scanning')
  const [loading, setLoading]         = useState(false)
  const [result, setResult]           = useState<ImportResult | null>(null)
  const [error, setError]             = useState<string | null>(null)

  // Only admin, auditor, pentester can import
  const canImport = role === 'admin' || role === 'auditor' || role === 'pentester'

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0] || null
    setFile(f)
    setResult(null)
    setError(null)
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault()
    const f = e.dataTransfer.files?.[0] || null
    if (f) {
      setFile(f)
      setResult(null)
      setError(null)
    }
  }

  async function handleImport() {
    if (!file || !canImport) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const formData = new FormData()
      formData.append('file', file)
      formData.append('scanner_type', scannerType)
      formData.append('phase_type', phase)

      const token = localStorage.getItem('gungnir_token')
      const resp = await fetch(`/api/engagements/${engagementId}/import-scan`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ error: 'Error desconocido' }))
        throw new Error(err.error || `Error ${resp.status}`)
      }
      const data: ImportResult = await resp.json()
      setResult(data)
      onImported?.()
      toast.success(`${data.imported} hallazgos importados`)
    } catch(e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error al importar'
      setError(msg)
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  function handleClose() {
    setFile(null)
    setResult(null)
    setError(null)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className='sm:max-w-lg'>
        <DialogHeader>
          <DialogTitle className='flex items-center gap-2'>
            <Upload className='h-4 w-4' />
            Importar desde scanner
          </DialogTitle>
        </DialogHeader>

        {!result ? (
          <div className='space-y-5 py-2'>
            {/* Scanner type */}
            <div className='grid grid-cols-2 gap-2'>
              {[
                { id: 'nessus',  label: 'Nessus',    ext: '.nessus' },
                { id: 'burp',    label: 'Burp Suite', ext: '.xml' },
                { id: 'openvas', label: 'OpenVAS',    ext: '.xml' },
                { id: 'nmap',    label: 'Nmap',       ext: '.xml' },
              ].map(s => (
                <button
                  key={s.id}
                  type='button'
                  onClick={() => setScannerType(s.id)}
                  className={cn(
                    'rounded-lg border p-3 text-center transition-all',
                    scannerType === s.id
                      ? 'border-primary bg-primary/10'
                      : 'border-border hover:border-primary/40'
                  )}
                >
                  <p className={cn('text-sm font-semibold', scannerType === s.id ? 'text-primary' : 'text-foreground')}>
                    {s.label}
                  </p>
                  <p className='text-[10px] text-muted-foreground font-mono mt-0.5'>{s.ext}</p>
                </button>
              ))}
            </div>

            {/* Fase destino */}
            <div className='space-y-1.5'>
              <Label className='text-xs'>Fase de destino</Label>
              <Select value={phase} onValueChange={setPhase}>
                <SelectTrigger className='h-8 text-sm'><SelectValue /></SelectTrigger>
                <SelectContent>
                  {PHASES.map(p => <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>

            {/* Drop zone */}
            <div
              onDrop={handleDrop}
              onDragOver={e => e.preventDefault()}
              onClick={() => fileRef.current?.click()}
              className={cn(
                'relative rounded-lg border-2 border-dashed cursor-pointer transition-colors p-6 text-center',
                file
                  ? 'border-primary/50 bg-primary/5'
                  : 'border-border hover:border-primary/40 hover:bg-muted/30'
              )}
            >
              <input
                ref={fileRef}
                type='file'
                accept='.xml,.nessus'
                onChange={handleFile}
                className='hidden'
              />
              {file ? (
                <div className='flex items-center justify-center gap-3'>
                  <FileUp className='size-6 text-primary' />
                  <div className='text-left'>
                    <p className='text-sm font-medium text-foreground'>{file.name}</p>
                    <p className='text-xs text-muted-foreground'>{(file.size / 1024).toFixed(1)} KB</p>
                  </div>
                  <button
                    type='button'
                    onClick={e => { e.stopPropagation(); setFile(null); }}
                    className='ml-auto text-muted-foreground hover:text-foreground'
                  >
                    <X className='size-4' />
                  </button>
                </div>
              ) : (
                <div>
                  <Upload className='size-8 text-muted-foreground/40 mx-auto mb-2' />
                  <p className='text-sm text-muted-foreground'>Arrastrá el archivo aquí o hacé click para seleccionar</p>
                  <p className='text-xs text-muted-foreground/60 mt-1'>
                    Nessus: .nessus · Burp/OpenVAS/Nmap: .xml · Máx. 50MB
                  </p>
                </div>
              )}
            </div>

            {/* Error */}
            {error && (
              <div className='flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive'>
                <AlertCircle className='size-4 shrink-0 mt-0.5' />
                {error}
              </div>
            )}
          </div>
        ) : (
          /* Resultado */
          <div className='py-4 space-y-4'>
            <div className='flex items-center gap-3'>
              <CheckCircle2 className='size-8 text-green-400 shrink-0' />
              <div>
                <p className='font-semibold'>Import completado</p>
                <p className='text-sm text-muted-foreground'>
                  {result.imported} hallazgo{result.imported !== 1 ? 's' : ''} importado{result.imported !== 1 ? 's' : ''}
                </p>
              </div>
            </div>

            <div className='rounded-lg border border-border max-h-60 overflow-y-auto'>
              {result.findings.map(f => (
                <div key={f.id} className='flex items-center gap-2 px-3 py-2 border-b border-border/50 last:border-0'>
                  <div className={cn('h-2 w-2 rounded-full shrink-0', SEV_DOT[f.severity] ?? 'bg-muted')} />
                  <span className='text-xs truncate'>{f.title}</span>
                  <span className='text-[10px] text-muted-foreground ml-auto shrink-0'>{f.severity}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <DialogFooter>
          {!result ? (
            <>
              <Button variant='outline' size='sm' onClick={handleClose}>Cancelar</Button>
              <Button
                size='sm'
                onClick={handleImport}
                disabled={!file || loading || !canImport}
                className='gap-1.5'
              >
                {loading ? (
                  <>
                    <div className='h-3.5 w-3.5 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent' />
                    Importando...
                  </>
                ) : (
                  <>
                    <Upload className='h-3.5 w-3.5' />
                    Importar
                  </>
                )}
              </Button>
            </>
          ) : (
            <Button size='sm' onClick={handleClose}>Cerrar</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
