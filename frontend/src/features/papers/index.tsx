/**
 * Papers - Security Research Paper editor & PDF generator
 *
 * Academic:  USENIX · NDSS · IEEE S&P · ACM CCS
 * Briefing:  Black Hat · DEF CON · EkoParty · BSides
 * Other:     Exploit-DB · Neutral
 *
 * 16 secciones basadas en la estructura de vulnerability research papers.
 * Tab "Exploit-DB" para buscar, descargar y guardar papers de exploit-db.com
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Download, Loader2, Shield, Save, Trash2, FolderOpen,
  RotateCcw, Plus, GraduationCap, AlertTriangle,
  CheckCircle2, ChevronRight, ChevronDown, Search,
  BookOpen, Star, ExternalLink, FileText,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { cn } from '@/lib/utils'
import { apiFetch } from '@/lib/api'
import { toast } from 'sonner'
import { generatePaperPDF, type PaperData } from '@/lib/paper-pdf'

// ─── Tipos ─────────────────────────────────────────────────────────────────────
interface SavedPaper {
  id: string; title: string; template: string; category: string
  tags: string; authors: string; date: string; cve_id: string | null
  cvss_score: number | null; status: string; updated_at: string
}

interface EdbResult {
  id: string; edb_id: string; title: string; author: string; date: string; file?: string
}

interface SavedEdbPaper {
  id: string; edb_id: string; title: string; author: string
  edb_date: string; notes: string; saved_at: string
}

// ─── Template registry ────────────────────────────────────────────────────────
type TemplateGroup = { group: string; items: { id: string; label: string; sub: string; accent: string }[] }

const TEMPLATE_GROUPS: TemplateGroup[] = [
  {
    group: 'Académico',
    items: [
      { id: 'usenix',  label: 'USENIX Security', sub: 'USENIX Security Symposium',                    accent: '#38bdf8' },
      { id: 'ndss',    label: 'NDSS',             sub: 'Network & Distributed System Security',        accent: '#60a5fa' },
      { id: 'ieee_sp', label: 'IEEE S&P',         sub: 'IEEE Symposium on Security & Privacy',         accent: '#818cf8' },
      { id: 'acm_ccs', label: 'ACM CCS',          sub: 'ACM Conf. on Computer & Communications Sec.', accent: '#a78bfa' },
    ],
  },
  {
    group: 'Whitepaper / Briefing',
    items: [
      { id: 'blackhat',  label: 'Black Hat',  sub: 'Black Hat Briefings',         accent: '#f97316' },
      { id: 'defcon',    label: 'DEF CON',    sub: 'DEF CON Hacking Conference',  accent: '#39ff14' },
      { id: 'ekoparty',  label: 'EkoParty',   sub: 'EkoParty Security Conf.',     accent: '#c026d3' },
      { id: 'bsides',    label: 'BSides',     sub: 'Security BSides',             accent: '#ef4444' },
    ],
  },
  {
    group: 'Otros',
    items: [
      { id: 'exploitdb', label: 'Exploit-DB', sub: 'Offensive Security / Exploit-DB', accent: '#16a34a' },
      { id: 'neutral',   label: 'Neutral',    sub: 'Presentación genérica',           accent: '#94a3b8' },
    ],
  },
]

const ALL_TEMPLATES = TEMPLATE_GROUPS.flatMap(g => g.items)
const TEMPLATE_MAP  = Object.fromEntries(ALL_TEMPLATES.map(t => [t.id, t]))

const CATEGORY_OPTIONS = [
  { id: 'vuln_research',    label: 'Vulnerability Research' },
  { id: 'attack_technique', label: 'Attack Technique / TTP' },
  { id: 'threat_intel',     label: 'Threat Intelligence'    },
  { id: 'malware_analysis', label: 'Malware Analysis'       },
  { id: 'tool_analysis',    label: 'Tool Analysis'          },
  { id: 'ctf_research',     label: 'CTF Research'           },
  { id: 'general',          label: 'General Research'       },
]

const STATUS_OPTIONS = [
  { id: 'draft',     label: 'Borrador',    cls: 'bg-zinc-700/60 text-zinc-300'    },
  { id: 'review',    label: 'En revisión', cls: 'bg-blue-900/40 text-blue-300'    },
  { id: 'published', label: 'Publicado',   cls: 'bg-green-900/40 text-green-300'  },
  { id: 'archived',  label: 'Archivado',   cls: 'bg-zinc-800 text-zinc-500'       },
]
const STATUS_CLS   = Object.fromEntries(STATUS_OPTIONS.map(s => [s.id, s.cls]))
const STATUS_LABEL = Object.fromEntries(STATUS_OPTIONS.map(s => [s.id, s.label]))

// ─── Section definitions (16 secciones estándar) ─────────────────────────────
const PAPER_SECTIONS = [
  { num: '01', key: 'abstract_text',      title: 'Abstract',                          hint: 'Resumen de 150-250 palabras (aparece en la portada)',        rows: 5  },
  { num: '02', key: 'introduction',       title: 'Introducción',                       hint: 'Contexto, motivación y aporte principal',                   rows: 7  },
  { num: '03', key: 'background',         title: 'Contexto Técnico',                   hint: 'Arquitectura, protocolos, trabajos previos',                rows: 6  },
  { num: '04', key: 'threat_model',       title: 'Alcance y Modelo de Amenaza',        hint: 'Qué se analizó, permisos del atacante, supuestos',          rows: 5  },
  { num: '05', key: 'methodology',        title: 'Metodología',                        hint: 'Entorno de lab, versiones, herramientas, técnicas',         rows: 6  },
  { num: '06', key: 'vuln_description',   title: 'Descripción de la Vulnerabilidad',   hint: 'Tipo, punto vulnerable, condición que la dispara',          rows: 7  },
  { num: '07', key: 'root_cause',         title: 'Análisis de Causa Raíz',             hint: 'Error de diseño, validación, permisos, criptografía',       rows: 6  },
  { num: '08', key: 'impact',             title: 'Explotabilidad e Impacto',           hint: 'Qué puede lograr un atacante - CIA',                        rows: 6  },
  { num: '09', key: 'evidence',           title: 'Evidencia Técnica / PoC',            hint: 'Código, requests, comandos - renderiza como bloque de código', rows: 10, mono: true },
  { num: '10', key: 'severity_section',   title: 'Severidad',                          hint: 'Justificación del score CVSS, impacto técnico y operativo', rows: 4  },
  { num: '11', key: 'mitigations',        title: 'Mitigaciones',                       hint: 'Correcciones, hardening, WAF/SIEM, detección',              rows: 6  },
  { num: '12', key: 'ethics',             title: 'Consideraciones Éticas y Legales',   hint: 'Autorización, no afectación a terceros, coordinación',      rows: 5  },
  { num: '13', key: 'conclusions',        title: 'Conclusión',                         hint: 'Aprendizajes, aportes a la comunidad, trabajo futuro',       rows: 5  },
  { num: '14', key: 'references_text',    title: 'Referencias',                        hint: 'Una por línea - URLs detectadas automáticamente',           rows: 6  },
  { num: '15', key: 'disclosure_timeline',title: 'Timeline de Disclosure',             hint: 'Formato: YYYY-MM-DD - descripción (una por línea)',         rows: 5  },
  { num: '16', key: 'appendices',         title: 'Apéndices',                          hint: 'Detalles extendidos, hashes, reglas de detección',          rows: 5  },
] as const

type SectionKey = typeof PAPER_SECTIONS[number]['key']

// ─── Default data ─────────────────────────────────────────────────────────────
const EMPTY: PaperData = {
  title: '', template: 'blackhat', category: 'vuln_research',
  tags: '', authors: '', date: new Date().toLocaleDateString('es-AR'),
  cve_id: '', advisory_url: '', cvss_vector: '', cvss_score: undefined,
  abstract_text: '', introduction: '', background: '', threat_model: '',
  methodology: '', vuln_description: '', root_cause: '', impact: '',
  evidence: '', severity_section: '', mitigations: '', ethics: '',
  conclusions: '', references_text: '', disclosure_timeline: '', appendices: '',
  status: 'draft',
}

// ─── Section card ──────────────────────────────────────────────────────────────
function SectionCard({
  num, title, hint, value, onChange, placeholder, rows, mono, accent,
}: {
  num: string; title: string; hint?: string; value: string
  onChange: (v: string) => void; placeholder?: string
  rows: number; mono?: boolean; accent: string
}) {
  const [open, setOpen] = useState(false)
  const hasContent = value.trim().length > 0

  return (
    <div className={cn(
      'rounded-xl border overflow-hidden transition-colors',
      hasContent ? 'border-zinc-700' : 'border-zinc-800/60',
      open && 'border-zinc-600'
    )}>
      <button
        type='button'
        onClick={() => setOpen(v => !v)}
        className='w-full flex items-center gap-2.5 px-4 py-2.5 bg-zinc-900/50 hover:bg-zinc-900/80 transition text-left'
      >
        <span className='font-mono text-[9px] font-bold min-w-[18px]' style={{ color: accent }}>{num}</span>
        <div className='h-3 w-0.5 rounded-full shrink-0' style={{ background: accent + '80' }} />
        <span className={cn('text-xs font-semibold flex-1', hasContent ? 'text-zinc-200' : 'text-zinc-500')}>
          {title}
        </span>
        {hint && !open && <span className='text-[9px] text-zinc-700 hidden lg:block truncate max-w-[200px]'>- {hint}</span>}
        {hasContent && !open && (
          <span className='text-[9px] rounded px-1.5 py-0.5 shrink-0'
            style={{ background: accent + '18', color: accent, border: `0.3px solid ${accent}40` }}>
            {value.trim().split('\n').length}L
          </span>
        )}
        {open
          ? <ChevronDown className='h-3 w-3 text-zinc-500 shrink-0' />
          : <ChevronRight className='h-3 w-3 text-zinc-600 shrink-0' />}
      </button>
      {open && (
        <div className='p-3 bg-zinc-950/50'>
          {hint && <p className='text-[10px] text-zinc-600 mb-2'>- {hint}</p>}
          <Textarea
            rows={rows}
            value={value}
            onChange={e => onChange(e.target.value)}
            placeholder={placeholder}
            className={cn(
              'bg-zinc-950 border-zinc-800 text-zinc-200 placeholder:text-zinc-700 text-xs focus:border-zinc-600 resize-y',
              mono && 'font-mono text-[11px]'
            )}
            style={{ borderColor: open ? accent + '40' : undefined }}
          />
        </div>
      )}
    </div>
  )
}

// ─── Saved list (authored papers) ─────────────────────────────────────────────
function SavedList({ papers, onLoad, onDelete, currentId }: {
  papers: SavedPaper[]; onLoad: (id: string) => void
  onDelete: (id: string) => void; currentId: string | null
}) {
  if (!papers.length)
    return <p className='text-[11px] text-zinc-600 text-center py-4'>No hay papers guardados</p>
  return (
    <div className='space-y-0.5'>
      {papers.map(p => {
        const tmpl = TEMPLATE_MAP[p.template]
        return (
          <div key={p.id} className={cn(
            'flex items-center gap-2 rounded px-2 py-1.5 group cursor-pointer transition',
            currentId === p.id ? 'bg-zinc-700/50' : 'hover:bg-zinc-800/50'
          )}>
            <div className='h-1.5 w-1.5 rounded-full shrink-0' style={{ background: tmpl?.accent ?? '#94a3b8' }} />
            <button onClick={() => onLoad(p.id)} className='flex-1 min-w-0 text-left'>
              <p className={cn('text-[11px] truncate', currentId === p.id ? 'text-zinc-100' : 'text-zinc-300')}>
                {p.title || '(sin título)'}
              </p>
              <p className='text-[9px] text-zinc-600 truncate mt-0.5'>
                {tmpl?.label ?? p.template}
                {p.cve_id ? ` · ${p.cve_id}` : ''}
                {p.cvss_score != null ? ` · CVSS ${Number(p.cvss_score).toFixed(1)}` : ''}
              </p>
            </button>
            <span className={cn('text-[9px] rounded px-1.5 py-0.5 shrink-0', STATUS_CLS[p.status] ?? STATUS_CLS.draft)}>
              {STATUS_LABEL[p.status] ?? p.status}
            </span>
            <button onClick={() => onDelete(p.id)}
              className='opacity-0 group-hover:opacity-100 p-0.5 text-zinc-600 hover:text-red-400 transition shrink-0'>
              <Trash2 className='h-3 w-3' />
            </button>
          </div>
        )
      })}
    </div>
  )
}

// ─── Exploit-DB Search Panel ───────────────────────────────────────────────────
function ExploitDBPanel() {
  const [query, setQuery]             = useState('')
  const [searching, setSearching]     = useState(false)
  const [results, setResults]         = useState<EdbResult[]>([])
  const [total, setTotal]             = useState<number | null>(null)
  const [searched, setSearched]       = useState(false)
  const [downloading, setDownloading] = useState<string | null>(null)
  const [saving, setSaving]           = useState<string | null>(null)
  const [savedIds, setSavedIds]       = useState<Set<string>>(new Set())
  const [savedList, setSavedList]     = useState<SavedEdbPaper[]>([])
  const [deleting, setDeleting]       = useState<string | null>(null)
  const [tab, setTab]                 = useState<'search' | 'saved'>('search')
  const inputRef = useRef<HTMLInputElement>(null)

  const loadSaved = useCallback(async () => {
    try {
      const rows = await apiFetch<SavedEdbPaper[]>('/exploitdb/saved') ?? []
      setSavedList(rows)
      setSavedIds(new Set(rows.map(r => r.edb_id)))
    } catch {}
  }, [])

  useEffect(() => { loadSaved() }, [loadSaved])

  async function handleSearch(e?: React.FormEvent) {
    e?.preventDefault()
    if (!query.trim()) return
    setSearching(true)
    setSearched(true)
    try {
      const res = await apiFetch<{ total: number; papers: EdbResult[] }>(`/exploitdb/search?q=${encodeURIComponent(query.trim())}`)
      setResults(res?.papers ?? [])
      setTotal(res?.total ?? 0)
    } catch {
      toast.error('Error al conectar con Exploit-DB')
      setResults([])
    } finally { setSearching(false) }
  }

  async function handleDownload(r: EdbResult) {
    setDownloading(r.edb_id)
    try {
      const token = localStorage.getItem('gungnir_token') ?? ''
      const resp  = await fetch(`/api/exploitdb/paper/${r.edb_id}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (resp.status === 422) {
        // Existe pero no es PDF - informar, sin redirigir (el botón EDB está para eso)
        toast.error('Este entry no tiene PDF - es código o texto. Usá el botón EDB para verlo.', { duration: 4000 })
        return
      }
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const blob  = await resp.blob()
      const url   = URL.createObjectURL(blob)
      const a     = document.createElement('a')
      a.href      = url
      a.download  = `exploitdb_${r.edb_id}_${(r.title || 'paper').replace(/[^a-zA-Z0-9]+/g, '_').slice(0, 40)}.pdf`
      a.click()
      setTimeout(() => URL.revokeObjectURL(url), 5000)
    } catch (e) {
      toast.error(`No se pudo descargar: ${e instanceof Error ? e.message : 'Error'}`)
    } finally { setDownloading(null) }
  }

  async function handleSave(r: EdbResult) {
    if (savedIds.has(r.edb_id)) {
      toast.info('Este paper ya está guardado')
      return
    }
    setSaving(r.edb_id)
    try {
      const res = await apiFetch<{ id: string; pdf_available: boolean }>(
        `/exploitdb/saved/${r.edb_id}`,
        {
          method: 'POST',
          body: JSON.stringify({ title: r.title, author: r.author, edb_date: r.date }),
        }
      )
      if (res?.id) {
        toast.success(res.pdf_available ? 'Paper guardado con PDF' : 'Paper guardado (PDF no disponible)')
        await loadSaved()
      }
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? ''
      if (msg.includes('409') || msg.includes('ya está')) {
        toast.info('Este paper ya está guardado')
        await loadSaved()
      } else {
        toast.error('Error al guardar')
      }
    } finally { setSaving(null) }
  }

  async function handleDeleteSaved(id: string) {
    setDeleting(id)
    try {
      await apiFetch(`/exploitdb/saved/${id}`, { method: 'DELETE' })
      toast.success('Paper eliminado')
      await loadSaved()
    } catch { toast.error('Error al eliminar') } finally { setDeleting(null) }
  }

  async function handleDownloadSaved(item: SavedEdbPaper) {
    setDownloading(item.id)
    try {
      const token = localStorage.getItem('gungnir_token') ?? ''
      const resp  = await fetch(`/api/exploitdb/saved/${item.id}/pdf`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (resp.status === 422) {
        toast.error('Este entry no tiene PDF - es código o texto. Usá el botón EDB para verlo.', { duration: 5000 })
        return
      }
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        throw new Error((err as { error?: string }).error ?? `HTTP ${resp.status}`)
      }
      const blob  = await resp.blob()
      const url   = URL.createObjectURL(blob)
      const a     = document.createElement('a')
      a.href      = url
      a.download  = `exploitdb_${item.edb_id}.pdf`
      a.click()
      setTimeout(() => URL.revokeObjectURL(url), 5000)
    } catch (e) {
      toast.error(`${e instanceof Error ? e.message : 'Error al descargar'}`)
    } finally { setDownloading(null) }
  }

  const EDB_GREEN = '#16a34a'

  return (
    <div className='p-5 max-w-3xl mx-auto space-y-4'>

      {/* Header */}
      <div className='rounded-xl border p-4 flex items-center gap-3'
        style={{ background: EDB_GREEN + '0d', borderColor: EDB_GREEN + '30' }}>
        <div className='rounded-lg p-2' style={{ background: EDB_GREEN + '20', color: EDB_GREEN }}>
          <BookOpen className='h-5 w-5' />
        </div>
        <div className='flex-1 min-w-0'>
          <p className='font-bold text-sm' style={{ color: EDB_GREEN }}>Exploit-DB Papers</p>
          <p className='text-xs text-zinc-500 mt-0.5'>
            Buscá papers publicados en exploit-db.com - descargalos o guardalos en tu biblioteca
          </p>
        </div>
        <a
          href='https://www.exploit-db.com/papers'
          target='_blank'
          rel='noopener noreferrer'
          className='flex items-center gap-1 text-[10px] px-2 py-1 rounded border transition'
          style={{ borderColor: EDB_GREEN + '40', color: EDB_GREEN + 'cc' }}
        >
          <ExternalLink className='h-3 w-3' />
          exploit-db.com
        </a>
      </div>

      {/* Tabs */}
      <div className='flex gap-1 bg-zinc-900/50 rounded-lg p-1 border border-zinc-800'>
        <button
          onClick={() => setTab('search')}
          className={cn(
            'flex-1 flex items-center justify-center gap-1.5 rounded-md py-1.5 text-xs font-medium transition',
            tab === 'search'
              ? 'bg-zinc-800 text-zinc-100'
              : 'text-zinc-500 hover:text-zinc-300'
          )}
        >
          <Search className='h-3 w-3' />
          Buscar
        </button>
        <button
          onClick={() => setTab('saved')}
          className={cn(
            'flex-1 flex items-center justify-center gap-1.5 rounded-md py-1.5 text-xs font-medium transition',
            tab === 'saved'
              ? 'bg-zinc-800 text-zinc-100'
              : 'text-zinc-500 hover:text-zinc-300'
          )}
        >
          <Star className='h-3 w-3' />
          Guardados
          {savedList.length > 0 && (
            <span className='ml-1 bg-zinc-700 text-zinc-300 rounded px-1.5 text-[9px]'>{savedList.length}</span>
          )}
        </button>
      </div>

      {/* ── Search tab ── */}
      {tab === 'search' && (
        <div className='space-y-4'>
          {/* Search form */}
          <form onSubmit={handleSearch} className='flex gap-2'>
            <Input
              ref={inputRef}
              placeholder='ej: EternalBlue, heartbleed, ms17-010...'
              value={query}
              onChange={e => setQuery(e.target.value)}
              className='flex-1 bg-zinc-900/60 border-zinc-800 text-zinc-200 placeholder:text-zinc-700 text-xs h-9 focus:border-zinc-600'
            />
            <Button
              type='submit'
              disabled={searching || !query.trim()}
              className='gap-1.5 text-xs h-9 px-4 font-semibold text-white'
              style={{ background: EDB_GREEN }}
            >
              {searching
                ? <><Loader2 className='h-3.5 w-3.5 animate-spin' /> Buscando...</>
                : <><Search className='h-3.5 w-3.5' /> Buscar</>}
            </Button>
          </form>

          {/* Results */}
          {searched && !searching && results.length === 0 && (
            <div className='rounded-lg border border-zinc-800 bg-zinc-900/30 p-6 text-center'>
              <FileText className='h-6 w-6 text-zinc-700 mx-auto mb-2' />
              <p className='text-sm text-zinc-500'>No se encontraron papers para "{query}"</p>
              <p className='text-xs text-zinc-700 mt-1'>Probá con un término diferente</p>
            </div>
          )}

          {results.length > 0 && (
            <div className='space-y-2'>
              <div className='flex items-center justify-between'>
                <p className='text-[10px] text-zinc-600 uppercase tracking-widest font-bold'>
                  Resultados
                </p>
                {total != null && (
                  <span className='text-[10px] text-zinc-600'>
                    {results.length} de {total} papers
                  </span>
                )}
              </div>

              {results.map(r => {
                const isSaved    = savedIds.has(r.edb_id)
                const isDownloading = downloading === r.edb_id
                const isSaving   = saving === r.edb_id
                return (
                  <div key={r.edb_id}
                    className='rounded-xl border border-zinc-800 bg-zinc-900/30 p-3.5 flex gap-3 hover:border-zinc-700 transition'>
                    {/* EDB ID badge */}
                    <div className='shrink-0 flex flex-col items-center'>
                      <span className='font-mono text-[9px] font-bold rounded px-1.5 py-0.5'
                        style={{ background: EDB_GREEN + '18', color: EDB_GREEN, border: `0.3px solid ${EDB_GREEN}40` }}>
                        #{r.edb_id}
                      </span>
                    </div>
                    {/* Info */}
                    <div className='flex-1 min-w-0'>
                      <p className='text-xs font-semibold text-zinc-200 leading-snug'>{r.title || '(sin título)'}</p>
                      <p className='text-[10px] text-zinc-600 mt-0.5'>
                        {r.author && <span>{r.author}</span>}
                        {r.author && r.date && <span className='mx-1'>·</span>}
                        {r.date && <span>{r.date}</span>}
                      </p>
                    </div>
                    {/* Actions */}
                    <div className='flex items-center gap-1.5 shrink-0'>
                      <Button
                        size='sm'
                        variant='outline'
                        onClick={() => handleDownload(r)}
                        disabled={isDownloading}
                        className='h-7 px-2 text-[10px] border-zinc-700 text-zinc-400 hover:text-zinc-100 hover:border-zinc-500 gap-1'
                      >
                        {isDownloading
                          ? <Loader2 className='h-3 w-3 animate-spin' />
                          : <Download className='h-3 w-3' />}
                        PDF
                      </Button>
                      <a
                        href={`https://www.exploit-db.com/papers/${r.edb_id}`}
                        target='_blank'
                        rel='noopener noreferrer'
                        className='inline-flex items-center gap-1 h-7 px-2 text-[10px] rounded-md border border-zinc-700 text-zinc-400 hover:text-zinc-100 hover:border-zinc-500 transition-colors font-medium'
                        title='Ver en Exploit-DB'
                      >
                        <ExternalLink className='h-3 w-3' />
                        EDB
                      </a>
                      <Button
                        size='sm'
                        onClick={() => handleSave(r)}
                        disabled={isSaving || isSaved}
                        className={cn(
                          'h-7 px-2 text-[10px] gap-1 font-medium',
                          isSaved
                            ? 'bg-zinc-800 text-zinc-500 cursor-default'
                            : 'text-white'
                        )}
                        style={!isSaved ? { background: EDB_GREEN } : {}}
                      >
                        {isSaving
                          ? <Loader2 className='h-3 w-3 animate-spin' />
                          : <Star className='h-3 w-3' />}
                        {isSaved ? 'Guardado' : 'Guardar'}
                      </Button>
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          {!searched && (
            <div className='rounded-lg border border-dashed border-zinc-800 p-8 text-center'>
              <Search className='h-6 w-6 text-zinc-700 mx-auto mb-3' />
              <p className='text-sm text-zinc-500'>Buscá un paper en Exploit-DB</p>
              <p className='text-xs text-zinc-700 mt-1'>Ingresá un término arriba y presioná Buscar</p>
            </div>
          )}
        </div>
      )}

      {/* ── Saved tab ── */}
      {tab === 'saved' && (
        <div className='space-y-2'>
          {savedList.length === 0 && (
            <div className='rounded-lg border border-dashed border-zinc-800 p-8 text-center'>
              <Star className='h-6 w-6 text-zinc-700 mx-auto mb-3' />
              <p className='text-sm text-zinc-500'>No hay papers guardados</p>
              <p className='text-xs text-zinc-700 mt-1'>
                Buscá papers en la pestaña "Buscar" y guárdalos para tenerlos a mano
              </p>
              <button
                onClick={() => setTab('search')}
                className='mt-3 text-xs underline underline-offset-2'
                style={{ color: EDB_GREEN }}>
                Ir a buscar
              </button>
            </div>
          )}

          {savedList.length > 0 && (
            <>
              <p className='text-[10px] text-zinc-600 uppercase tracking-widest font-bold'>
                Biblioteca - {savedList.length} paper{savedList.length !== 1 ? 's' : ''}
              </p>
              {savedList.map(item => {
                const isDownloading = downloading === item.id
                const isDeleting    = deleting === item.id
                return (
                  <div key={item.id}
                    className='rounded-xl border border-zinc-800 bg-zinc-900/30 p-3.5 flex gap-3 hover:border-zinc-700 transition group'>
                    {/* EDB ID */}
                    <div className='shrink-0'>
                      <span className='font-mono text-[9px] font-bold rounded px-1.5 py-0.5'
                        style={{ background: EDB_GREEN + '18', color: EDB_GREEN, border: `0.3px solid ${EDB_GREEN}40` }}>
                        #{item.edb_id}
                      </span>
                    </div>
                    {/* Info */}
                    <div className='flex-1 min-w-0'>
                      <p className='text-xs font-semibold text-zinc-200 leading-snug'>{item.title || '(sin título)'}</p>
                      <p className='text-[10px] text-zinc-600 mt-0.5'>
                        {item.author && <span>{item.author}</span>}
                        {item.author && item.edb_date && <span className='mx-1'>·</span>}
                        {item.edb_date && <span>{item.edb_date}</span>}
                        <span className='mx-1'>·</span>
                        <span>guardado {new Date(item.saved_at).toLocaleDateString('es-AR')}</span>
                      </p>
                    </div>
                    {/* Actions */}
                    <div className='flex items-center gap-1.5 shrink-0'>
                      <Button
                        size='sm'
                        variant='outline'
                        onClick={() => handleDownloadSaved(item)}
                        disabled={isDownloading}
                        className='h-7 px-2 text-[10px] border-zinc-700 text-zinc-400 hover:text-zinc-100 hover:border-zinc-500 gap-1'
                      >
                        {isDownloading
                          ? <Loader2 className='h-3 w-3 animate-spin' />
                          : <Download className='h-3 w-3' />}
                        PDF
                      </Button>
                      <a
                        href={`https://www.exploit-db.com/papers/${item.edb_id}`}
                        target='_blank'
                        rel='noopener noreferrer'
                        className='flex items-center gap-1 h-7 px-2 rounded border border-zinc-700 text-zinc-400 hover:text-zinc-100 hover:border-zinc-500 text-[10px] transition'
                      >
                        <ExternalLink className='h-3 w-3' />
                        EDB
                      </a>
                      <button
                        onClick={() => handleDeleteSaved(item.id)}
                        disabled={isDeleting}
                        className='opacity-0 group-hover:opacity-100 p-1 text-zinc-600 hover:text-red-400 transition'
                        title='Eliminar de la biblioteca'
                      >
                        {isDeleting
                          ? <Loader2 className='h-3.5 w-3.5 animate-spin' />
                          : <Trash2 className='h-3.5 w-3.5' />}
                      </button>
                    </div>
                  </div>
                )
              })}
            </>
          )}
        </div>
      )}

      {/* Footer note */}
      <div className='flex items-start gap-2 rounded-lg bg-zinc-900/30 border border-zinc-800/50 p-3'>
        <Shield className='h-3.5 w-3.5 text-zinc-600 mt-0.5 shrink-0' />
        <p className='text-[11px] text-zinc-600 leading-relaxed'>
          Exploit-DB es un repositorio público de seguridad mantenido por Offensive Security.
          Los papers guardados se almacenan localmente en Gungnir para referencia rápida.
          Respetá los términos de uso y la autoría de los papers que descargues.
        </p>
      </div>
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────
export function Papers() {
  const [data, setData]           = useState<PaperData>({ ...EMPTY })
  const [generating, setGen]      = useState(false)
  const [saving, setSaving]       = useState(false)
  const [papers, setPapers]       = useState<SavedPaper[]>([])
  const [currentId, setId]        = useState<string | null>(null)
  const [showSaved, setShowSaved] = useState(false)
  const [activeTab, setActiveTab] = useState<'editor' | 'exploitdb'>('editor')
  const titleRef = useRef<HTMLInputElement>(null)

  const loadList = useCallback(async () => {
    try { setPapers((await apiFetch<SavedPaper[]>('/papers')) ?? []) } catch {}
  }, [])

  useEffect(() => { loadList() }, [loadList])

  function setField(field: keyof PaperData) {
    return (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
      setData(p => ({ ...p, [field]: e.target.value }))
  }
  function setSectionVal(key: SectionKey, val: string) {
    setData(p => ({ ...p, [key]: val }))
  }
  function setVal(field: keyof PaperData, val: string | number | undefined) {
    setData(p => ({ ...p, [field]: val }))
  }

  function reset() {
    setData({ ...EMPTY, date: new Date().toLocaleDateString('es-AR') })
    setId(null)
    setTimeout(() => titleRef.current?.focus(), 50)
  }

  async function handleSave() {
    if (!data.title?.trim()) { toast.error('El paper necesita un título'); return }
    setSaving(true)
    try {
      if (currentId) {
        await apiFetch(`/papers/${currentId}`, { method: 'PUT', body: JSON.stringify(data) })
        toast.success('Paper actualizado')
      } else {
        const res = await apiFetch<{ id: string }>('/papers', { method: 'POST', body: JSON.stringify(data) })
        if (res?.id) setId(res.id)
        toast.success('Paper guardado')
      }
      await loadList()
    } catch { toast.error('Error al guardar') } finally { setSaving(false) }
  }

  async function handleLoad(id: string) {
    try {
      const row = await apiFetch<PaperData & { id: string }>(`/papers/${id}`)
      if (row) { setData(row); setId(id); setShowSaved(false) }
    } catch { toast.error('Error al cargar') }
  }

  async function handleDelete(id: string) {
    try {
      await apiFetch(`/papers/${id}`, { method: 'DELETE' })
      if (currentId === id) reset()
      await loadList()
      toast.success('Eliminado')
    } catch { toast.error('Error al eliminar') }
  }

  async function handleGenerate() {
    if (!data.title?.trim()) { toast.error('El paper necesita un título'); return }
    setGen(true)
    try {
      await generatePaperPDF(data)
      toast.success('PDF generado')
    } catch (e) {
      toast.error(`Error: ${e instanceof Error ? e.message : 'Error desconocido'}`)
    } finally { setGen(false) }
  }

  const selectedTmpl = TEMPLATE_MAP[data.template ?? 'blackhat']
  const accent       = selectedTmpl?.accent ?? '#94a3b8'
  const filledSecs   = PAPER_SECTIONS.filter(s => (data[s.key as keyof PaperData] as string)?.trim()).length
  const canGenerate  = !!data.title?.trim()

  return (
    <div className='flex h-[calc(100vh-4rem)] -m-6 overflow-hidden'>

      {/* ── Left panel ─────────────────────────────────────────────────────── */}
      <div className='w-80 shrink-0 flex flex-col border-r border-zinc-800 overflow-hidden bg-zinc-950/30'>

        {/* Header */}
        <div className='border-b border-zinc-800 p-4'>
          <div className='flex items-center gap-2 mb-1'>
            <GraduationCap className='h-4 w-4' style={{ color: accent }} />
            <h1 className='font-semibold text-sm text-zinc-200'>Research Papers</h1>
          </div>
          <p className='text-[11px] text-zinc-500'>
            Documenta investigación de seguridad para conferencias y publicación
          </p>
        </div>

        {/* Template selector - grouped */}
        <div className='p-3 border-b border-zinc-800 space-y-3 overflow-y-auto max-h-72'>
          {TEMPLATE_GROUPS.map(g => (
            <div key={g.group}>
              <p className='text-[9px] font-bold uppercase tracking-widest text-zinc-600 mb-1.5'>{g.group}</p>
              <div className='grid grid-cols-2 gap-1.5'>
                {g.items.map(t => {
                  const active = data.template === t.id
                  return (
                    <button
                      key={t.id}
                      onClick={() => { setVal('template', t.id); setActiveTab('editor') }}
                      className={cn(
                        'text-left rounded-lg border p-2 transition-all',
                        active ? 'border-zinc-600' : 'border-zinc-800 hover:border-zinc-700 bg-zinc-900/20'
                      )}
                      style={active ? { borderColor: t.accent + '60', background: t.accent + '0d' } : {}}
                    >
                      <div className='flex items-center gap-1.5 mb-0.5'>
                        <div className='h-2 w-2 rounded-full shrink-0' style={{ background: active ? t.accent : '#3f3f46' }} />
                        <p className={cn('text-[10px] font-semibold leading-tight truncate', active ? 'text-zinc-100' : 'text-zinc-400')}>
                          {t.label}
                        </p>
                      </div>
                      <p className='text-[8px] text-zinc-600 truncate pl-3.5'>{t.sub}</p>
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Actions */}
        <div className='px-3 pt-3 space-y-1.5'>
          <button
            onClick={reset}
            className='w-full flex items-center gap-2 rounded-lg border border-dashed px-3 py-2 text-xs transition'
            style={{ borderColor: accent + '40', color: accent + 'cc' }}
          >
            <Plus className='h-3.5 w-3.5 shrink-0' /> Nuevo paper
          </button>
          <button
            onClick={() => setShowSaved(v => !v)}
            className='w-full flex items-center gap-2 rounded-lg border border-dashed border-zinc-700/60 px-3 py-2 text-xs text-zinc-500 hover:text-zinc-300 hover:border-zinc-600 transition'
          >
            <FolderOpen className='h-3.5 w-3.5 text-amber-500/70 shrink-0' />
            Papers guardados
            {papers.length > 0 && (
              <span className='ml-auto text-[10px] bg-zinc-700 text-zinc-300 rounded px-1.5 py-0.5'>{papers.length}</span>
            )}
          </button>
        </div>

        {showSaved && (
          <div className='mx-3 mt-2 rounded-lg border border-zinc-700/60 bg-zinc-900/80 p-2 max-h-52 overflow-y-auto'>
            <SavedList papers={papers} currentId={currentId} onLoad={handleLoad} onDelete={handleDelete} />
          </div>
        )}

        {/* Metadata */}
        <div className='flex-1 overflow-y-auto p-3 space-y-2.5'>

          <div>
            <Label className='text-[9px] text-zinc-500 uppercase tracking-widest'>Título *</Label>
            <Input
              ref={titleRef}
              className='mt-1 bg-zinc-900/60 border-zinc-800 text-zinc-200 placeholder:text-zinc-700 text-xs h-8 focus:border-zinc-600'
              placeholder='Título del paper...'
              value={data.title}
              onChange={setField('title')}
            />
          </div>

          <div>
            <Label className='text-[9px] text-zinc-500 uppercase tracking-widest'>Categoría</Label>
            <div className='mt-1 flex flex-wrap gap-1'>
              {CATEGORY_OPTIONS.map(c => (
                <button key={c.id} onClick={() => setVal('category', c.id)}
                  className={cn('rounded px-2 py-0.5 text-[9px] font-medium border transition-all',
                    data.category === c.id
                      ? 'border-zinc-500 bg-zinc-700 text-zinc-100'
                      : 'border-zinc-800 text-zinc-600 hover:border-zinc-700 hover:text-zinc-400'
                  )}>
                  {c.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <Label className='text-[9px] text-zinc-500 uppercase tracking-widest'>Autor(es)</Label>
            <Input className='mt-1 bg-zinc-900/60 border-zinc-800 text-zinc-200 placeholder:text-zinc-700 text-xs h-8'
              placeholder='Nombre / @handle / afiliación'
              value={data.authors ?? ''} onChange={setField('authors')} />
          </div>

          <div className='grid grid-cols-2 gap-2'>
            <div>
              <Label className='text-[9px] text-zinc-500 uppercase tracking-widest'>Fecha</Label>
              <Input className='mt-1 bg-zinc-900/60 border-zinc-800 text-zinc-200 placeholder:text-zinc-700 text-xs h-8'
                value={data.date ?? ''} onChange={setField('date')} />
            </div>
            <div>
              <Label className='text-[9px] text-zinc-500 uppercase tracking-widest'>CVE / ID</Label>
              <Input className='mt-1 bg-zinc-900/60 border-zinc-800 text-zinc-200 placeholder:text-zinc-700 text-xs h-8 font-mono'
                placeholder='CVE-2024-...' value={data.cve_id ?? ''} onChange={setField('cve_id')} />
            </div>
          </div>

          <div className='grid grid-cols-2 gap-2'>
            <div>
              <Label className='text-[9px] text-zinc-500 uppercase tracking-widest'>CVSS Score</Label>
              <Input type='number' step='0.1' min='0' max='10'
                className='mt-1 bg-zinc-900/60 border-zinc-800 text-zinc-200 placeholder:text-zinc-700 text-xs h-8 font-mono'
                placeholder='9.8'
                value={data.cvss_score != null ? String(data.cvss_score) : ''}
                onChange={e => setVal('cvss_score', e.target.value ? parseFloat(e.target.value) : undefined)} />
            </div>
            <div>
              <Label className='text-[9px] text-zinc-500 uppercase tracking-widest'>Estado</Label>
              <select
                value={data.status ?? 'draft'}
                onChange={e => setVal('status', e.target.value)}
                className='mt-1 w-full rounded border border-zinc-800 bg-zinc-900 px-2 py-1 text-xs text-zinc-200 focus:outline-none focus:border-zinc-600 h-8'>
                {STATUS_OPTIONS.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
              </select>
            </div>
          </div>

          <div>
            <Label className='text-[9px] text-zinc-500 uppercase tracking-widest'>CVSS Vector</Label>
            <Input className='mt-1 bg-zinc-900/60 border-zinc-800 text-zinc-200 placeholder:text-zinc-700 text-xs h-8 font-mono'
              placeholder='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/...'
              value={data.cvss_vector ?? ''} onChange={setField('cvss_vector')} />
          </div>

          <div>
            <Label className='text-[9px] text-zinc-500 uppercase tracking-widest'>Advisory URL</Label>
            <Input className='mt-1 bg-zinc-900/60 border-zinc-800 text-zinc-200 placeholder:text-zinc-700 text-xs h-8'
              placeholder='https://...' value={data.advisory_url ?? ''} onChange={setField('advisory_url')} />
          </div>

          <div>
            <Label className='text-[9px] text-zinc-500 uppercase tracking-widest'>Tags</Label>
            <Input className='mt-1 bg-zinc-900/60 border-zinc-800 text-zinc-200 placeholder:text-zinc-700 text-xs h-8'
              placeholder='RCE, SMB, Windows, CVE, ...'
              value={data.tags ?? ''} onChange={setField('tags')} />
          </div>
        </div>

        {/* Bottom actions */}
        <div className='border-t border-zinc-800 p-3 space-y-2'>
          {currentId && (
            <div className='flex items-center gap-1.5 text-[10px] text-amber-400/80 bg-amber-500/10 rounded px-2 py-1 border border-amber-500/20'>
              <FolderOpen className='h-3 w-3 shrink-0' />
              <span className='truncate'>Editando: {papers.find(p => p.id === currentId)?.title || 'Paper guardado'}</span>
            </div>
          )}
          <Button
            onClick={handleGenerate}
            disabled={!canGenerate || generating}
            className={cn('w-full gap-2 font-semibold', canGenerate ? 'text-white' : 'opacity-40')}
            style={{ background: canGenerate ? accent : undefined }}
          >
            {generating
              ? <><Loader2 className='h-4 w-4 animate-spin' /> Generando PDF...</>
              : <><Download className='h-4 w-4' /> Exportar PDF</>}
          </Button>
          <div className='flex gap-2'>
            <Button variant='outline' size='sm' onClick={handleSave}
              disabled={!canGenerate || saving}
              className='flex-1 gap-1.5 text-xs border-zinc-700 text-zinc-300 hover:bg-zinc-800'>
              {saving ? <Loader2 className='h-3 w-3 animate-spin' /> : <Save className='h-3 w-3' />}
              {saving ? 'Guardando...' : currentId ? 'Actualizar' : 'Guardar'}
            </Button>
            <Button variant='ghost' size='sm' onClick={reset} title='Nuevo'
              className='text-zinc-600 hover:text-zinc-400 text-xs h-8 px-3'>
              <RotateCcw className='h-3 w-3' />
            </Button>
          </div>
        </div>
      </div>

      {/* ── Right panel ────────────────────────────────────────────────────── */}
      <div className='flex-1 flex flex-col overflow-hidden'>

        {/* Tab bar */}
        <div className='border-b border-zinc-800 bg-zinc-950/50 px-5 pt-3 pb-0 flex gap-1'>
          <button
            onClick={() => setActiveTab('editor')}
            className={cn(
              'flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-colors -mb-px',
              activeTab === 'editor'
                ? 'border-current text-zinc-100'
                : 'border-transparent text-zinc-500 hover:text-zinc-300'
            )}
            style={activeTab === 'editor' ? { borderColor: accent, color: accent } : {}}
          >
            <GraduationCap className='h-3.5 w-3.5' />
            Editor
            {filledSecs > 0 && (
              <span className='ml-1 text-[9px] rounded px-1'
                style={{ background: accent + '20', color: accent }}>
                {filledSecs}/16
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('exploitdb')}
            className={cn(
              'flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-colors -mb-px',
              activeTab === 'exploitdb'
                ? 'border-green-500 text-green-400'
                : 'border-transparent text-zinc-500 hover:text-zinc-300'
            )}
          >
            <BookOpen className='h-3.5 w-3.5' />
            Exploit-DB
          </button>
        </div>

        {/* Tab content */}
        <div className='flex-1 overflow-y-auto'>
          {activeTab === 'editor' && (
            <div className='p-5 max-w-3xl mx-auto space-y-3'>

              {/* Banner */}
              <div className='rounded-xl border p-4 flex items-center gap-3'
                style={{ background: accent + '0d', borderColor: accent + '30' }}>
                <div className='rounded-lg p-2' style={{ background: accent + '20', color: accent }}>
                  <GraduationCap className='h-5 w-5' />
                </div>
                <div className='flex-1 min-w-0'>
                  <p className='font-bold text-sm truncate' style={{ color: accent }}>
                    {selectedTmpl?.label ?? 'Paper'} - {CATEGORY_OPTIONS.find(c => c.id === data.category)?.label ?? ''}
                  </p>
                  <p className='text-xs text-zinc-500 truncate mt-0.5'>
                    {data.title ? `"${data.title}"` : 'Escribe el título en el panel izquierdo'}
                    {data.cve_id ? ` · ${data.cve_id}` : ''}
                    {data.cvss_score != null ? ` · CVSS ${Number(data.cvss_score).toFixed(1)}` : ''}
                  </p>
                </div>
                {filledSecs > 0 && (
                  <div className='text-right shrink-0'>
                    <p className='text-xs font-semibold' style={{ color: accent }}>{filledSecs}</p>
                    <p className='text-[9px] text-zinc-600'>secciones</p>
                  </div>
                )}
              </div>

              {/* Sections */}
              {PAPER_SECTIONS.map(sec => (
                <SectionCard
                  key={sec.key}
                  num={sec.num}
                  title={sec.title}
                  hint={sec.hint}
                  value={(data[sec.key as keyof PaperData] as string) ?? ''}
                  onChange={v => setSectionVal(sec.key, v)}
                  rows={sec.rows}
                  mono={'mono' in sec ? sec.mono : false}
                  accent={accent}
                />
              ))}

              {/* Generate CTA */}
              <div className='rounded-xl border border-zinc-800 bg-zinc-950 p-5'>
                <div className='flex items-center justify-between gap-4'>
                  <div>
                    <p className='text-sm font-medium text-zinc-200'>
                      {selectedTmpl?.label ?? 'Research'} Paper - PDF
                    </p>
                    <p className='text-xs text-zinc-500 mt-0.5'>
                      Portada · Abstract · {filledSecs} secciones · Pie de página
                    </p>
                    {!canGenerate && (
                      <p className='mt-2 flex items-center gap-1.5 text-xs text-yellow-500'>
                        <AlertTriangle className='h-3.5 w-3.5' /> Agregá un título para continuar
                      </p>
                    )}
                    {canGenerate && (
                      <p className='mt-2 flex items-center gap-1.5 text-xs text-zinc-600'>
                        <CheckCircle2 className='h-3.5 w-3.5 text-green-600' /> Listo - {filledSecs} de 16 secciones completadas
                      </p>
                    )}
                  </div>
                  <Button
                    onClick={handleGenerate}
                    disabled={!canGenerate || generating}
                    className={cn('shrink-0 gap-2 font-semibold text-white', !canGenerate && 'opacity-40')}
                    style={{ background: canGenerate ? accent : undefined }}
                  >
                    {generating
                      ? <><Loader2 className='h-4 w-4 animate-spin' /> Generando...</>
                      : <><Download className='h-4 w-4' /> Exportar PDF</>}
                  </Button>
                </div>
              </div>

              {/* Note */}
              <div className='flex items-start gap-2 rounded-lg bg-zinc-900/30 border border-zinc-800/50 p-3'>
                <Shield className='h-3.5 w-3.5 text-zinc-600 mt-0.5 shrink-0' />
                <p className='text-[11px] text-zinc-600 leading-relaxed'>
                  Seguí un proceso de responsible disclosure antes de publicar investigaciones de vulnerabilidades. Black Hat indica que el contenido generado por LLM no puede ser el cuerpo principal de una submission - usá esta herramienta para estructurar y formatear, pero la investigación debe ser tuya.
                </p>
              </div>

              <div className='h-4' />
            </div>
          )}

          {activeTab === 'exploitdb' && <ExploitDBPanel />}
        </div>
      </div>
    </div>
  )
}
