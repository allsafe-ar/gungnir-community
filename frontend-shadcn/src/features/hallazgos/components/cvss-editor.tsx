/**
 * CVSS 3.1 Editor visual — AllSafe Gungnir
 * Calcula el score base en el frontend sin backend.
 * Basado en la especificación CVSS 3.1 del FIRST.
 */

import { useMemo } from 'react'
import { cn } from '@/lib/utils'

// ─── Tipos CVSS ───────────────────────────────────────────────────────────────
export interface CvssVector {
  AV: 'N' | 'A' | 'L' | 'P'   // Attack Vector
  AC: 'L' | 'H'                 // Attack Complexity
  PR: 'N' | 'L' | 'H'          // Privileges Required
  UI: 'N' | 'R'                 // User Interaction
  S:  'U' | 'C'                 // Scope
  C:  'N' | 'L' | 'H'          // Confidentiality
  I:  'N' | 'L' | 'H'          // Integrity
  A:  'N' | 'L' | 'H'          // Availability
}

export const DEFAULT_VECTOR: CvssVector = {
  AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H',
}

// ─── Cálculo CVSS 3.1 ────────────────────────────────────────────────────────
export function calcCvss31(v: CvssVector): number {
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2  }[v.AV]
  const AC = { L: 0.77, H: 0.44 }[v.AC]
  const PR_U = { N: 0.85, L: 0.62, H: 0.27 }[v.PR]  // Scope Unchanged
  const PR_C = { N: 0.85, L: 0.68, H: 0.50 }[v.PR]  // Scope Changed
  const PR = v.S === 'U' ? PR_U : PR_C
  const UI = { N: 0.85, R: 0.62 }[v.UI]
  const C = { N: 0, L: 0.22, H: 0.56 }[v.C]
  const I = { N: 0, L: 0.22, H: 0.56 }[v.I]
  const A = { N: 0, L: 0.22, H: 0.56 }[v.A]

  const ISCBase = 1 - (1 - C) * (1 - I) * (1 - A)
  const ISS = v.S === 'U'
    ? 6.42 * ISCBase
    : 7.52 * (ISCBase - 0.029) - 3.25 * Math.pow(ISCBase - 0.02, 15)

  if (ISS <= 0) return 0

  const ExSS = AV * AC * PR * UI
  const raw = v.S === 'U'
    ? Math.min(ISS + ExSS, 10)
    : Math.min(1.08 * (ISS + ExSS), 10)

  return Math.ceil(raw * 10) / 10
}

function scoreToSeverity(score: number): { label: string; color: string; bg: string } {
  if (score === 0)          return { label: 'None',     color: 'text-muted-foreground', bg: 'bg-muted' }
  if (score < 4)            return { label: 'Low',      color: 'text-blue-400',         bg: 'bg-blue-500/10' }
  if (score < 7)            return { label: 'Medium',   color: 'text-yellow-400',       bg: 'bg-yellow-500/10' }
  if (score < 9)            return { label: 'High',     color: 'text-orange-400',       bg: 'bg-orange-500/10' }
  return                           { label: 'Critical', color: 'text-red-400',          bg: 'bg-red-500/10' }
}

export function vectorToString(v: CvssVector): string {
  return `CVSS:3.1/AV:${v.AV}/AC:${v.AC}/PR:${v.PR}/UI:${v.UI}/S:${v.S}/C:${v.C}/I:${v.I}/A:${v.A}`
}

export function stringToVector(str: string): CvssVector | null {
  try {
    const parts = str.replace('CVSS:3.1/', '').split('/')
    const get = (key: string) => parts.find(p => p.startsWith(key + ':'))?.split(':')[1] ?? null
    const v = {
      AV: get('AV'), AC: get('AC'), PR: get('PR'), UI: get('UI'),
      S: get('S'), C: get('C'), I: get('I'), A: get('A'),
    }
    if (Object.values(v).some(x => !x)) return null
    return v as CvssVector
  } catch { return null }
}

// ─── Grupos de métricas ───────────────────────────────────────────────────────
const METRICS = [
  {
    group: 'Explotabilidad',
    items: [
      {
        key: 'AV', label: 'Attack Vector',
        options: [
          { value: 'N', label: 'Network',   desc: 'Explotable remotamente vía red' },
          { value: 'A', label: 'Adjacent',  desc: 'Requiere acceso a la misma red local' },
          { value: 'L', label: 'Local',     desc: 'Requiere acceso local al sistema' },
          { value: 'P', label: 'Physical',  desc: 'Requiere acceso físico al hardware' },
        ],
      },
      {
        key: 'AC', label: 'Attack Complexity',
        options: [
          { value: 'L', label: 'Low',  desc: 'No requiere condiciones especiales' },
          { value: 'H', label: 'High', desc: 'Requiere condiciones específicas difíciles' },
        ],
      },
      {
        key: 'PR', label: 'Privileges Required',
        options: [
          { value: 'N', label: 'None', desc: 'No necesita autenticación previa' },
          { value: 'L', label: 'Low',  desc: 'Requiere privilegios básicos (usuario normal)' },
          { value: 'H', label: 'High', desc: 'Requiere privilegios elevados (admin/root)' },
        ],
      },
      {
        key: 'UI', label: 'User Interaction',
        options: [
          { value: 'N', label: 'None',     desc: 'No requiere acción de ningún usuario' },
          { value: 'R', label: 'Required', desc: 'Requiere que un usuario tome alguna acción' },
        ],
      },
    ],
  },
  {
    group: 'Alcance',
    items: [
      {
        key: 'S', label: 'Scope',
        options: [
          { value: 'U', label: 'Unchanged', desc: 'El impacto se limita al componente vulnerable' },
          { value: 'C', label: 'Changed',   desc: 'El impacto se extiende a otros componentes' },
        ],
      },
    ],
  },
  {
    group: 'Impacto',
    items: [
      {
        key: 'C', label: 'Confidentiality',
        options: [
          { value: 'N', label: 'None', desc: 'Sin impacto en confidencialidad' },
          { value: 'L', label: 'Low',  desc: 'Acceso parcial a información sensible' },
          { value: 'H', label: 'High', desc: 'Acceso total a toda la información' },
        ],
      },
      {
        key: 'I', label: 'Integrity',
        options: [
          { value: 'N', label: 'None', desc: 'Sin impacto en integridad' },
          { value: 'L', label: 'Low',  desc: 'Modificación parcial de datos' },
          { value: 'H', label: 'High', desc: 'Modificación completa de datos' },
        ],
      },
      {
        key: 'A', label: 'Availability',
        options: [
          { value: 'N', label: 'None', desc: 'Sin impacto en disponibilidad' },
          { value: 'L', label: 'Low',  desc: 'Degradación parcial del servicio' },
          { value: 'H', label: 'High', desc: 'Servicio completamente inaccesible' },
        ],
      },
    ],
  },
]

// ─── Componente ───────────────────────────────────────────────────────────────
interface CvssEditorProps {
  value: CvssVector
  onChange: (v: CvssVector) => void
  className?: string
}

export function CvssEditor({ value, onChange, className }: CvssEditorProps) {
  const score = useMemo(() => calcCvss31(value), [value])
  const sev = scoreToSeverity(score)
  const vector = vectorToString(value)

  const setMetric = (key: keyof CvssVector, val: string) => {
    onChange({ ...value, [key]: val })
  }

  return (
    <div className={cn('space-y-5', className)}>
      {/* Score badge */}
      <div className={cn('flex items-center gap-4 rounded-lg border p-4', sev.bg)}>
        <div className={cn('text-5xl font-bold tabular-nums', sev.color)}>
          {score.toFixed(1)}
        </div>
        <div>
          <div className={cn('text-lg font-bold', sev.color)}>{sev.label}</div>
          <div className='text-xs font-mono text-muted-foreground mt-0.5 break-all'>{vector}</div>
        </div>
        <button
          type='button'
          onClick={() => navigator.clipboard.writeText(vector).then(() => {})}
          className='ml-auto text-xs text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded border border-border hover:border-primary'
        >
          Copiar vector
        </button>
      </div>

      {/* Métricas */}
      {METRICS.map(group => (
        <div key={group.group}>
          <p className='text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-3'>
            {group.group}
          </p>
          <div className='space-y-3'>
            {group.items.map(metric => {
              const current = value[metric.key as keyof CvssVector]
              return (
                <div key={metric.key}>
                  <p className='text-sm font-medium mb-1.5'>{metric.label}</p>
                  <div className='flex flex-wrap gap-2'>
                    {metric.options.map(opt => (
                      <button
                        key={opt.value}
                        type='button'
                        title={opt.desc}
                        onClick={() => setMetric(metric.key as keyof CvssVector, opt.value)}
                        className={cn(
                          'rounded-md border px-3 py-1.5 text-xs font-medium transition-all',
                          current === opt.value
                            ? 'border-primary bg-primary text-primary-foreground'
                            : 'border-border bg-transparent text-muted-foreground hover:border-primary/50 hover:text-foreground'
                        )}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                  {/* Mostrar descripción de la opción activa */}
                  <p className='text-xs text-muted-foreground mt-1'>
                    {metric.options.find(o => o.value === current)?.desc}
                  </p>
                </div>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}
