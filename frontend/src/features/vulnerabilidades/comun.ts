/**
 * Piezas comunes de Vulnerabilidades y Activos: tipos, colores, permisos y cliente recordado.
 * Los componentes (insignias y selector de cliente) están en `componentes.tsx`.
 *
 * 🔑 En Gungnir el inventario y las vulnerabilidades son de cada CLIENTE (la organización que se
 * audita). Las dos pantallas eligen cliente con el mismo selector y lo recuerdan en este navegador.
 *
 * Copia de Gungnir Pro. En Community no hay inquilinos: el administrador de la instalación es quien
 * en Pro es el staff (política global de plazos y "Actualizar ahora" de KEV y EPSS).
 */
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'

export type Severidad = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Estado = 'abierto' | 'en_remediacion' | 'remediado' | 'reabierto' | 'riesgo_aceptado' | 'falso_positivo'

export const SEVERIDADES: Severidad[] = ['critical', 'high', 'medium', 'low', 'info']
export const ESTADOS: Estado[] = ['abierto', 'en_remediacion', 'reabierto', 'remediado', 'riesgo_aceptado', 'falso_positivo']
/** A los que se puede pasar a mano: `reabierto` lo pone solo una importación. */
export const MANUALES: Estado[] = ['abierto', 'en_remediacion', 'remediado', 'riesgo_aceptado', 'falso_positivo']
export const FUENTES = ['openvas', 'nessus', 'nmap', 'zap', 'burp', 'sarif', 'trivy', 'nuclei', 'wazuh', 'manual'] as const
export const IMPORTABLES = ['openvas', 'nessus', 'nmap', 'zap', 'burp', 'sarif', 'trivy', 'nuclei'] as const
/** Formatos de código e imágenes: el activo es el repositorio o la imagen (se puede escribir al importar). */
export const CON_ACTIVO_DE_CODIGO = ['sarif', 'trivy'] as const

/** Prioridad calculada (etapa 2): no reemplaza a la severidad. La regla vive en el backend. */
export type Prioridad = 'urgente' | 'alta' | 'media' | 'baja'
export const PRIORIDADES: Prioridad[] = ['urgente', 'alta', 'media', 'baja']
export type EstadoPlazo = 'vencida' | 'por_vencer' | 'en_plazo' | 'sin_plazo' | 'no_aplica'

export interface KevDetalle {
  cve: string
  nombre: string | null
  proveedor: string | null
  producto: string | null
  alta: string | null
  vence: string | null
  ransomware: boolean
}

export interface Vulnerabilidad {
  id: string
  cliente_id: string
  activo_id: string
  fuente: string
  fuente_ultima: string | null
  titulo: string
  severidad: Severidad
  cvss: number | string | null
  cves: string | null
  cwe: string | null
  puerto: string | null
  protocolo: string | null
  servicio: string | null
  /** Etapa 4: "archivo:línea" (SARIF), el paquete (Trivy) o la URL (Nuclei). */
  ubicacion: string | null
  engagement_id: string | null
  finding_id: string | null
  estado: Estado
  primera_vez: string
  ultima_vez: string
  fecha_cierre: string | null
  reaperturas: number
  responsable: string | null
  prioridad: Prioridad | null
  epss: number | string | null
  epss_percentil: number | string | null
  kev: number | null
  kev_ransomware: number | null
  kev_vence: string | null
  /** Día límite "YYYY-MM-DD" (fecha de calendario, sin hora). */
  fecha_limite: string | null
  estado_plazo: EstadoPlazo
  kev_detalle?: KevDetalle[]
  activo_nombre: string
  activo_ip: string | null
  activo_hostname: string | null
}

export interface EventoHistorial {
  id: string
  estado_antes: Estado | null
  estado_despues: Estado | null
  evento: 'alta' | 'alta_manual' | 'cierre_auto' | 'reapertura' | 'manual' | 'a_engagement' | 'retest'
  motivo: string | null
  automatico: number
  importacion_id: string | null
  fuente: string | null
  usuario: string | null
  created_at: string
}

export interface FichaVulnerabilidad extends Omit<Vulnerabilidad, 'activo_nombre' | 'activo_ip' | 'activo_hostname'> {
  descripcion: string | null
  solucion: string | null
  evidencia: string | null
  cvss_vector: string | null
  regla: string | null
  notas: string | null
  activo: { id: string; nombre: string; ip: string | null; hostname: string | null; criticidad: string } | null
  historial: EventoHistorial[]
  plazo_desde: string
  kev_detalle: KevDetalle[]
  cves_detalle: { cve: string; epss: number | null; percentil: number | null; fecha_epss: string | null; kev: KevDetalle | null }[]
  /** El hallazgo del engagement al que se llevó (etapa 4). */
  engagement: EnlaceEngagement | null
}

export type RetestEstado = 'not_retested' | 'passed' | 'failed' | 'partial'
export interface EnlaceEngagement {
  roto?: boolean
  sin_acceso?: boolean
  finding_id?: string
  estado?: 'open' | 'in_remediation' | 'fixed' | 'accepted'
  retest?: RetestEstado
  retest_fecha?: string | null
  engagement_id?: string
  engagement_titulo?: string
  engagement_estado?: string
}

export interface Delta {
  importacion_id: string
  codigo: string
  fuente: string
  nuevos: number
  cerrados: number
  reabiertos: number
  sin_cambios: number
  decisiones_mantenidas: number
  total: number
  activos_nuevos: number
  alcance: number
  sin_activo: number
  alcance_no_reconocido: string[]
}

export const SEV_CLASE: Record<Severidad, string> = {
  critical: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30',
  high: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30',
  info: 'bg-muted text-muted-foreground border-border',
}

export const ESTADO_CLASE: Record<Estado, string> = {
  abierto: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30',
  en_remediacion: 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-500/30',
  reabierto: 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30',
  remediado: 'bg-green-500/10 text-green-700 dark:text-green-400 border-green-500/30',
  riesgo_aceptado: 'bg-slate-500/10 text-slate-700 dark:text-slate-300 border-slate-500/30',
  falso_positivo: 'bg-muted text-muted-foreground border-border',
}

export const PRIORIDAD_CLASE: Record<Prioridad, string> = {
  urgente: 'bg-red-600 text-white border-red-700 dark:bg-red-600 dark:text-white',
  alta: 'bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/40',
  media: 'bg-yellow-500/10 text-yellow-800 dark:text-yellow-300 border-yellow-500/30',
  baja: 'bg-muted text-muted-foreground border-border',
}

export const PLAZO_CLASE: Record<EstadoPlazo, string> = {
  vencida: 'text-red-600 dark:text-red-400',
  por_vencer: 'text-amber-700 dark:text-amber-400',
  en_plazo: 'text-green-700 dark:text-green-400',
  sin_plazo: 'text-muted-foreground',
  no_aplica: 'text-muted-foreground',
}

/** Lo que puede hacer la persona. El backend lo hace cumplir igual. */
export function usePermisos() {
  const role = useAuthStore((s) => s.auth.user?.role)
  const edita = role === 'admin' || role === 'auditor' || role === 'pentester'
  const conduce = role === 'admin' || role === 'auditor'
  // Community no tiene inquilinos: el administrador de la instalación hace lo que en Pro hace el staff.
  const staff = role === 'admin'
  return { editar: edita, importar: edita, aceptarRiesgo: conduce, borrar: conduce, administrar: conduce, staff }
}

export function useFecha() {
  const { i18n } = useTranslation()
  const loc = i18n.language?.startsWith('en') ? 'en-US' : 'es-AR'
  return {
    loc,
    fecha: (s: string | null | undefined) => (s ? new Date(s).toLocaleDateString(loc, { day: '2-digit', month: '2-digit', year: 'numeric' }) : '-'),
    /** Un día de calendario "YYYY-MM-DD" (plazos, fechas de CISA): se arma local, no se corre por la zona. */
    dia: (s: string | null | undefined) => {
      const d = diaLocal(s)
      return d ? d.toLocaleDateString(loc, { day: '2-digit', month: '2-digit', year: 'numeric' }) : '-'
    },
    fechaHora: (s: string | null | undefined) => (s ? new Date(s).toLocaleString(loc, { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '-'),
    /** "hace 12 días": desde cuándo está la vulnerabilidad. */
    antiguedad: (s: string | null | undefined) => {
      if (!s) return '-'
      const dias = Math.max(0, Math.floor((Date.now() - new Date(s).getTime()) / 86400000))
      return new Intl.RelativeTimeFormat(loc, { numeric: 'auto' }).format(-dias, 'day')
    },
  }
}

/** "YYYY-MM-DD" como fecha local (new Date("YYYY-MM-DD") la toma en UTC y en Argentina da el día anterior). */
export function diaLocal(s: string | null | undefined): Date | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(s || '')
  return m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : null
}

/** Días que faltan hasta un día límite (negativo si ya pasó). */
export function diasHasta(s: string | null | undefined): number | null {
  const d = diaLocal(s)
  if (!d) return null
  const h = new Date()
  const hoy = new Date(h.getFullYear(), h.getMonth(), h.getDate())
  return Math.round((d.getTime() - hoy.getTime()) / 86400000)
}

/** EPSS como porcentaje con un decimal y el percentil como "p97". */
export function formatoEpss(epss: number | string | null | undefined, percentil: number | string | null | undefined, loc: string) {
  if (epss == null || epss === '') return null
  const e = Number(epss)
  const pct = (e * 100).toLocaleString(loc, { maximumFractionDigits: e < 0.01 ? 2 : 1 })
  const p = percentil == null || percentil === '' ? null : Math.floor(Number(percentil) * 100)
  return { pct: `${pct} %`, percentil: p }
}

export function nombreFuente(f: string | null | undefined, t: (k: string) => string) {
  return f ? t(`vulns.fuente.${f}`) : '-'
}

interface Cliente { id: string; name: string }

export function useClientes() {
  return useQuery<Cliente[]>({ queryKey: ['clientes-lista'], queryFn: () => apiFetch<Cliente[]>('/clientes'), staleTime: 60_000 })
}

const CLAVE_CLIENTE = 'gungnir_cliente_seguimiento'

/** Cliente recordado en este navegador (comodidad: si no se puede leer, se elige de nuevo). */
export function clienteRecordado(): string {
  try { return localStorage.getItem(CLAVE_CLIENTE) || '' } catch { return '' }
}
export function recordarCliente(id: string) {
  try { localStorage.setItem(CLAVE_CLIENTE, id) } catch { /* sin almacenamiento: no pasa nada */ }
}

/** Los estados que cuentan como abiertos (los únicos que el cierre automático toca). */
export const ESTADOS_ABIERTOS: Estado[] = ['abierto', 'en_remediacion', 'reabierto']
