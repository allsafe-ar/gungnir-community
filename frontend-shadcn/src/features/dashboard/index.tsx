import { Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import {
  ClipboardList, Building2, ShieldAlert, AlertTriangle,
  Crosshair, Activity, Terminal,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { apiFetch } from '@/lib/api'

// ─── Tipos ────────────────────────────────────────────────────────────────────
interface DashboardStats {
  total_engagements: number
  active_engagements: number
  total_clients: number
  total_findings: number
  critical_open: number
  high_open: number
  severity_breakdown: { severity: string; count: number }[]
  findings_by_status: { status: string; count: number }[]
  engagements_by_status: { status: string; count: number }[]
  recent_logs: { logged_at: string; tool: string; target: string; command: string; engagement_title: string }[]
  recent_engagements: {
    id: string
    title: string
    client_name: string
    status: string
    type: string
    current_phase: string
    updated_at: string
  }[]
}

// ─── Constantes ───────────────────────────────────────────────────────────────
const STATUS_LABEL: Record<string, string> = {
  planned: 'Planificado', in_progress: 'En curso', reporting: 'Reportando',
  qa: 'QA', delivered: 'Entregado', archived: 'Archivado',
}
const STATUS_VARIANT: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  planned: 'outline', in_progress: 'default', reporting: 'secondary',
  qa: 'secondary', delivered: 'outline', archived: 'outline',
}
const PHASE_LABEL: Record<string, string> = {
  planning: 'Planificación', recon: 'Reconocimiento', scanning: 'Escaneo',
  exploitation: 'Explotación', post_exploitation: 'Post-Explotación', reporting: 'Reporting',
}

// Severity colors (bar chart)
const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#ca8a04',
  low:      '#2563eb',
  info:     '#64748b',
}

// Engagement status colors (pie)
const STATUS_COLORS: string[] = ['#dc2626', '#ea580c', '#ca8a04', '#2563eb', '#16a34a', '#64748b']

const SEV_LABEL: Record<string, string> = {
  critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo', info: 'Info',
}
const FIND_STATUS_LABEL: Record<string, string> = {
  open: 'Abierto', in_progress: 'En progreso', closed: 'Cerrado', remediated: 'Remediado',
}

// ─── Custom Tooltip ───────────────────────────────────────────────────────────
function SevTooltip({ active, payload }: { active?: boolean; payload?: { payload: { severity: string; count: number } }[] }) {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  return (
    <div className='rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs shadow'>
      <p className='font-semibold' style={{ color: SEV_COLORS[d.severity] }}>
        {SEV_LABEL[d.severity] ?? d.severity}
      </p>
      <p className='text-zinc-400'>{d.count} hallazgo{d.count !== 1 ? 's' : ''} abiertos</p>
    </div>
  )
}

// ─── Componente principal ─────────────────────────────────────────────────────
export function Dashboard() {
  const { data: stats, isLoading } = useQuery<DashboardStats>({
    queryKey: ['gungnir-dashboard'],
    queryFn: () => apiFetch<DashboardStats>('/dashboard'),
    staleTime: 60_000,   // 1 min cached — no recarga en cada navegación
    retry: 1,
  })

  if (isLoading) {
    return (
      <div className='flex h-64 items-center justify-center'>
        <div className='h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent' />
      </div>
    )
  }

  // Prepare chart data
  const sevData = (stats?.severity_breakdown ?? []).map(d => ({
    severity: d.severity,
    count: Number(d.count),
    label: SEV_LABEL[d.severity] ?? d.severity,
  }))

  const engStatusData = (stats?.engagements_by_status ?? []).map(d => ({
    name: STATUS_LABEL[d.status] ?? d.status,
    value: Number(d.count),
  }))

  const findStatusData = (stats?.findings_by_status ?? []).map(d => ({
    name: FIND_STATUS_LABEL[d.status] ?? d.status,
    value: Number(d.count),
  }))

  const hasChartData = sevData.length > 0 || engStatusData.length > 0

  return (
    <div className='space-y-6'>
      {/* Header */}
      <div>
        <h1 className='text-2xl font-bold tracking-tight'>Panel de Control</h1>
        <p className='text-sm text-muted-foreground'>Vista general de operaciones de pentesting</p>
      </div>

      {/* KPI Cards */}
      <div className='grid gap-4 md:grid-cols-2 lg:grid-cols-4'>
        <Card>
          <CardHeader className='flex flex-row items-center justify-between space-y-0 pb-2'>
            <CardTitle className='text-sm font-medium'>Engagements activos</CardTitle>
            <ClipboardList className='size-4 text-muted-foreground' />
          </CardHeader>
          <CardContent>
            <div className='text-3xl font-bold'>{stats?.active_engagements ?? 0}</div>
            <p className='text-xs text-muted-foreground'>de {stats?.total_engagements ?? 0} totales</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className='flex flex-row items-center justify-between space-y-0 pb-2'>
            <CardTitle className='text-sm font-medium'>Clientes</CardTitle>
            <Building2 className='size-4 text-muted-foreground' />
          </CardHeader>
          <CardContent>
            <div className='text-3xl font-bold'>{stats?.total_clients ?? 0}</div>
            <p className='text-xs text-muted-foreground'>registrados</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className='flex flex-row items-center justify-between space-y-0 pb-2'>
            <CardTitle className='text-sm font-medium'>Críticos abiertos</CardTitle>
            <ShieldAlert className='size-4 text-destructive' />
          </CardHeader>
          <CardContent>
            <div className='text-3xl font-bold text-destructive'>{stats?.critical_open ?? 0}</div>
            <p className='text-xs text-muted-foreground'>sin remediar</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className='flex flex-row items-center justify-between space-y-0 pb-2'>
            <CardTitle className='text-sm font-medium'>Altos abiertos</CardTitle>
            <AlertTriangle className='size-4 text-orange-500' />
          </CardHeader>
          <CardContent>
            <div className='text-3xl font-bold text-orange-500'>{stats?.high_open ?? 0}</div>
            <p className='text-xs text-muted-foreground'>sin remediar</p>
          </CardContent>
        </Card>
      </div>

      {/* Charts row */}
      {hasChartData && (
        <div className='grid gap-4 md:grid-cols-2'>
          {/* Bar: hallazgos por severidad (abiertos) */}
          {sevData.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className='text-sm font-medium'>Hallazgos abiertos por severidad</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width='100%' height={180}>
                  <BarChart data={sevData} barCategoryGap='35%'>
                    <XAxis
                      dataKey='label'
                      tick={{ fontSize: 11, fill: '#94a3b8' }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      allowDecimals={false}
                      tick={{ fontSize: 11, fill: '#94a3b8' }}
                      axisLine={false}
                      tickLine={false}
                      width={24}
                    />
                    <Tooltip content={<SevTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                    <Bar dataKey='count' radius={[4, 4, 0, 0]}>
                      {sevData.map((d) => (
                        <Cell key={d.severity} fill={SEV_COLORS[d.severity] ?? '#64748b'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}

          {/* Bar: estado de engagements */}
          {engStatusData.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className='text-sm font-medium'>Engagements por estado</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width='100%' height={180}>
                  <BarChart data={engStatusData} barCategoryGap='35%'>
                    <XAxis
                      dataKey='name'
                      tick={{ fontSize: 10, fill: '#94a3b8' }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      allowDecimals={false}
                      tick={{ fontSize: 10, fill: '#94a3b8' }}
                      axisLine={false}
                      tickLine={false}
                      width={20}
                    />
                    <Tooltip
                      formatter={(v: number) => [v, 'Engagements']}
                      contentStyle={{ background: '#18181b', border: '1px solid #3f3f46', borderRadius: 6, fontSize: 11 }}
                      labelStyle={{ color: '#e4e4e7' }}
                      cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                    />
                    <Bar dataKey='value' radius={[4, 4, 0, 0]}>
                      {engStatusData.map((_, i) => (
                        <Cell key={i} fill={STATUS_COLORS[i % STATUS_COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}

          {/* Findings by status as small pill row */}
          {findStatusData.length > 0 && (
            <Card className='col-span-full'>
              <CardHeader>
                <CardTitle className='text-sm font-medium'>Estado de hallazgos</CardTitle>
              </CardHeader>
              <CardContent>
                <div className='flex flex-wrap gap-4'>
                  {findStatusData.map((d, i) => (
                    <div key={d.name} className='flex items-center gap-2'>
                      <div className='h-2.5 w-2.5 rounded-full' style={{ background: STATUS_COLORS[i % STATUS_COLORS.length] }} />
                      <span className='text-xs text-muted-foreground'>{d.name}</span>
                      <span className='text-sm font-bold'>{d.value}</span>
                    </div>
                  ))}
                  <div className='ml-auto flex items-center gap-2'>
                    <span className='text-xs text-muted-foreground'>Total</span>
                    <span className='text-sm font-bold'>{stats?.total_findings ?? 0}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      <div className='grid gap-4 lg:grid-cols-5'>
        {/* Recent engagements */}
        <Card className='lg:col-span-3'>
          <CardHeader>
            <CardTitle className='text-sm font-medium'>Engagements recientes</CardTitle>
          </CardHeader>
          <CardContent>
            {!stats?.recent_engagements?.length ? (
              <div className='flex flex-col items-center gap-3 py-8 text-center'>
                <Crosshair className='size-10 text-muted-foreground/40' />
                <p className='text-sm text-muted-foreground'>
                  No hay engagements aún.{' '}
                  <Link to='/engagements/nuevo' className='text-primary underline-offset-4 hover:underline'>
                    Crear el primero
                  </Link>
                </p>
              </div>
            ) : (
              <div className='space-y-2'>
                {stats.recent_engagements.map((eng) => (
                  <Link
                    key={eng.id}
                    to='/engagements/$engagementId'
                    params={{ engagementId: eng.id }}
                    className='flex items-center justify-between rounded-lg border border-border px-4 py-3 hover:bg-accent transition-colors'
                  >
                    <div className='min-w-0 flex-1'>
                      <p className='truncate font-medium text-sm'>{eng.title}</p>
                      <p className='truncate text-xs text-muted-foreground'>{eng.client_name}</p>
                    </div>
                    <div className='ml-4 flex items-center gap-2 shrink-0'>
                      {eng.current_phase && (
                        <span className='text-xs text-muted-foreground hidden sm:block'>
                          {PHASE_LABEL[eng.current_phase] ?? eng.current_phase}
                        </span>
                      )}
                      <Badge variant={STATUS_VARIANT[eng.status] ?? 'outline'}>
                        {STATUS_LABEL[eng.status] ?? eng.status}
                      </Badge>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Recent activity log */}
        <Card className='lg:col-span-2'>
          <CardHeader>
            <CardTitle className='text-sm font-medium flex items-center gap-2'>
              <Activity className='size-3.5' />
              Actividad reciente
            </CardTitle>
          </CardHeader>
          <CardContent>
            {!stats?.recent_logs?.length ? (
              <div className='flex flex-col items-center gap-2 py-8 text-center'>
                <Terminal className='size-8 text-muted-foreground/30' />
                <p className='text-xs text-muted-foreground'>Sin actividad registrada aún</p>
              </div>
            ) : (
              <div className='space-y-3'>
                {stats.recent_logs.map((log, i) => (
                  <div key={i} className='flex gap-3 text-xs'>
                    <div className='mt-0.5 shrink-0'>
                      <div className='h-2 w-2 rounded-full bg-primary/60 mt-1' />
                    </div>
                    <div className='min-w-0'>
                      <div className='flex items-center gap-1.5 flex-wrap'>
                        {log.tool && (
                          <span className='rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]'>{log.tool}</span>
                        )}
                        {log.target && (
                          <span className='text-muted-foreground font-mono text-[10px] truncate max-w-[120px]'>{log.target}</span>
                        )}
                      </div>
                      {log.command && (
                        <p className='mt-0.5 font-mono text-[10px] text-muted-foreground/70 truncate'>{log.command}</p>
                      )}
                      <p className='mt-0.5 text-[10px] text-muted-foreground/50'>
                        {log.engagement_title} · {new Date(log.logged_at).toLocaleDateString('es-AR')}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
