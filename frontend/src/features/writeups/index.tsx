/**
 * Writeups — Generador de writeups para plataformas de práctica
 * HackTheBox · TryHackMe · OSCP Lab · Bug Bounty
 * Generador de writeups para plataformas de práctica.
 */

import { useState } from 'react'
import {
  Download, Loader2, Shield, Sword, Bug, Flag, ChevronRight,
  User, Calendar, Globe, Server, Hash, AlertTriangle, Crosshair,
  RotateCcw,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { cn } from '@/lib/utils'
import { generateWriteup, type WriteupPlatform, type WriteupData } from '@/lib/writeup-pdf'

// ─── Plataformas ───────────────────────────────────────────────────────────────
const PLATFORMS: {
  id: WriteupPlatform
  label: string
  sub: string
  color: string
  bg: string
  border: string
  textColor: string
  icon: React.ReactNode
}[] = [
  {
    id: 'htb',
    label: 'HackTheBox',
    sub: 'Máquinas CTF · Flags',
    color: '#9fef00',
    bg: 'bg-[#0f141e]',
    border: 'border-[#9fef00]/40',
    textColor: 'text-[#9fef00]',
    icon: <Flag className='h-5 w-5' />,
  },
  {
    id: 'thm',
    label: 'TryHackMe',
    sub: 'Rooms · Guided paths',
    color: '#d4068c',
    bg: 'bg-[#14143c]',
    border: 'border-[#d4068c]/40',
    textColor: 'text-[#d4068c]',
    icon: <Shield className='h-5 w-5' />,
  },
  {
    id: 'oscp',
    label: 'OSCP Lab',
    sub: 'OffSec · Proof hashes',
    color: '#c1292e',
    bg: 'bg-[#1a0505]',
    border: 'border-[#c1292e]/40',
    textColor: 'text-[#c1292e]',
    icon: <Sword className='h-5 w-5' />,
  },
  {
    id: 'bugbounty',
    label: 'Bug Bounty',
    sub: 'VDP · BBP · Disclosure',
    color: '#2563eb',
    bg: 'bg-[#05152a]',
    border: 'border-[#2563eb]/40',
    textColor: 'text-[#2563eb]',
    icon: <Bug className='h-5 w-5' />,
  },
]

const SEV_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']
const DIFFICULTY_OPTIONS = ['Easy', 'Medium', 'Hard', 'Insane']
const OS_OPTIONS = ['Linux', 'Windows', 'FreeBSD', 'Other']

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-zinc-500',
}

// ─── Sub-componentes ──────────────────────────────────────────────────────────
function FieldGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className='space-y-3'>
      <h3 className='text-[10px] font-semibold uppercase tracking-widest text-zinc-600 border-b border-zinc-800/60 pb-1'>
        {title}
      </h3>
      {children}
    </div>
  )
}

function FormField({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className='space-y-1.5'>
      <Label className='text-xs text-zinc-400'>
        {label}
        {hint && <span className='ml-2 text-zinc-600 font-normal'>{hint}</span>}
      </Label>
      {children}
    </div>
  )
}

function PillSelect({
  options, value, onChange, colorMap,
}: {
  options: string[]
  value: string
  onChange: (v: string) => void
  colorMap?: Record<string, string>
}) {
  return (
    <div className='flex flex-wrap gap-1.5'>
      {options.map(opt => (
        <button
          key={opt}
          type='button'
          onClick={() => onChange(value === opt ? '' : opt)}
          className={cn(
            'rounded px-2.5 py-0.5 text-xs font-medium border transition-all',
            value === opt
              ? 'border-zinc-500 bg-zinc-700 text-zinc-100'
              : 'border-zinc-800 text-zinc-500 hover:border-zinc-700 hover:text-zinc-400'
          )}
        >
          {colorMap?.[opt] && (
            <span className={cn('inline-block h-1.5 w-1.5 rounded-full mr-1.5', colorMap[opt])} />
          )}
          {opt}
        </button>
      ))}
    </div>
  )
}

const INPUT_CLS = 'bg-zinc-900/60 border-zinc-800 text-zinc-200 placeholder:text-zinc-700 text-xs h-8 focus:border-zinc-600'
const TA_CLS = 'bg-zinc-900/60 border-zinc-800 text-zinc-200 placeholder:text-zinc-600 text-xs focus:border-zinc-600 resize-y min-h-[80px]'

// ─── Valores por defecto ──────────────────────────────────────────────────────
const EMPTY_DATA: Omit<WriteupData, 'platform'> = {
  title: '',
  author: '',
  date: new Date().toLocaleDateString('es-AR'),
  difficulty: '',
  os: '',
  ip: '',
  machine_name: '',
  user_flag: '',
  root_flag: '',
  points: '',
  hostname: '',
  local_proof: '',
  proof: '',
  program: '',
  severity: '',
  cvss: '',
  bounty: '',
  affected_url: '',
  summary: '',
  enumeration: '',
  foothold: '',
  privilege_escalation: '',
  post_exploitation: '',
  flags: '',
  description: '',
  steps_to_reproduce: '',
  impact: '',
  remediation: '',
  service_enum: '',
  exploitation: '',
  screenshots: '',
  tools_used: '',
  lessons_learned: '',
}

// ─── Componente principal ─────────────────────────────────────────────────────
export function Writeups() {
  const [platform, setPlatform] = useState<WriteupPlatform>('htb')
  const [data, setData] = useState<Omit<WriteupData, 'platform'>>(EMPTY_DATA)
  const [generating, setGenerating] = useState(false)

  const P = PLATFORMS.find(p => p.id === platform)!

  function set(field: keyof typeof data) {
    return (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
      setData(prev => ({ ...prev, [field]: e.target.value }))
  }
  function setVal(field: keyof typeof data, val: string) {
    setData(prev => ({ ...prev, [field]: val }))
  }

  function reset() {
    setData({ ...EMPTY_DATA, date: new Date().toLocaleDateString('es-AR') })
  }

  async function handleGenerate() {
    setGenerating(true)
    try {
      await generateWriteup({ ...data, platform })
    } catch (e) {
      console.error('Error generando writeup:', e)
    } finally {
      setGenerating(false)
    }
  }

  const canGenerate = !!(data.machine_name || data.title || data.program)

  return (
    <div className='flex h-[calc(100vh-4rem)] -m-6 overflow-hidden'>

      {/* ── Left: platform selector + metadata ─────────────────────────────── */}
      <div className='w-80 shrink-0 flex flex-col border-r border-zinc-800 overflow-hidden'>
        {/* Header */}
        <div className='border-b border-zinc-800 p-4'>
          <div className='flex items-center gap-2 mb-1'>
            <Crosshair className='h-4 w-4 text-red-500' />
            <h1 className='font-semibold text-sm text-zinc-200'>Writeup Generator</h1>
          </div>
          <p className='text-[11px] text-zinc-500'>
            Writeups para plataformas de práctica
          </p>
        </div>

        {/* Platform grid */}
        <div className='p-3 border-b border-zinc-800 grid grid-cols-2 gap-2'>
          {PLATFORMS.map(pl => (
            <button
              key={pl.id}
              onClick={() => setPlatform(pl.id)}
              className={cn(
                'text-left rounded-lg border p-3 transition-all',
                platform === pl.id
                  ? `${pl.bg} ${pl.border}`
                  : 'border-zinc-800 hover:border-zinc-700 bg-zinc-900/30'
              )}
            >
              <div className={cn('mb-1', platform === pl.id ? pl.textColor : 'text-zinc-600')}>
                {pl.icon}
              </div>
              <p className={cn('text-xs font-semibold leading-tight', platform === pl.id ? pl.textColor : 'text-zinc-400')}>
                {pl.label}
              </p>
              <p className='text-[10px] text-zinc-600 mt-0.5'>{pl.sub}</p>
            </button>
          ))}
        </div>

        {/* Metadata fields — scroll */}
        <div className='flex-1 overflow-y-auto p-3 space-y-4'>
          <FieldGroup title='Identificación'>
            <FormField label='Autor'>
              <Input
                className={INPUT_CLS}
                placeholder='Tu nombre o handle'
                value={data.author}
                onChange={set('author')}
              />
            </FormField>
            <FormField label='Fecha'>
              <Input
                className={INPUT_CLS}
                placeholder={new Date().toLocaleDateString('es-AR')}
                value={data.date}
                onChange={set('date')}
              />
            </FormField>
          </FieldGroup>

          {/* HTB / TryHackMe */}
          {(platform === 'htb' || platform === 'thm') && (
            <FieldGroup title='Máquina'>
              <FormField label='Nombre'>
                <Input className={INPUT_CLS} placeholder='Lame' value={data.machine_name} onChange={set('machine_name')} />
              </FormField>
              <FormField label='IP objetivo'>
                <div className='relative'>
                  <Globe className='absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-zinc-600' />
                  <Input className={cn(INPUT_CLS, 'pl-7')} placeholder='10.10.11.xxx' value={data.ip} onChange={set('ip')} />
                </div>
              </FormField>
              <FormField label='Sistema operativo'>
                <PillSelect options={OS_OPTIONS} value={data.os || ''} onChange={v => setVal('os', v)} />
              </FormField>
              <FormField label='Dificultad'>
                <PillSelect options={DIFFICULTY_OPTIONS} value={data.difficulty || ''} onChange={v => setVal('difficulty', v)} />
              </FormField>
              <FormField label='Puntos' hint='(opcional)'>
                <Input className={INPUT_CLS} placeholder='20' value={data.points} onChange={set('points')} />
              </FormField>
            </FieldGroup>
          )}

          {/* OSCP */}
          {platform === 'oscp' && (
            <FieldGroup title='Target'>
              <FormField label='Hostname'>
                <div className='relative'>
                  <Server className='absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-zinc-600' />
                  <Input className={cn(INPUT_CLS, 'pl-7')} placeholder='CONFLUENCE01' value={data.hostname} onChange={set('hostname')} />
                </div>
              </FormField>
              <FormField label='IP'>
                <Input className={INPUT_CLS} placeholder='192.168.x.x' value={data.ip} onChange={set('ip')} />
              </FormField>
              <FormField label='Sistema operativo'>
                <PillSelect options={OS_OPTIONS} value={data.os || ''} onChange={v => setVal('os', v)} />
              </FormField>
              <FormField label='Dificultad'>
                <PillSelect options={DIFFICULTY_OPTIONS} value={data.difficulty || ''} onChange={v => setVal('difficulty', v)} />
              </FormField>
            </FieldGroup>
          )}

          {/* Bug Bounty */}
          {platform === 'bugbounty' && (
            <FieldGroup title='Reporte'>
              <FormField label='Título'>
                <Input className={INPUT_CLS} placeholder='Reflected XSS en /search' value={data.title} onChange={set('title')} />
              </FormField>
              <FormField label='Programa'>
                <Input className={INPUT_CLS} placeholder='HackerOne — Empresa XYZ' value={data.program} onChange={set('program')} />
              </FormField>
              <FormField label='Severidad'>
                <PillSelect
                  options={SEV_OPTIONS}
                  value={data.severity || ''}
                  onChange={v => setVal('severity', v)}
                  colorMap={SEV_DOT}
                />
              </FormField>
              <FormField label='CVSS score' hint='(ej: 8.1)'>
                <Input className={INPUT_CLS} placeholder='8.1' value={data.cvss} onChange={set('cvss')} />
              </FormField>
              <FormField label='Bounty recibido' hint='(opcional)'>
                <Input className={INPUT_CLS} placeholder='$500' value={data.bounty} onChange={set('bounty')} />
              </FormField>
              <FormField label='URL afectada'>
                <Input className={INPUT_CLS} placeholder='https://target.com/search?q=...' value={data.affected_url} onChange={set('affected_url')} />
              </FormField>
            </FieldGroup>
          )}

          {/* Flags / Proofs */}
          {(platform === 'htb' || platform === 'thm') && (
            <FieldGroup title='Flags'>
              <FormField label='User flag'>
                <div className='relative'>
                  <Hash className='absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-zinc-600' />
                  <Input className={cn(INPUT_CLS, 'pl-7 font-mono')} placeholder='3f4b...' value={data.user_flag} onChange={set('user_flag')} />
                </div>
              </FormField>
              <FormField label='Root flag'>
                <div className='relative'>
                  <Hash className='absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-zinc-600' />
                  <Input className={cn(INPUT_CLS, 'pl-7 font-mono')} placeholder='8a2c...' value={data.root_flag} onChange={set('root_flag')} />
                </div>
              </FormField>
            </FieldGroup>
          )}
          {platform === 'oscp' && (
            <FieldGroup title='Proof hashes'>
              <FormField label='local.txt'>
                <Input className={cn(INPUT_CLS, 'font-mono')} placeholder='hash MD5 local.txt' value={data.local_proof} onChange={set('local_proof')} />
              </FormField>
              <FormField label='proof.txt'>
                <Input className={cn(INPUT_CLS, 'font-mono')} placeholder='hash MD5 proof.txt' value={data.proof} onChange={set('proof')} />
              </FormField>
            </FieldGroup>
          )}

          {/* Tools used */}
          <FieldGroup title='Misc'>
            <FormField label='Herramientas utilizadas'>
              <Input
                className={INPUT_CLS}
                placeholder='nmap, gobuster, sqlmap, ...'
                value={data.tools_used}
                onChange={set('tools_used')}
              />
            </FormField>
          </FieldGroup>
        </div>

        {/* Action buttons */}
        <div className='border-t border-zinc-800 p-3 space-y-2'>
          <Button
            onClick={handleGenerate}
            disabled={!canGenerate || generating}
            className={cn(
              'w-full gap-2 font-semibold',
              canGenerate
                ? 'bg-red-700 hover:bg-red-600 text-white'
                : 'opacity-40'
            )}
          >
            {generating ? (
              <><Loader2 className='h-4 w-4 animate-spin' /> Generando PDF...</>
            ) : (
              <><Download className='h-4 w-4' /> Exportar Writeup PDF</>
            )}
          </Button>
          <Button
            variant='ghost'
            size='sm'
            onClick={reset}
            className='w-full gap-1.5 text-zinc-600 hover:text-zinc-400 text-xs h-7'
          >
            <RotateCcw className='h-3 w-3' /> Limpiar todo
          </Button>
        </div>
      </div>

      {/* ── Right: content sections ─────────────────────────────────────────── */}
      <div className='flex-1 overflow-y-auto'>
        <div className='p-6 max-w-2xl mx-auto space-y-6'>

          {/* Platform banner */}
          <div className={cn('rounded-xl border p-4', P.bg, P.border)}>
            <div className='flex items-center gap-3'>
              <div className={cn('rounded-lg p-2', P.textColor)}
                style={{ background: P.color + '20' }}>
                {P.icon}
              </div>
              <div>
                <p className={cn('font-bold text-sm', P.textColor)}>{P.label}</p>
                <p className='text-xs text-zinc-500'>
                  {platform === 'htb' && 'Resumen · Enumeración · Foothold · Escalada · Flags'}
                  {platform === 'thm' && 'Resumen · Enumeración · Foothold · Escalada · Flags'}
                  {platform === 'oscp' && 'Resumen lab · Enum servicios · Explotación · Escalada · Proof hashes'}
                  {platform === 'bugbounty' && 'Descripción · Steps to reproduce · Impacto · Remediación'}
                </p>
              </div>
              <ChevronRight className={cn('ml-auto h-4 w-4', P.textColor)} />
            </div>
          </div>

          {/* HTB / TryHackMe sections */}
          {(platform === 'htb' || platform === 'thm') && (
            <>
              <SectionCard title='Resumen' hint='Breve overview de la máquina y el approach usado'>
                <Textarea
                  className={TA_CLS}
                  placeholder='Descripción general de la máquina, tipo de vulnerabilidades encontradas y técnicas utilizadas para comprometer el sistema...'
                  value={data.summary}
                  onChange={set('summary')}
                  rows={4}
                />
              </SectionCard>

              <SectionCard title='Enumeración' hint='Descubrimiento de puertos, servicios y versiones'>
                <Textarea
                  className={TA_CLS}
                  placeholder={`nmap -sC -sV -oA nmap/initial 10.10.11.xxx\n\nPorts open:\n- 22/tcp SSH OpenSSH 8.4\n- 80/tcp HTTP Apache 2.4.51\n\nWeb enumeration...\ngobuster dir -u http://10.10.11.xxx -w /usr/share/wordlists/dirb/common.txt`}
                  value={data.enumeration}
                  onChange={set('enumeration')}
                  rows={8}
                />
              </SectionCard>

              <SectionCard title='Foothold / Acceso inicial' hint='Cómo se obtuvo el acceso al sistema'>
                <Textarea
                  className={TA_CLS}
                  placeholder='Vulnerabilidad explotada, exploit usado, reverse shell obtenida...'
                  value={data.foothold}
                  onChange={set('foothold')}
                  rows={6}
                />
              </SectionCard>

              <SectionCard title='Escalada de privilegios' hint='De usuario a root/SYSTEM'>
                <Textarea
                  className={TA_CLS}
                  placeholder='Técnica de privesc: SUID, sudo misconfig, kernel exploit, token impersonation...'
                  value={data.privilege_escalation}
                  onChange={set('privilege_escalation')}
                  rows={6}
                />
              </SectionCard>

              <SectionCard title='Post-explotación' hint='(opcional) Pivoting, loot, persistence'>
                <Textarea
                  className={TA_CLS}
                  placeholder='Dump de credenciales, loot de archivos interesantes, movimiento lateral...'
                  value={data.post_exploitation}
                  onChange={set('post_exploitation')}
                  rows={4}
                />
              </SectionCard>
            </>
          )}

          {/* OSCP sections */}
          {platform === 'oscp' && (
            <>
              <SectionCard title='Resumen del laboratorio' hint='Overview del objetivo y approach'>
                <Textarea
                  className={TA_CLS}
                  placeholder='Descripción del objetivo, superficie de ataque inicial y estrategia de compromiso...'
                  value={data.summary}
                  onChange={set('summary')}
                  rows={4}
                />
              </SectionCard>

              <SectionCard title='Enumeración de servicios' hint='Puertos, servicios, versiones'>
                <Textarea
                  className={TA_CLS}
                  placeholder={`sudo nmap -sC -sV -p- --min-rate 5000 192.168.x.x\n\nOpen ports:\n21/tcp  FTP  vsftpd 3.0.3\n22/tcp  SSH  OpenSSH 7.9\n80/tcp  HTTP nginx 1.14.2\n\nService fingerprinting...\nWeb directory enumeration...`}
                  value={data.service_enum || data.enumeration}
                  onChange={set('service_enum')}
                  rows={8}
                />
              </SectionCard>

              <SectionCard title='Explotación' hint='Vector de ataque y acceso inicial'>
                <Textarea
                  className={TA_CLS}
                  placeholder='CVE utilizado, exploit, payload, acceso inicial obtenido...'
                  value={data.exploitation || data.foothold}
                  onChange={set('exploitation')}
                  rows={6}
                />
              </SectionCard>

              <SectionCard title='Escalada de privilegios' hint='De acceso limitado a root/SYSTEM'>
                <Textarea
                  className={TA_CLS}
                  placeholder='Técnica de privesc, comandos ejecutados, evidencia de escalada...'
                  value={data.privilege_escalation}
                  onChange={set('privilege_escalation')}
                  rows={6}
                />
              </SectionCard>

              <SectionCard title='Post-explotación' hint='(opcional)'>
                <Textarea
                  className={TA_CLS}
                  placeholder='Movimiento lateral, persistence, loot...'
                  value={data.post_exploitation}
                  onChange={set('post_exploitation')}
                  rows={4}
                />
              </SectionCard>
            </>
          )}

          {/* Bug Bounty sections */}
          {platform === 'bugbounty' && (
            <>
              <SectionCard title='Descripción de la vulnerabilidad' hint='Qué es y dónde se encontró'>
                <Textarea
                  className={TA_CLS}
                  placeholder='Se identificó una vulnerabilidad de tipo Reflected Cross-Site Scripting (XSS) en el parámetro `q` del endpoint `/search`. La aplicación no sanitiza correctamente la entrada del usuario antes de reflejarla en la respuesta HTML...'
                  value={data.description || data.summary}
                  onChange={set('description')}
                  rows={5}
                />
              </SectionCard>

              <SectionCard title='Pasos para reproducir' hint='Steps to reproduce detallados'>
                <Textarea
                  className={TA_CLS}
                  placeholder={`1. Navegar a https://target.com/search\n2. Ingresar el siguiente payload en el campo de búsqueda:\n   <script>alert(document.domain)</script>\n3. Presionar Enter\n4. Observar la ejecución del script en el contexto de la página`}
                  value={data.steps_to_reproduce}
                  onChange={set('steps_to_reproduce')}
                  rows={7}
                />
              </SectionCard>

              <SectionCard title='Impacto' hint='Qué puede hacer un atacante con esta vulnerabilidad'>
                <Textarea
                  className={TA_CLS}
                  placeholder='Un atacante podría utilizar esta vulnerabilidad para robar cookies de sesión de usuarios autenticados, realizar phishing dentro del dominio legítimo, ejecutar acciones no autorizadas en nombre del usuario víctima...'
                  value={data.impact}
                  onChange={set('impact')}
                  rows={4}
                />
              </SectionCard>

              <SectionCard title='Recomendación de remediación' hint='Cómo corregir la vulnerabilidad'>
                <Textarea
                  className={TA_CLS}
                  placeholder='Implementar codificación de salida (output encoding) en todos los puntos donde se refleja input del usuario. Utilizar una librería como DOMPurify para sanitización en el cliente y escapar correctamente en el servidor. Aplicar Content Security Policy (CSP) como medida de defensa en profundidad...'
                  value={data.remediation}
                  onChange={set('remediation')}
                  rows={4}
                />
              </SectionCard>
            </>
          )}

          {/* Common sections */}
          <SectionCard title='Lecciones aprendidas' hint='(opcional) Takeaways, conceptos nuevos'>
            <Textarea
              className={TA_CLS}
              placeholder='Qué aprendiste de esta máquina / vulnerabilidad. Técnicas nuevas, herramientas, conceptos de seguridad...'
              value={data.lessons_learned}
              onChange={set('lessons_learned')}
              rows={4}
            />
          </SectionCard>

          {/* Generate CTA */}
          <div className='rounded-xl border border-zinc-800 bg-zinc-950 p-5'>
            <div className='flex items-center justify-between gap-4'>
              <div>
                <p className='text-sm font-medium text-zinc-200'>
                  Writeup PDF — {P.label}
                </p>
                <p className='text-xs text-zinc-500 mt-0.5'>
                  Portada · Info card · Secciones de contenido · Pie de página
                </p>
                {!canGenerate && (
                  <p className='mt-1.5 flex items-center gap-1.5 text-xs text-yellow-500'>
                    <AlertTriangle className='h-3.5 w-3.5' />
                    {platform === 'bugbounty'
                      ? 'Completá el campo Título o Programa para continuar'
                      : 'Completá el nombre de la máquina para continuar'}
                  </p>
                )}
              </div>
              <Button
                onClick={handleGenerate}
                disabled={!canGenerate || generating}
                className={cn(
                  'shrink-0 gap-2 font-semibold',
                  canGenerate
                    ? 'bg-red-700 hover:bg-red-600 text-white'
                    : 'opacity-40'
                )}
              >
                {generating ? (
                  <><Loader2 className='h-4 w-4 animate-spin' /> Generando...</>
                ) : (
                  <><Download className='h-4 w-4' /> Exportar PDF</>
                )}
              </Button>
            </div>
          </div>

          {/* Privacy note */}
          <div className='flex items-start gap-2 rounded-lg bg-zinc-900/30 border border-zinc-800/50 p-3'>
            <Shield className='h-3.5 w-3.5 text-zinc-600 mt-0.5 shrink-0' />
            <p className='text-[11px] text-zinc-600 leading-relaxed'>
              El PDF se genera completamente en el cliente. No se envía ningún dato al servidor.
              Los writeups son para uso personal / práctica — respetá las reglas de cada plataforma respecto a publicación de soluciones.
            </p>
          </div>

          {/* Spacer */}
          <div className='h-4' />
        </div>
      </div>
    </div>
  )
}

// ─── SectionCard ──────────────────────────────────────────────────────────────
function SectionCard({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className='rounded-xl border border-zinc-800 bg-zinc-900/30 overflow-hidden'>
      <div className='border-b border-zinc-800 px-4 py-3 flex items-center gap-2'>
        <div className='h-2.5 w-0.5 rounded-full bg-red-600' />
        <h3 className='text-xs font-semibold text-zinc-300'>{title}</h3>
        {hint && <span className='text-[10px] text-zinc-600'>— {hint}</span>}
      </div>
      <div className='p-4'>
        {children}
      </div>
    </div>
  )
}
