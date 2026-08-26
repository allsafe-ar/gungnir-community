import { type ReactNode } from 'react'

// Renderer de Markdown liviano y seguro (sin dependencias, sin dangerouslySetInnerHTML).
// Cubre lo que se usa en los hallazgos y en el reporte: encabezados, viñetas, listas
// numeradas, código en bloque e inline, negrita, itálica y links. Pensado para la
// vista previa del hallazgo (lo que después renderiza el PDF del reporte).

// Formato inline: **negrita**, *itálica*, `código`, [texto](url).
function inline(text: string, keyBase: string): ReactNode[] {
  const out: ReactNode[] = []
  const re = /(\*\*([^*]+)\*\*)|(\*([^*]+)\*)|(`([^`]+)`)|(\[([^\]]+)\]\((https?:\/\/[^\s)]+)\))/g
  let last = 0, m: RegExpExecArray | null, i = 0
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index))
    if (m[2]) out.push(<strong key={`${keyBase}-${i}`}>{m[2]}</strong>)
    else if (m[4]) out.push(<em key={`${keyBase}-${i}`}>{m[4]}</em>)
    else if (m[6]) out.push(<code key={`${keyBase}-${i}`} className='rounded bg-muted px-1 py-0.5 text-[0.85em] font-mono'>{m[6]}</code>)
    else if (m[8]) out.push(<a key={`${keyBase}-${i}`} href={m[9]} target='_blank' rel='noopener noreferrer' className='text-primary underline underline-offset-2'>{m[8]}</a>)
    last = m.index + m[0].length; i++
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

export function Markdown({ children, className = '' }: { children: string; className?: string }) {
  const lines = (children || '').replace(/\r\n/g, '\n').split('\n')
  const blocks: ReactNode[] = []
  let i = 0, key = 0

  while (i < lines.length) {
    const line = lines[i]

    // Bloque de código ```
    if (/^```/.test(line)) {
      const buf: string[] = []
      i++
      while (i < lines.length && !/^```/.test(lines[i])) { buf.push(lines[i]); i++ }
      i++ // cierre
      blocks.push(<pre key={key++} className='my-2 overflow-x-auto rounded-md bg-muted p-3 text-xs font-mono'>{buf.join('\n')}</pre>)
      continue
    }
    // Encabezados
    const h = line.match(/^(#{1,3})\s+(.+)/)
    if (h) {
      const lvl = h[1].length
      const cls = lvl === 1 ? 'text-base font-bold mt-3 mb-1' : lvl === 2 ? 'text-sm font-bold mt-3 mb-1' : 'text-xs font-bold uppercase tracking-wide text-muted-foreground mt-2 mb-1'
      blocks.push(<div key={key++} className={cls}>{inline(h[2], `h${key}`)}</div>)
      i++; continue
    }
    // Lista con viñetas
    if (/^[-*•]\s+/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^[-*•]\s+/.test(lines[i])) { items.push(lines[i].replace(/^[-*•]\s+/, '')); i++ }
      blocks.push(<ul key={key++} className='my-1 list-disc pl-5 space-y-0.5 text-sm'>{items.map((it, n) => <li key={n}>{inline(it, `ul${key}-${n}`)}</li>)}</ul>)
      continue
    }
    // Lista numerada
    if (/^\d+\.\s+/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^\d+\.\s+/.test(lines[i])) { items.push(lines[i].replace(/^\d+\.\s+/, '')); i++ }
      blocks.push(<ol key={key++} className='my-1 list-decimal pl-5 space-y-0.5 text-sm'>{items.map((it, n) => <li key={n}>{inline(it, `ol${key}-${n}`)}</li>)}</ol>)
      continue
    }
    // Línea en blanco
    if (line.trim() === '') { i++; continue }
    // Párrafo
    blocks.push(<p key={key++} className='my-1 text-sm leading-relaxed'>{inline(line, `p${key}`)}</p>)
    i++
  }

  return <div className={className}>{blocks}</div>
}

export default Markdown
