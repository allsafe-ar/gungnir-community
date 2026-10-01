/**
 * Archivos de /api/uploads con el header Authorization.
 *
 * 🔴 U-05: antes se pedían con el JWT en la URL (?token=), que queda en el historial, en los
 * registros del proxy y en todo lo que se copia o comparte. El servidor ya no lo acepta: el
 * archivo se baja con el header y se muestra desde un blob local.
 */
import { useEffect, useState } from 'react'
import { API_BASE } from '@/lib/api'

export async function blobProtegido(filename: string): Promise<Blob> {
  const token = localStorage.getItem('gungnir_token')
  const res = await fetch(`${API_BASE}/uploads/${encodeURIComponent(filename)}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.blob()
}

/** Descarga el archivo con su nombre original. */
export async function descargarProtegido(filename: string, nombre: string) {
  const url = URL.createObjectURL(await blobProtegido(filename))
  const a = document.createElement('a')
  a.href = url
  a.download = nombre
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 10000)
}

/** Abre el archivo en otra pestaña. La pestaña se abre antes del fetch para que no la bloqueen. */
export async function abrirProtegido(filename: string) {
  const ventana = window.open('', '_blank')
  try {
    const url = URL.createObjectURL(await blobProtegido(filename))
    if (ventana) ventana.location.href = url
    setTimeout(() => URL.revokeObjectURL(url), 60000)
  } catch {
    ventana?.close()
  }
}

export function ImagenProtegida({ filename, alt, className, onClick }: {
  filename: string
  alt: string
  className?: string
  onClick?: () => void
}) {
  const [src, setSrc] = useState<string | null>(null)
  useEffect(() => {
    let url: string | null = null
    let vigente = true
    blobProtegido(filename)
      .then(b => { if (vigente) { url = URL.createObjectURL(b); setSrc(url) } })
      .catch(() => {})
    return () => { vigente = false; if (url) URL.revokeObjectURL(url) }
  }, [filename])
  if (!src) return null
  return <img src={src} alt={alt} className={className} onClick={onClick} />
}
