export const API_BASE = '/api'
const BASE = API_BASE

/**
 * `body` se declara aparte de RequestInit a proposito: esta funcion serializa sola
 * cualquier objeto plano (ver mas abajo), asi que los llamadores le pasan el objeto
 * y no un string. Con el RequestInit crudo el tipo exige BodyInit y todos esos
 * llamados quedan marcados como error aunque en ejecucion sean correctos.
 */
export type OpcionesApi = Omit<RequestInit, 'body'> & { body?: unknown }

export async function apiFetch<T = unknown>(
  path: string,
  options: OpcionesApi = {}
): Promise<T> {
  const token = localStorage.getItem('gungnir_token')

  // Auto-serialize body if it's a plain object (not FormData / string / BufferSource)
  const rawBody = options.body
  const needsStringify = rawBody !== undefined
    && rawBody !== null
    && typeof rawBody === 'object'
    && !(rawBody instanceof FormData)
    && !(rawBody instanceof Blob)
    && !(rawBody instanceof ArrayBuffer)
    && !ArrayBuffer.isView(rawBody)
  const body = (needsStringify ? JSON.stringify(rawBody) : rawBody) as BodyInit | null | undefined

  // Don't set Content-Type for FormData (browser sets it with boundary)
  const isFormData = rawBody instanceof FormData
  const headers: HeadersInit = {
    ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers as Record<string, string> | undefined),
  }
  // `body` se saca del spread porque en OpcionesApi es unknown: el valor que va es el
  // serializado de arriba, no el que vino.
  const { body: _sinUsar, ...resto } = options
  const res = await fetch(`${BASE}${path}`, { ...resto, body, headers })
  if (res.status === 401 && localStorage.getItem('gungnir_token')) {
    window.dispatchEvent(new CustomEvent('session-expired'))
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(body.error || `HTTP ${res.status}`)
  }
  return res.json() as Promise<T>
}
