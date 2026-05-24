export const API_BASE = '/api'
const BASE = API_BASE

export async function apiFetch<T = unknown>(
  path: string,
  options: RequestInit = {}
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
  const body = needsStringify ? JSON.stringify(rawBody) : rawBody

  // Don't set Content-Type for FormData (browser sets it with boundary)
  const isFormData = rawBody instanceof FormData
  const headers: HeadersInit = {
    ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers as Record<string, string> | undefined),
  }
  const res = await fetch(`${BASE}${path}`, { ...options, body, headers })
  if (res.status === 401 && localStorage.getItem('gungnir_token')) {
    window.dispatchEvent(new CustomEvent('session-expired'))
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(body.error || `HTTP ${res.status}`)
  }
  return res.json() as Promise<T>
}
