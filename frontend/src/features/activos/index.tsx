/**
 * Inventario de activos de Gungnir: la pantalla es el componente único `components/inventario`
 * (canónico en utiles/activos/ui, el mismo de Skuld y Gjallarhorn). Acá queda solo lo propio de
 * Gungnir (igual que en Pro): el selector de cliente (los activos son de la organización que se audita), los permisos
 * por rol y, en la ficha, las vulnerabilidades del equipo.
 */
import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import i18next from 'i18next'
import { HardDrive } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { InventarioBase } from '@/components/inventario/inventario-base'
import type { Fetcher } from '@/components/inventario/tipos'
import { clienteRecordado, usePermisos } from '@/features/vulnerabilidades/comun'
import { SelectorCliente } from '@/features/vulnerabilidades/componentes'
import { VulnsDelActivo } from '@/features/vulnerabilidades/vulns-del-activo'

const fetcher: Fetcher = (path, init) => apiFetch(path, init)

/** El CSV necesita el token: se baja con fetch. */
async function descargar(path: string, nombre: string) {
  const token = localStorage.getItem('gungnir_token')
  const res = await fetch(`/api${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
  if (!res.ok) throw new Error(i18next.t('activos.errorDescarga'))
  const url = URL.createObjectURL(await res.blob())
  const a = document.createElement('a')
  a.href = url; a.download = nombre; a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function Activos() {
  const { t } = useTranslation()
  const puede = usePermisos()
  const [cliente, setClienteEstado] = useState<string>(clienteRecordado)
  const setCliente = useCallback((id: string) => setClienteEstado(id), [])
  return (
    <div className='space-y-5'>
      <div>
        <h1 className='flex items-center gap-2 text-2xl font-bold tracking-tight'><HardDrive className='size-6' />{t('activos.titulo')}</h1>
        <p className='text-muted-foreground text-sm'>{t('activos.subtitulo')}</p>
      </div>
      <InventarioBase
        fetcher={fetcher}
        descargar={descargar}
        alcance={cliente ? `cliente=${encodeURIComponent(cliente)}` : ''}
        listo={!!cliente}
        puede={{ editar: puede.editar, borrar: puede.borrar, administrar: puede.administrar }}
        sistema='Gungnir'
        sincronizacion={false}
        cabecera={<SelectorCliente valor={cliente} onCambio={setCliente} />}
        extraFicha={(a) => <VulnsDelActivo activoId={a.id} />}
        extraFichaTitulo={t('vulns.tabActivo')}
      />
    </div>
  )
}
