import { create } from 'zustand'

const TOKEN_KEY = 'gungnir_token'

export interface ArpUser {
  id: string
  username: string
  email?: string | null
  full_name?: string | null
  role: 'admin' | 'lead' | 'analyst' | 'viewer'
  totp_enabled?: boolean
}

interface AuthState {
  auth: {
    user: ArpUser | null
    setUser: (user: ArpUser | null) => void
    accessToken: string
    setAccessToken: (accessToken: string) => void
    resetAccessToken: () => void
    reset: () => void
  }
}

export const useAuthStore = create<AuthState>()((set) => {
  const initToken = localStorage.getItem(TOKEN_KEY) ?? ''
  return {
    auth: {
      user: null,
      setUser: (user) =>
        set((state) => ({ ...state, auth: { ...state.auth, user } })),
      accessToken: initToken,
      setAccessToken: (accessToken) =>
        set((state) => {
          localStorage.setItem(TOKEN_KEY, accessToken)
          return { ...state, auth: { ...state.auth, accessToken } }
        }),
      resetAccessToken: () =>
        set((state) => {
          localStorage.removeItem(TOKEN_KEY)
          return { ...state, auth: { ...state.auth, accessToken: '' } }
        }),
      reset: () =>
        set((state) => {
          localStorage.removeItem(TOKEN_KEY)
          return { ...state, auth: { ...state.auth, user: null, accessToken: '' } }
        }),
    },
  }
})
