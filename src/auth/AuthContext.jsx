import { createContext, useContext, useEffect, useState, useCallback } from 'react'

const TOKEN_KEY = 'vulnreview.token'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [token, setTokenState] = useState(() => localStorage.getItem(TOKEN_KEY))
  const [user, setUser]        = useState(null)
  const [loading, setLoading]  = useState(true)
  const [setupRequired, setSetupRequired] = useState(false)

  const setToken = useCallback(t => {
    if (t) localStorage.setItem(TOKEN_KEY, t)
    else   localStorage.removeItem(TOKEN_KEY)
    setTokenState(t)
  }, [])

  const logout = useCallback(() => {
    setToken(null)
    setUser(null)
  }, [setToken])

  // apiFetch — adds Authorization header to /api/* requests and auto-logs out on 401.
  // /pentester/* and external URLs pass through without the header.
  const apiFetch = useCallback(async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url
    const isApi = url.startsWith('/api')

    const headers = new Headers(init.headers || {})
    if (isApi && token) headers.set('Authorization', `Bearer ${token}`)
    if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')

    const res = await fetch(input, { ...init, headers })
    if (res.status === 401 && isApi) {
      logout()
    }
    return res
  }, [token, logout])

  // On mount / token change: check who we are, or whether setup is needed.
  useEffect(() => {
    let cancelled = false
    setLoading(true)

    async function bootstrap() {
      if (token) {
        try {
          const res = await fetch('/api/auth/me', { headers: { Authorization: `Bearer ${token}` } })
          if (cancelled) return
          if (res.ok) {
            setUser(await res.json())
            setSetupRequired(false)
            setLoading(false)
            return
          }
          // 401 / 404 — fall through to clear token
          setToken(null)
        } catch {
          // network error — keep token, treat as logged out for now
        }
      }
      try {
        const res = await fetch('/api/auth/setup-required')
        if (cancelled) return
        if (res.ok) {
          const { setup_required } = await res.json()
          setSetupRequired(!!setup_required)
        }
      } catch {
        // server might be down — Login screen will surface the error
      }
      setUser(null)
      setLoading(false)
    }

    bootstrap()
    return () => { cancelled = true }
  }, [token, setToken])

  const login = useCallback(async (username, password) => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
    setUser(data.user)
    setToken(data.token)
    setSetupRequired(false)
    return data
  }, [setToken])

  const register = useCallback(async (username, password) => {
    const headers = { 'Content-Type': 'application/json' }
    if (token) headers.Authorization = `Bearer ${token}`
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers,
      body: JSON.stringify({ username, password }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
    // First-run register returns a token + auto-logs in
    if (data.token) {
      setUser(data.user)
      setToken(data.token)
      setSetupRequired(false)
    }
    return data
  }, [token, setToken])

  const value = {
    token,
    user,
    loading,
    setupRequired,
    login,
    register,
    logout,
    apiFetch,
    isAuthenticated: !!user,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
