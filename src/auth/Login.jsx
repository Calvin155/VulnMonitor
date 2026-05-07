import { useState } from 'react'
import { useAuth } from './AuthContext'
import './Login.css'

function ShieldLogo() {
  return (
    <div className="login-brand">
      <div className="login-brand-icon">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <div>
        <div className="login-brand-name">VULNREVIEW</div>
        <div className="login-brand-sub">AI Pentest Monitor</div>
      </div>
    </div>
  )
}

export default function Login() {
  const { login, register, setupRequired } = useAuth()
  const [mode, setMode] = useState('login') // 'login' | 'signup'
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm]   = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const isFirstRun = setupRequired
  const isRegister = isFirstRun || mode === 'signup'

  function switchMode(next) {
    setMode(next)
    setError(null)
    setUsername('')
    setPassword('')
    setConfirm('')
  }

  async function onSubmit(e) {
    e.preventDefault()
    setError(null)

    if (!username.trim() || !password) {
      setError('Username and password required.')
      return
    }
    if (isRegister) {
      if (password.length < 8) {
        setError('Password must be at least 8 characters.')
        return
      }
      if (password !== confirm) {
        setError('Passwords do not match.')
        return
      }
    }

    setSubmitting(true)
    try {
      if (isRegister) await register(username.trim(), password)
      else            await login(username.trim(), password)
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="login-shell">
      <form className="login-card" onSubmit={onSubmit}>
        <ShieldLogo />

        <h1 className="login-title">
          {isFirstRun ? 'Create the first user' : isRegister ? 'Create account' : 'Sign in'}
        </h1>

        {isFirstRun && (
          <p className="login-subtitle">
            No accounts exist yet — this user will be the initial admin.
          </p>
        )}

        <label className="login-field">
          <span className="login-label">Username</span>
          <input
            className="login-input"
            type="text"
            autoComplete="username"
            autoFocus
            value={username}
            onChange={e => setUsername(e.target.value)}
          />
        </label>

        <label className="login-field">
          <span className="login-label">Password</span>
          <input
            className="login-input"
            type="password"
            autoComplete={isRegister ? 'new-password' : 'current-password'}
            value={password}
            onChange={e => setPassword(e.target.value)}
          />
        </label>

        {isRegister && (
          <label className="login-field">
            <span className="login-label">Confirm password</span>
            <input
              className="login-input"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
            />
          </label>
        )}

        {error && <div className="login-error">{error}</div>}

        <button className="login-btn" disabled={submitting} type="submit">
          {submitting
            ? (isRegister ? 'Creating account...' : 'Signing in...')
            : (isRegister ? 'Create account' : 'Sign in')}
        </button>

        {!isFirstRun && (
          <p className="login-switch">
            {mode === 'login' ? (
              <>Don&apos;t have an account?{' '}
                <button type="button" className="login-switch-btn" onClick={() => switchMode('signup')}>
                  Sign up
                </button>
              </>
            ) : (
              <>Already have an account?{' '}
                <button type="button" className="login-switch-btn" onClick={() => switchMode('login')}>
                  Sign in
                </button>
              </>
            )}
          </p>
        )}
      </form>
    </div>
  )
}
