import { useEffect, useState, useRef } from 'react'
import Dashboard from './components/Dashboard'
import Requests from './components/Requests'
import Network from './components/Network'
import Tools from './components/Tools'
import Settings from './components/Settings'
import Login from './auth/Login'
import { useAuth } from './auth/AuthContext'
import './App.css'

function ShieldIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  )
}

function SecurityIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  )
}

function GridIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" rx="1"/>
      <rect x="14" y="3" width="7" height="7" rx="1"/>
      <rect x="14" y="14" width="7" height="7" rx="1"/>
      <rect x="3" y="14" width="7" height="7" rx="1"/>
    </svg>
  )
}

function TerminalIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 17 10 11 4 5"/>
      <line x1="12" y1="19" x2="20" y2="19"/>
    </svg>
  )
}

function NetworkIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9"/>
      <path d="M3 12h18"/>
      <path d="M12 3a14 14 0 0 1 0 18"/>
      <path d="M12 3a14 14 0 0 0 0 18"/>
    </svg>
  )
}

function WrenchIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
    </svg>
  )
}

function SettingsIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
  )
}

function UsersIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
      <circle cx="9" cy="7" r="4"/>
      <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
      <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
    </svg>
  )
}

function ChevronIcon({ open }) {
  return (
    <svg
      width="10" height="10" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
      style={{ transition: 'transform 0.18s', transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}
    >
      <polyline points="6 9 12 15 18 9"/>
    </svg>
  )
}

function StatusBadge({ label, status }) {
  const isUp   = status === 'up'
  const isDown = status === 'down'
  return (
    <div className={`conn-badge ${isDown ? 'conn-badge-down' : !isUp ? 'conn-badge-checking' : ''}`}>
      <span className={`conn-dot ${isDown ? 'conn-dot-down' : !isUp ? 'conn-dot-checking' : ''}`} />
      {label}
    </div>
  )
}

function LogoutIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
      <polyline points="16 17 21 12 16 7"/>
      <line x1="21" y1="12" x2="9" y2="12"/>
    </svg>
  )
}

export default function App() {
  const { loading, isAuthenticated, isAdmin, user, logout } = useAuth()
  const [activeTab, setActiveTab] = useState('dashboard')
  const [securityOpen, setSecurityOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const toolsRef = useRef(null)
  const [apiStatus, setApiStatus] = useState('checking') // 'checking' | 'up' | 'down'
  const [dbStatus,  setDbStatus]  = useState('checking')
  const securityRef = useRef(null)
  const settingsRef = useRef(null)

  // "Scan →" buttons in the Network tab dispatch this event to jump to Requests
  // pre-filled with the chosen target.
  useEffect(() => {
    function onRequestScan() { setActiveTab('requests') }
    window.addEventListener('vulnreview:request-scan', onRequestScan)
    return () => window.removeEventListener('vulnreview:request-scan', onRequestScan)
  }, [])

  // Poll both services — drives the header badges
  useEffect(() => {
    function checkApi() {
      fetch('/pentester/health/api')
        .then(r => r.ok ? r.json() : Promise.reject())
        .then(d => setApiStatus(d.online ? 'up' : 'down'))
        .catch(() => setApiStatus('down'))
    }
    function checkDb() {
      fetch('/pentester/health/db')
        .then(r => r.ok ? r.json() : Promise.reject())
        .then(d => setDbStatus(d.online ? 'up' : 'down'))
        .catch(() => setDbStatus('down'))
    }
    checkApi(); checkDb()
    const id = setInterval(() => { checkApi(); checkDb() }, 30000)
    return () => clearInterval(id)
  }, [])

  // Close dropdowns when clicking outside
  useEffect(() => {
    function onClickOutside(e) {
      if (securityRef.current && !securityRef.current.contains(e.target)) setSecurityOpen(false)
      if (settingsRef.current && !settingsRef.current.contains(e.target)) setSettingsOpen(false)
      if (toolsRef.current    && !toolsRef.current.contains(e.target))    setSecurityOpen(false)
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [])

  if (loading) {
    return <div className="app-boot">Loading...</div>
  }

  if (!isAuthenticated) {
    return <Login />
  }

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <div className="brand-icon">
            <ShieldIcon />
          </div>
          <div>
            <div className="brand-name">VULNREVIEW</div>
            <span className="brand-sub">AI Pentest Monitor</span>
          </div>
        </div>

        <div className="header-sep" />

        <nav className="header-nav">
          <button
            className={`nav-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <GridIcon />
            Dashboard
          </button>

          <div className="nav-dropdown" ref={securityRef}>
            <button
              className={`nav-btn nav-btn-dropdown ${['requests','network','tools'].includes(activeTab) ? 'active' : ''}`}
              onClick={() => setSecurityOpen(o => !o)}
            >
              <SecurityIcon />
              Security
              <ChevronIcon open={securityOpen} />
            </button>
            {securityOpen && (
              <div className="nav-dropdown-menu">
                <button
                  className="nav-dropdown-item"
                  onClick={() => { setActiveTab('requests'); setSecurityOpen(false) }}
                >
                  <TerminalIcon />
                  Requests
                </button>
                <button
                  className="nav-dropdown-item"
                  onClick={() => { setActiveTab('network'); setSecurityOpen(false) }}
                >
                  <NetworkIcon />
                  Network Scan
                </button>
                <button
                  className="nav-dropdown-item"
                  onClick={() => { setActiveTab('tools'); setSecurityOpen(false) }}
                >
                  <WrenchIcon />
                  Tools
                </button>
              </div>
            )}
          </div>

          {isAdmin && (
            <div className="nav-dropdown" ref={settingsRef}>
              <button
                className={`nav-btn nav-btn-dropdown ${activeTab === 'settings' ? 'active' : ''}`}
                onClick={() => setSettingsOpen(o => !o)}
              >
                <SettingsIcon />
                Settings
                <ChevronIcon open={settingsOpen} />
              </button>
              {settingsOpen && (
                <div className="nav-dropdown-menu">
                  <button
                    className="nav-dropdown-item"
                    onClick={() => { setActiveTab('settings'); setSettingsOpen(false) }}
                  >
                    <UsersIcon />
                    Manage Users
                  </button>
                  <a
                    className="nav-dropdown-item"
                    href={`http://${window.location.hostname}:8000/docs`}
                    target="_blank"
                    rel="noreferrer"
                    onClick={() => setSettingsOpen(false)}
                  >
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                      <polyline points="14 2 14 8 20 8"/>
                      <line x1="16" y1="13" x2="8" y2="13"/>
                      <line x1="16" y1="17" x2="8" y2="17"/>
                    </svg>
                    Swagger Docs
                  </a>
                </div>
              )}
            </div>
          )}
        </nav>

        <div className="header-right">
          <StatusBadge label="API" status={apiStatus} />
          <StatusBadge label="DB"  status={dbStatus} />
          <div className="user-chip">
            {isAdmin && <span className="user-role-badge">admin</span>}
            <span className="user-name">{user?.username}</span>
            <button className="logout-btn" onClick={logout} title="Sign out">
              <LogoutIcon />
            </button>
          </div>
        </div>
      </header>

      <main className="main-content">
        {activeTab === 'dashboard' && <Dashboard />}
        {activeTab === 'requests'  && <Requests />}
        {activeTab === 'network'   && <Network />}
        {activeTab === 'tools'     && <Tools />}
        {activeTab === 'settings'  && isAdmin && <Settings />}
      </main>
    </div>
  )
}
