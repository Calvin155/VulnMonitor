import { useEffect, useState } from 'react'
import Dashboard from './components/Dashboard'
import Requests from './components/Requests'
import Network from './components/Network'
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
  const { loading, isAuthenticated, user, logout } = useAuth()
  const [activeTab, setActiveTab] = useState('dashboard')

  // "Scan →" buttons in the Network tab dispatch this event to jump to Requests
  // pre-filled with the chosen target.
  useEffect(() => {
    function onRequestScan() { setActiveTab('requests') }
    window.addEventListener('vulnreview:request-scan', onRequestScan)
    return () => window.removeEventListener('vulnreview:request-scan', onRequestScan)
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
          <button
            className={`nav-btn ${activeTab === 'requests' ? 'active' : ''}`}
            onClick={() => setActiveTab('requests')}
          >
            <TerminalIcon />
            Requests
          </button>
          <button
            className={`nav-btn ${activeTab === 'network' ? 'active' : ''}`}
            onClick={() => setActiveTab('network')}
          >
            <NetworkIcon />
            My Network
          </button>
        </nav>

        <div className="header-right">
          <div className="conn-badge">
            <span className="conn-dot" />
            CONNECTED
          </div>
          <div className="user-chip">
            <span className="user-name">{user?.username}</span>
            <button className="logout-btn" onClick={logout} title="Sign out">
              <LogoutIcon />
            </button>
          </div>
        </div>
      </header>

      <main className="main-content">
        {activeTab === 'dashboard' && <Dashboard />}
        {activeTab === 'requests' && <Requests />}
        {activeTab === 'network'  && <Network />}
      </main>
    </div>
  )
}
