import { useState, useEffect, useCallback, useRef, Fragment } from 'react'
import { useAuth } from '../auth/AuthContext'
import './Settings.css'

/* ── Icons ─────────────────────────────────────────── */

function KeyIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="7.5" cy="15.5" r="4.5"/>
      <path d="M21 2l-9.6 9.6"/>
      <path d="M15.5 7.5l3 3L22 7l-3-3"/>
    </svg>
  )
}

function TrashIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="3 6 5 6 21 6"/>
      <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
      <path d="M10 11v6"/>
      <path d="M14 11v6"/>
      <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
    </svg>
  )
}

function XIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18"/>
      <line x1="6" y1="6" x2="18" y2="18"/>
    </svg>
  )
}

function PlusIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="5" x2="12" y2="19"/>
      <line x1="5" y1="12" x2="19" y2="12"/>
    </svg>
  )
}

function UserCircleIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
      <circle cx="12" cy="7" r="4"/>
    </svg>
  )
}

/* ── Add User Modal ────────────────────────────────── */

function AddUserModal({ onAdd, onClose }) {
  const [username, setUsername]     = useState('')
  const [password, setPassword]     = useState('')
  const [confirmPw, setConfirmPw]   = useState('')
  const [role, setRole]             = useState('user')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError]           = useState(null)
  const [showPw, setShowPw]         = useState(false)
  const usernameRef = useRef(null)

  useEffect(() => { usernameRef.current?.focus() }, [])

  useEffect(() => {
    function onKey(e) { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  async function handleSubmit(e) {
    e.preventDefault()
    setError(null)
    if (password !== confirmPw) { setError('Passwords do not match'); return }
    setSubmitting(true)
    const err = await onAdd(username.trim(), password, role)
    setSubmitting(false)
    if (err) { setError(err) } else { onClose() }
  }

  return (
    <div className="settings-modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="settings-modal">
        <div className="settings-modal-header">
          <div className="settings-modal-title-row">
            <div className="settings-modal-icon">
              <UserCircleIcon />
            </div>
            <h3 className="settings-modal-title">Create User</h3>
          </div>
          <button className="settings-modal-close" onClick={onClose} aria-label="Close">
            <XIcon />
          </button>
        </div>

        <form className="settings-modal-body" onSubmit={handleSubmit}>
          <div className="settings-modal-field">
            <label className="settings-modal-label">Username</label>
            <input
              ref={usernameRef}
              className="settings-modal-input"
              placeholder="e.g. jdoe"
              value={username}
              onChange={e => setUsername(e.target.value)}
              autoComplete="off"
              required
            />
          </div>

          <div className="settings-modal-field">
            <label className="settings-modal-label">Password</label>
            <div className="settings-pw-wrap">
              <input
                className="settings-modal-input"
                type={showPw ? 'text' : 'password'}
                placeholder="Min 8 characters"
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete="new-password"
                required
              />
              <button type="button" className="settings-pw-toggle" onClick={() => setShowPw(v => !v)}>
                {showPw ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>

          <div className="settings-modal-field">
            <label className="settings-modal-label">Confirm Password</label>
            <input
              className="settings-modal-input"
              type={showPw ? 'text' : 'password'}
              placeholder="Repeat password"
              value={confirmPw}
              onChange={e => setConfirmPw(e.target.value)}
              autoComplete="new-password"
              required
            />
          </div>

          <div className="settings-modal-field">
            <label className="settings-modal-label">Role</label>
            <div className="settings-role-toggle">
              <button
                type="button"
                className={`settings-role-btn ${role === 'user' ? 'active' : ''}`}
                onClick={() => setRole('user')}
              >
                User
              </button>
              <button
                type="button"
                className={`settings-role-btn settings-role-btn-admin ${role === 'admin' ? 'active-admin' : ''}`}
                onClick={() => setRole('admin')}
              >
                Admin
              </button>
            </div>
            <p className="settings-modal-hint">
              {role === 'admin'
                ? 'Admins can manage users, view all scans, and access API docs.'
                : 'Standard users can run scans and view findings.'}
            </p>
          </div>

          {error && <div className="settings-modal-error">{error}</div>}

          <div className="settings-modal-actions">
            <button type="submit" className="settings-modal-submit" disabled={submitting}>
              {submitting ? 'Creating…' : 'Create User'}
            </button>
            <button type="button" className="settings-modal-cancel" onClick={onClose}>
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

/* ── User Row (with inline password reset) ─────────── */

function UserRow({ u, currentUserId, onRoleChange, onDelete, onResetPassword }) {
  const [changing, setChanging]     = useState(false)
  const [deleting, setDeleting]     = useState(false)
  const [resetOpen, setResetOpen]   = useState(false)
  const [newPw, setNewPw]           = useState('')
  const [confirmPw, setConfirmPw]   = useState('')
  const [showPw, setShowPw]         = useState(false)
  const [resetting, setResetting]   = useState(false)
  const [resetError, setResetError] = useState(null)
  const [resetOk, setResetOk]       = useState(false)
  const pwRef = useRef(null)
  const isSelf = u.id === currentUserId

  useEffect(() => {
    if (resetOpen) pwRef.current?.focus()
  }, [resetOpen])

  async function handleRoleChange(e) {
    const newRole = e.target.value
    setChanging(true)
    await onRoleChange(u.id, newRole)
    setChanging(false)
  }

  async function handleDelete() {
    if (!window.confirm(`Delete user "${u.username}"?\n\nThis cannot be undone.`)) return
    setDeleting(true)
    await onDelete(u.id)
    setDeleting(false)
  }

  async function handleResetSubmit(e) {
    e.preventDefault()
    setResetError(null)
    if (newPw.length < 8) { setResetError('Password must be at least 8 characters'); return }
    if (newPw !== confirmPw) { setResetError('Passwords do not match'); return }
    setResetting(true)
    const err = await onResetPassword(u.id, newPw)
    setResetting(false)
    if (err) {
      setResetError(err)
    } else {
      setResetOk(true)
      setTimeout(() => {
        setResetOpen(false)
        setNewPw('')
        setConfirmPw('')
        setResetOk(false)
      }, 1200)
    }
  }

  function cancelReset() {
    setResetOpen(false)
    setNewPw('')
    setConfirmPw('')
    setResetError(null)
    setResetOk(false)
  }

  return (
    <Fragment>
      <tr className={`settings-row ${isSelf ? 'settings-row-self' : ''} ${resetOpen ? 'settings-row-expanded' : ''}`}>
        <td className="settings-td">
          <div className="settings-user-cell">
            <div className="settings-avatar">
              {u.username[0].toUpperCase()}
            </div>
            <div>
              <span className="settings-username">{u.username}</span>
              {isSelf && <span className="settings-you-badge">you</span>}
            </div>
          </div>
        </td>
        <td className="settings-td">
          {isSelf ? (
            <span className={`role-badge role-${u.role}`}>{u.role}</span>
          ) : (
            <select
              className={`role-select role-${u.role}`}
              value={u.role}
              onChange={handleRoleChange}
              disabled={changing}
            >
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
          )}
        </td>
        <td className="settings-td settings-td-date">
          {new Date(u.created_at).toLocaleDateString()}
        </td>
        <td className="settings-td settings-td-actions">
          {!isSelf && (
            <div className="settings-action-btns">
              <button
                className={`settings-icon-btn settings-key-btn ${resetOpen ? 'active' : ''}`}
                onClick={() => resetOpen ? cancelReset() : setResetOpen(true)}
                title="Reset password"
              >
                <KeyIcon />
              </button>
              <button
                className="settings-icon-btn settings-trash-btn"
                onClick={handleDelete}
                disabled={deleting}
                title="Delete user"
              >
                {deleting ? '…' : <TrashIcon />}
              </button>
            </div>
          )}
        </td>
      </tr>

      {resetOpen && (
        <tr className="settings-reset-row">
          <td colSpan={4} className="settings-reset-td">
            {resetOk ? (
              <div className="settings-reset-ok">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
                Password updated successfully
              </div>
            ) : (
              <form className="settings-reset-form" onSubmit={handleResetSubmit}>
                <div className="settings-reset-label">
                  <KeyIcon />
                  Reset password for <strong>{u.username}</strong>
                </div>
                <div className="settings-reset-fields">
                  <div className="settings-pw-wrap">
                    <input
                      ref={pwRef}
                      className="settings-reset-input"
                      type={showPw ? 'text' : 'password'}
                      placeholder="New password (min 8 chars)"
                      value={newPw}
                      onChange={e => setNewPw(e.target.value)}
                      autoComplete="new-password"
                    />
                    <button type="button" className="settings-pw-toggle" onClick={() => setShowPw(v => !v)}>
                      {showPw ? 'Hide' : 'Show'}
                    </button>
                  </div>
                  <input
                    className="settings-reset-input"
                    type={showPw ? 'text' : 'password'}
                    placeholder="Confirm new password"
                    value={confirmPw}
                    onChange={e => setConfirmPw(e.target.value)}
                    autoComplete="new-password"
                  />
                  <div className="settings-reset-actions">
                    <button type="submit" className="settings-reset-save" disabled={resetting}>
                      {resetting ? 'Saving…' : 'Save Password'}
                    </button>
                    <button type="button" className="settings-reset-cancel" onClick={cancelReset}>
                      Cancel
                    </button>
                  </div>
                </div>
                {resetError && <div className="settings-reset-error">{resetError}</div>}
              </form>
            )}
          </td>
        </tr>
      )}
    </Fragment>
  )
}

/* ── Main Settings Page ────────────────────────────── */

export default function Settings() {
  const { apiFetch, user } = useAuth()
  const [users, setUsers]       = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [showModal, setShowModal] = useState(false)

  const fetchUsers = useCallback(async () => {
    try {
      const res = await apiFetch('/api/admin/users')
      if (!res.ok) throw new Error(`Failed to load users (${res.status})`)
      setUsers(await res.json())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [apiFetch])

  useEffect(() => { fetchUsers() }, [fetchUsers])

  async function handleRoleChange(id, role) {
    const res = await apiFetch(`/api/admin/users/${id}/role`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    })
    if (res.ok) {
      const updated = await res.json()
      setUsers(prev => prev.map(u => u.id === updated.id ? { ...u, role: updated.role } : u))
    }
  }

  async function handleDelete(id) {
    const res = await apiFetch(`/api/admin/users/${id}`, { method: 'DELETE' })
    if (res.ok) setUsers(prev => prev.filter(u => u.id !== id))
  }

  async function handleAdd(username, password, role) {
    const res = await apiFetch('/api/admin/users', {
      method: 'POST',
      body: JSON.stringify({ username, password, role }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) return data.error || `HTTP ${res.status}`
    setUsers(prev => [...prev, data])
    return null
  }

  async function handleResetPassword(id, password) {
    const res = await apiFetch(`/api/admin/users/${id}/password`, {
      method: 'PATCH',
      body: JSON.stringify({ password }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) return data.error || `HTTP ${res.status}`
    return null
  }

  return (
    <div className="settings">
      {/* ── Manage Users ── */}
      <div className="settings-section">
        <div className="settings-section-header">
          <div className="settings-section-title-group">
            <h2 className="settings-section-title">Manage Users</h2>
            {!loading && !error && (
              <span className="settings-user-count">{users.length} {users.length === 1 ? 'user' : 'users'}</span>
            )}
          </div>
          <button className="settings-add-btn" onClick={() => setShowModal(true)}>
            <PlusIcon />
            Add User
          </button>
        </div>

        {loading && <div className="settings-loading">Loading users…</div>}
        {error   && <div className="settings-error">{error}</div>}

        {!loading && !error && (
          <div className="settings-table-wrap">
            <table className="settings-table">
              <thead>
                <tr>
                  <th className="settings-th">User</th>
                  <th className="settings-th">Role</th>
                  <th className="settings-th">Joined</th>
                  <th className="settings-th settings-th-actions">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <UserRow
                    key={u.id}
                    u={u}
                    currentUserId={user?.id}
                    onRoleChange={handleRoleChange}
                    onDelete={handleDelete}
                    onResetPassword={handleResetPassword}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── API Links ── */}
      <div className="settings-section">
        <div className="settings-section-header">
          <h2 className="settings-section-title">API Links</h2>
        </div>
        <div className="settings-api-links">
          <a
            className="settings-api-link"
            href={`http://${window.location.hostname}:8000/docs`}
            target="_blank"
            rel="noreferrer"
          >
            <div className="settings-api-link-icon">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
                <line x1="16" y1="13" x2="8" y2="13"/>
                <line x1="16" y1="17" x2="8" y2="17"/>
              </svg>
            </div>
            <div>
              <div className="settings-api-link-title">Swagger UI</div>
              <div className="settings-api-link-url">{window.location.hostname}:8000/docs</div>
            </div>
            <svg className="settings-api-link-arrow" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
              <polyline points="15 3 21 3 21 9"/>
              <line x1="10" y1="14" x2="21" y2="3"/>
            </svg>
          </a>

          <a
            className="settings-api-link"
            href={`http://${window.location.hostname}:8000/health`}
            target="_blank"
            rel="noreferrer"
          >
            <div className="settings-api-link-icon">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
              </svg>
            </div>
            <div>
              <div className="settings-api-link-title">Health Check</div>
              <div className="settings-api-link-url">{window.location.hostname}:8000/health</div>
            </div>
            <svg className="settings-api-link-arrow" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
              <polyline points="15 3 21 3 21 9"/>
              <line x1="10" y1="14" x2="21" y2="3"/>
            </svg>
          </a>
        </div>
      </div>

      {/* ── Add User Modal ── */}
      {showModal && (
        <AddUserModal
          onAdd={handleAdd}
          onClose={() => setShowModal(false)}
        />
      )}
    </div>
  )
}
