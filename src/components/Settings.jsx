import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '../auth/AuthContext'
import './Settings.css'

function UserRow({ u, currentUserId, onRoleChange, onDelete }) {
  const [changing, setChanging] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const isSelf = u.id === currentUserId

  async function handleRoleChange(e) {
    const newRole = e.target.value
    setChanging(true)
    await onRoleChange(u.id, newRole)
    setChanging(false)
  }

  async function handleDelete() {
    if (!window.confirm(`Delete user "${u.username}"? This cannot be undone.`)) return
    setDeleting(true)
    await onDelete(u.id)
    setDeleting(false)
  }

  return (
    <tr className={isSelf ? 'settings-row settings-row-self' : 'settings-row'}>
      <td className="settings-td">
        <span className="settings-username">{u.username}</span>
        {isSelf && <span className="settings-you-badge">you</span>}
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
          <button
            className="settings-delete-btn"
            onClick={handleDelete}
            disabled={deleting}
          >
            {deleting ? '...' : 'Delete'}
          </button>
        )}
      </td>
    </tr>
  )
}

function AddUserForm({ onAdd }) {
  const [open, setOpen] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('user')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  async function handleSubmit(e) {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    const err = await onAdd(username.trim(), password, role)
    setSubmitting(false)
    if (err) {
      setError(err)
    } else {
      setUsername('')
      setPassword('')
      setRole('user')
      setOpen(false)
    }
  }

  if (!open) {
    return (
      <button className="settings-add-btn" onClick={() => setOpen(true)}>
        + Add user
      </button>
    )
  }

  return (
    <form className="settings-add-form" onSubmit={handleSubmit}>
      <input
        className="settings-input"
        placeholder="Username"
        value={username}
        onChange={e => setUsername(e.target.value)}
        autoFocus
      />
      <input
        className="settings-input"
        type="password"
        placeholder="Password (min 8 chars)"
        value={password}
        onChange={e => setPassword(e.target.value)}
      />
      <select className="role-select" value={role} onChange={e => setRole(e.target.value)}>
        <option value="user">user</option>
        <option value="admin">admin</option>
      </select>
      {error && <span className="settings-form-error">{error}</span>}
      <button className="settings-add-btn" type="submit" disabled={submitting}>
        {submitting ? 'Creating...' : 'Create'}
      </button>
      <button
        className="settings-cancel-btn"
        type="button"
        onClick={() => { setOpen(false); setError(null) }}
      >
        Cancel
      </button>
    </form>
  )
}

export default function Settings() {
  const { apiFetch, user } = useAuth()
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

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

  return (
    <div className="settings">
      <div className="settings-section">
        <div className="settings-section-header">
          <h2 className="settings-section-title">Users</h2>
          <AddUserForm onAdd={handleAdd} />
        </div>

        {loading && <div className="settings-loading">Loading...</div>}
        {error   && <div className="settings-error">{error}</div>}

        {!loading && !error && (
          <div className="settings-table-wrap">
            <table className="settings-table">
              <thead>
                <tr>
                  <th className="settings-th">Username</th>
                  <th className="settings-th">Role</th>
                  <th className="settings-th">Created</th>
                  <th className="settings-th" />
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
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

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
                <polyline points="10 9 9 9 8 9"/>
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
    </div>
  )
}
