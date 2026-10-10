import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { api, call, ifMatch, type Role, type UserView } from '../api/client'
import { usersQuery } from '../api/queries'
import { ErrorNotice } from '../components/ui'

/** The users with access to the API; admins only. */
export function Users() {
	const users = useQuery(usersQuery)
	const queryClient = useQueryClient()
	const refresh = () => queryClient.invalidateQueries({ queryKey: ['users'] })

	const [name, setName] = useState('')
	const [password, setPassword] = useState('')
	const [role, setRole] = useState<Role>('admin')
	const create = useMutation({
		mutationFn: () =>
			call(
				api.POST('/api/v1/users', {
					body: { name: name.trim(), password, role },
				}),
			),
		onSuccess: () => {
			setName('')
			setPassword('')
			setRole('admin')
			void refresh()
		},
	})

	const [passwordFor, setPasswordFor] = useState<UserView | null>(null)
	const [newPassword, setNewPassword] = useState('')
	const setUserPassword = useMutation({
		mutationFn: (user: UserView) =>
			call(
				api.POST('/api/v1/users/{id}/password', {
					params: { path: { id: user.id } },
					body: { password: newPassword },
				}),
			),
		onSuccess: () => {
			setPasswordFor(null)
			setNewPassword('')
			void refresh()
		},
	})

	const toggle = useMutation({
		mutationFn: (user: UserView) =>
			call(
				api.PUT('/api/v1/users/{id}', {
					params: { path: { id: user.id }, header: ifMatch(user.revision) },
					body: { name: user.name, role: user.role, disabled: !user.disabled },
				}),
			),
		onSuccess: refresh,
	})
	const remove = useMutation({
		mutationFn: (user: UserView) =>
			call(
				api.DELETE('/api/v1/users/{id}', {
					params: { path: { id: user.id }, header: ifMatch(user.revision) },
				}),
			),
		onSuccess: refresh,
	})

	const [resetLink, setResetLink] = useState<string | null>(null)
	const issueReset = useMutation({
		mutationFn: (user: UserView) =>
			call(api.POST('/api/v1/users/{id}/reset', { params: { path: { id: user.id } } })),
		onSuccess: (issued) => {
			setResetLink(`${window.location.origin}/reset?token=${issued.token}`)
			void refresh()
		},
	})

	const error = create.error ?? setUserPassword.error ?? toggle.error ?? remove.error ?? issueReset.error

	return (
		<div className="grid-page">
			<div className="page-head">
				<h1>Users</h1>
			</div>
			<p className="muted">
				Users sign in to the web UI and the API. Admins change everything; viewers read, and may manage their
				own password and second factor. The admin token, for scripts, still works next to these.
			</p>

			{resetLink === null ? null : (
				<section className="panel" aria-labelledby="reset-link-title">
					<h2 id="reset-link-title">One-time reset link</h2>
					<p>Hand it to the user; it works once, for an hour.</p>
					<p>
						<code>{resetLink}</code>
					</p>
					<button type="button" className="button" onClick={() => setResetLink(null)}>
						Done
					</button>
				</section>
			)}

			{passwordFor === null ? null : (
				<section className="panel" aria-labelledby="set-password-title">
					<h2 id="set-password-title">Password for {passwordFor.name}</h2>
					<form
						onSubmit={(event) => {
							event.preventDefault()
							setUserPassword.mutate(passwordFor)
						}}
					>
						<label className="field">
							New password
							<input
								className="input"
								type="password"
								autoComplete="new-password"
								required
								value={newPassword}
								onChange={(event) => setNewPassword(event.target.value)}
							/>
						</label>
						<div>
							<button type="submit" className="button primary" disabled={setUserPassword.isPending}>
								Set it
							</button>
							<button
								type="button"
								className="button"
								onClick={() => {
									setPasswordFor(null)
									setNewPassword('')
								}}
							>
								Cancel
							</button>
						</div>
					</form>
				</section>
			)}

			<section className="panel" aria-labelledby="new-user-title">
				<h2 id="new-user-title">New user</h2>
				<form
					onSubmit={(event) => {
						event.preventDefault()
						create.mutate()
					}}
				>
					<label className="field">
						User name
						<input
							className="input"
							type="text"
							autoComplete="off"
							autoCapitalize="none"
							spellCheck={false}
							required
							value={name}
							onChange={(event) => setName(event.target.value)}
						/>
					</label>
					<label className="field">
						Password
						<input
							className="input"
							type="password"
							autoComplete="new-password"
							required
							value={password}
							onChange={(event) => setPassword(event.target.value)}
						/>
					</label>
					<label className="field">
						Role
						<select className="input" value={role} onChange={(event) => setRole(event.target.value as Role)}>
							<option value="admin">admin — change everything</option>
							<option value="viewer">viewer — read only</option>
						</select>
					</label>
					<div>
						<button type="submit" className="button primary" disabled={create.isPending}>
							Add
						</button>
					</div>
					<p className="muted">At least 12 characters. Give the password to the user yourself.</p>
				</form>
			</section>

			<ErrorNotice error={error} />
			<div className="panel">
				<table className="table">
					<thead>
						<tr>
							<th>Name</th>
							<th>Role</th>
							<th>State</th>
							<th>2FA</th>
							<th>Actions</th>
						</tr>
					</thead>
					<tbody>
						{(users.data ?? []).map((user) => (
							<tr key={user.id}>
								<td>{user.name}</td>
								<td>{user.role}</td>
								<td>{user.disabled ? 'disabled' : 'enabled'}</td>
								<td>{user.totp ? `on (${user.recovery_codes_left} codes left)` : 'off'}</td>
								<td>
									<button
										type="button"
										className="button small"
										disabled={issueReset.isPending}
										onClick={() => issueReset.mutate(user)}
									>
										Reset link
									</button>{' '}
									<button
										type="button"
										className="button small"
										onClick={() => {
											setPasswordFor(user)
											setNewPassword('')
										}}
									>
										Password
									</button>{' '}
									<button
										type="button"
										className="button small"
										disabled={toggle.isPending}
										onClick={() => toggle.mutate(user)}
									>
										{user.disabled ? 'Enable' : 'Disable'}
									</button>{' '}
									<button
										type="button"
										className="button small"
										disabled={remove.isPending}
										onClick={() => {
											if (window.confirm(`Remove ${user.name}?`)) {
												remove.mutate(user)
											}
										}}
									>
										Remove
									</button>
								</td>
							</tr>
						))}
						{users.data?.length === 0 ? (
							<tr>
								<td colSpan={5}>No users yet.</td>
							</tr>
						) : null}
					</tbody>
				</table>
			</div>
			<ErrorNotice error={users.error} />
		</div>
	)
}
