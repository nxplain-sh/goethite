import { useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from '@tanstack/react-router'
import { type FormEvent, useState } from 'react'

import { ApiError, api, call, describe } from '../api/client'
import { safeRedirect } from '../auth'
import { DocsLinks } from '../components/DocsLinks'

/** Signs in with a user name and password, and a code when a second factor is on. */
export function Login({ redirect }: { redirect: string | undefined }) {
	const navigate = useNavigate()
	const queryClient = useQueryClient()
	const [name, setName] = useState('')
	const [password, setPassword] = useState('')
	const [code, setCode] = useState('')
	const [needsCode, setNeedsCode] = useState(false)
	const [error, setError] = useState<string | null>(null)
	const [busy, setBusy] = useState(false)

	const submit = async (event: FormEvent) => {
		event.preventDefault()
		setBusy(true)
		setError(null)
		const body: { name: string; password: string; code?: string } = {
			name: name.trim(),
			password,
		}
		if (needsCode || code.trim() !== '') {
			body.code = code.trim()
		}
		try {
			await call(api.POST('/api/v1/auth/login', { body }))
			queryClient.clear()
			await navigate({ to: safeRedirect(redirect) ?? '/' })
		} catch (err) {
			if (err instanceof ApiError && err.code === 'otp_required') {
				setNeedsCode(true)
				setError('Enter the six-digit code from your authenticator app, or a recovery code.')
			} else {
				setError(describe(err))
			}
		} finally {
			setBusy(false)
		}
	}

	return (
		<main className="login">
			<section className="panel" aria-labelledby="login-title">
				<h1 id="login-title">goethite</h1>
				<p>Sign in to administer this node.</p>
				<form onSubmit={(event) => void submit(event)}>
					<label className="field">
						User name
						<input
							className="input"
							type="text"
							name="username"
							autoComplete="username"
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
							name="password"
							autoComplete="current-password"
							required
							value={password}
							onChange={(event) => setPassword(event.target.value)}
						/>
					</label>
					{needsCode ? (
						<label className="field">
							Code
							<input
								className="input"
								type="text"
								name="code"
								autoComplete="one-time-code"
								autoCapitalize="none"
								spellCheck={false}
								required
								value={code}
								onChange={(event) => setCode(event.target.value)}
							/>
						</label>
					) : null}
					{error === null ? null : (
						<div className="notice error" role="alert">
							{error}
						</div>
					)}
					<div>
						<button type="submit" className="button primary" disabled={busy}>
							Sign in
						</button>
					</div>
					<p className="muted">
						The session lives in this browser as an HttpOnly cookie, and ends when you sign out or after
						twelve hours.
					</p>
					<p className="muted">
						Forgot the password? Ask an admin to issue a <Link to="/reset">reset link</Link>. First run, with
						no users yet? Create one on the node with <code>goethite user add</code>.
					</p>
				</form>
			</section>
			<DocsLinks />
		</main>
	)
}
