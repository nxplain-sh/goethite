import { Link } from '@tanstack/react-router'
import { type FormEvent, useState } from 'react'

import { api, call, describe } from '../api/client'
import { DocsLinks } from '../components/DocsLinks'

/** Sets a new password with the one-time token an admin issued. */
export function Reset({ token }: { token: string | undefined }) {
	const [password, setPassword] = useState('')
	const [repeat, setRepeat] = useState('')
	const [error, setError] = useState<string | null>(null)
	const [done, setDone] = useState(false)
	const [busy, setBusy] = useState(false)

	const submit = async (event: FormEvent) => {
		event.preventDefault()
		if (token === undefined) {
			setError('This link carries no reset token. Ask an admin for a new link.')
			return
		}
		if (password !== repeat) {
			setError('The two passwords are not the same.')
			return
		}
		setBusy(true)
		setError(null)
		try {
			await call(api.POST('/api/v1/auth/reset', { body: { token, password } }))
			setDone(true)
		} catch (err) {
			setError(describe(err))
		} finally {
			setBusy(false)
		}
	}

	return (
		<main className="login">
			<section className="panel" aria-labelledby="reset-title">
				<h1 id="reset-title">Set a new password</h1>
				{done ? (
					<>
						<p role="status">The password was set, and every session of the account has ended.</p>
						<p>
							<Link to="/login" className="button primary">
								Sign in
							</Link>
						</p>
					</>
				) : (
					<form onSubmit={(event) => void submit(event)}>
						<p>A reset link works once, and expires an hour after it is issued.</p>
						<label className="field">
							New password
							<input
								className="input"
								type="password"
								name="password"
								autoComplete="new-password"
								required
								value={password}
								onChange={(event) => setPassword(event.target.value)}
							/>
						</label>
						<label className="field">
							Repeat it
							<input
								className="input"
								type="password"
								name="repeat"
								autoComplete="new-password"
								required
								value={repeat}
								onChange={(event) => setRepeat(event.target.value)}
							/>
						</label>
						{error === null ? null : (
							<div className="notice error" role="alert">
								{error}
							</div>
						)}
						<div>
							<button type="submit" className="button primary" disabled={busy}>
								Set it
							</button>
						</div>
						<p className="muted">At least 12 characters. A passphrase of a few words works well.</p>
					</form>
				)}
			</section>
			<DocsLinks />
		</main>
	)
}
