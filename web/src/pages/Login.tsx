import { useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { type FormEvent, useState } from 'react'

import { ApiError, api, call, describe } from '../api/client'
import { clearToken, looksLikeToken, safeRedirect, setToken } from '../auth'
import { DocsLinks } from '../components/DocsLinks'

/** Asks for the admin token. */
export function Login({ redirect }: { redirect: string | undefined }) {
	const navigate = useNavigate()
	const queryClient = useQueryClient()
	const [value, setValue] = useState('')
	const [error, setError] = useState<string | null>(null)
	const [busy, setBusy] = useState(false)

	const submit = async (event: FormEvent) => {
		event.preventDefault()
		const candidate = value.trim()
		if (!looksLikeToken(candidate)) {
			setError('That is not a goethite token: they start with gth_ followed by 64 hex digits.')
			return
		}
		setBusy(true)
		setError(null)
		setToken(candidate)
		try {
			await call(api.GET('/api/v1/status'))
			queryClient.clear()
			await navigate({ to: safeRedirect(redirect) ?? '/' })
		} catch (err) {
			clearToken()
			setError(
				err instanceof ApiError && err.status === 401
					? 'This node does not accept that token.'
					: describe(err),
			)
		} finally {
			setBusy(false)
		}
	}

	return (
		<main className="login">
			<section className="panel" aria-labelledby="login-title">
				<h1 id="login-title">goethite</h1>
				<p>
					This node needs its admin token. Create one on the node with <code>goethite token</code>.
				</p>
				<form onSubmit={(event) => void submit(event)}>
					<label className="field">
						Admin token
						<input
							className="input"
							type="password"
							name="token"
							autoComplete="off"
							spellCheck={false}
							required
							value={value}
							onChange={(event) => setValue(event.target.value)}
						/>
					</label>
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
						The token is kept in this browser tab only, and forgotten when the tab closes.
					</p>
				</form>
			</section>
			<DocsLinks />
		</main>
	)
}
