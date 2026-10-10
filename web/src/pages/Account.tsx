import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { type FormEvent, useState } from 'react'

import { api, call } from '../api/client'
import { sessionQuery } from '../api/queries'
import { ErrorNotice } from '../components/ui'

/** The signed-in user's own account: password and second factor. */
export function Account() {
	const session = useQuery(sessionQuery)
	const queryClient = useQueryClient()
	const refresh = () => queryClient.invalidateQueries({ queryKey: ['session'] })

	return (
		<div className="grid-page">
			<div className="page-head">
				<h1>Account</h1>
			</div>
			<p className="muted">
				Signed in as <strong>{session.data?.name ?? '…'}</strong> ({session.data?.role ?? '…'}).
			</p>
			<ErrorNotice error={session.error} />
			<Password />
			{session.data?.totp === true ? <DisableOtp onDone={refresh} /> : <SetupOtp onDone={refresh} />}
		</div>
	)
}

/** Changing the password; every other session of the user ends. */
function Password() {
	const queryClient = useQueryClient()
	const [current, setCurrent] = useState('')
	const [next, setNext] = useState('')
	const [repeat, setRepeat] = useState('')
	const [done, setDone] = useState(false)
	const change = useMutation({
		mutationFn: () => {
			if (next !== repeat) {
				throw new Error('The two passwords are not the same.')
			}
			return call(
				api.POST('/api/v1/auth/password', {
					body: { current_password: current, new_password: next },
				}),
			)
		},
		onSuccess: () => {
			setDone(true)
			setCurrent('')
			setNext('')
			setRepeat('')
			void queryClient.invalidateQueries({ queryKey: ['session'] })
		},
		onMutate: () => setDone(false),
	})
	const submit = (event: FormEvent) => {
		event.preventDefault()
		change.mutate()
	}
	return (
		<section className="panel" aria-labelledby="password-title">
			<h2 id="password-title">Password</h2>
			<form onSubmit={submit}>
				<label className="field">
					Current password
					<input
						className="input"
						type="password"
						autoComplete="current-password"
						required
						value={current}
						onChange={(event) => setCurrent(event.target.value)}
					/>
				</label>
				<label className="field">
					New password
					<input
						className="input"
						type="password"
						autoComplete="new-password"
						required
						value={next}
						onChange={(event) => setNext(event.target.value)}
					/>
				</label>
				<label className="field">
					Repeat it
					<input
						className="input"
						type="password"
						autoComplete="new-password"
						required
						value={repeat}
						onChange={(event) => setRepeat(event.target.value)}
					/>
				</label>
				{done ? (
					<div className="notice" role="status">
						The password was changed. Other sessions of this account have ended.
					</div>
				) : null}
				<ErrorNotice error={change.error} />
				<div>
					<button type="submit" className="button primary" disabled={change.isPending}>
						Change it
					</button>
				</div>
				<p className="muted">At least 12 characters. A passphrase of a few words works well.</p>
			</form>
		</section>
	)
}

/** Setting a TOTP second factor up: secret, then a code, then recovery codes. */
function SetupOtp({ onDone }: { onDone: () => void }) {
	const [password, setPassword] = useState('')
	const [pending, setPending] = useState<{ secret: string; uri: string } | null>(null)
	const [code, setCode] = useState('')
	const [codes, setCodes] = useState<string[] | null>(null)
	const setup = useMutation({
		mutationFn: () => call(api.POST('/api/v1/auth/otp/setup', { body: { password } })),
		onSuccess: (data) => {
			setPending({ secret: data.secret, uri: data.uri })
			setPassword('')
			onDone()
		},
	})
	const enable = useMutation({
		mutationFn: () => call(api.POST('/api/v1/auth/otp/enable', { body: { code: code.trim() } })),
		onSuccess: (data) => {
			setCodes(data.recovery_codes)
			setPending(null)
			setCode('')
			onDone()
		},
	})
	if (codes !== null) {
		return (
			<section className="panel" aria-labelledby="otp-title">
				<h2 id="otp-title">Two-factor authentication</h2>
				<div className="notice" role="status">
					The second factor is on. Save these recovery codes somewhere safe: each works once, and they are the
					way in when the authenticator app is lost.
				</div>
				<ul>
					{codes.map((value) => (
						<li key={value}>
							<code>{value}</code>
						</li>
					))}
				</ul>
				<button type="button" className="button" onClick={() => setCodes(null)}>
					Done
				</button>
			</section>
		)
	}
	return (
		<section className="panel" aria-labelledby="otp-title">
			<h2 id="otp-title">Two-factor authentication</h2>
			{pending === null ? (
				<form
					onSubmit={(event) => {
						event.preventDefault()
						setup.mutate()
					}}
				>
					<p className="muted">
						A code from an authenticator app (Aegis, 1Password, Google Authenticator…) will be asked for at
						every sign-in, next to the password.
					</p>
					<label className="field">
						Confirm with your password
						<input
							className="input"
							type="password"
							autoComplete="current-password"
							required
							value={password}
							onChange={(event) => setPassword(event.target.value)}
						/>
					</label>
					<ErrorNotice error={setup.error} />
					<div>
						<button type="submit" className="button primary" disabled={setup.isPending}>
							Set it up
						</button>
					</div>
				</form>
			) : (
				<form
					onSubmit={(event) => {
						event.preventDefault()
						enable.mutate()
					}}
				>
					<p>
						Add this secret to the app — scan it as a QR code or type it in — then confirm with the code it
						shows.
					</p>
					<label className="field">
						Secret
						<input className="input" type="text" readOnly value={pending.secret} />
					</label>
					<p className="muted">
						Or open the <a href={pending.uri}>otpauth link</a> on the device with the app.
					</p>
					<label className="field">
						Code from the app
						<input
							className="input"
							type="text"
							inputMode="numeric"
							autoComplete="one-time-code"
							required
							value={code}
							onChange={(event) => setCode(event.target.value)}
						/>
					</label>
					<ErrorNotice error={enable.error} />
					<div>
						<button type="submit" className="button primary" disabled={enable.isPending}>
							Turn it on
						</button>
					</div>
				</form>
			)}
		</section>
	)
}

/** Turning the second factor off; the password confirms it. */
function DisableOtp({ onDone }: { onDone: () => void }) {
	const [password, setPassword] = useState('')
	const disable = useMutation({
		mutationFn: () => call(api.POST('/api/v1/auth/otp/disable', { body: { password } })),
		onSuccess: () => {
			setPassword('')
			onDone()
		},
	})
	return (
		<section className="panel" aria-labelledby="otp-off-title">
			<h2 id="otp-off-title">Two-factor authentication</h2>
			<p className="muted">The second factor is on. Turning it off also removes every recovery code.</p>
			<form
				onSubmit={(event) => {
					event.preventDefault()
					disable.mutate()
				}}
			>
				<label className="field">
					Confirm with your password
					<input
						className="input"
						type="password"
						autoComplete="current-password"
						required
						value={password}
						onChange={(event) => setPassword(event.target.value)}
					/>
				</label>
				<ErrorNotice error={disable.error} />
				<div>
					<button type="submit" className="button" disabled={disable.isPending}>
						Turn it off
					</button>
				</div>
			</form>
		</section>
	)
}
