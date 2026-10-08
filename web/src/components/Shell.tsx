import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, Outlet, useNavigate } from '@tanstack/react-router'
import { useEffect, useState } from 'react'

import { clearToken, currentToken } from '../auth'
import { api, call } from '../api/client'
import { statusQuery } from '../api/queries'
import { currentTheme, onSystemThemeChange, setTheme } from '../theme'
import { ErrorNotice, ProtectionBadge } from './ui'

/** How long the pause button pauses filtering. */
const PAUSE_SECONDS = 600

/** The frame around every signed-in page. */
export function Shell() {
	const status = useQuery(statusQuery)
	const queryClient = useQueryClient()
	const navigate = useNavigate()
	const [theme, setThemeState] = useState(currentTheme)
	useEffect(() => onSystemThemeChange(() => setThemeState(currentTheme())), [])
	const refresh = () => queryClient.invalidateQueries({ queryKey: ['status'] })
	const pause = useMutation({
		mutationFn: () => call(api.PUT('/api/v1/pause', { body: { seconds: PAUSE_SECONDS } })),
		onSettled: refresh,
	})
	const resume = useMutation({
		mutationFn: () => call(api.DELETE('/api/v1/pause')),
		onSettled: refresh,
	})
	const paused = status.data?.paused_until != null

	return (
		<div className="shell">
			<header className="topbar">
				<div className="brand">
					goethite
					{status.data ? <small>v{status.data.version}</small> : null}
				</div>
				{status.data ? <ProtectionBadge status={status.data} /> : null}
				{status.data?.protection ? (
					paused ? (
						<button
							type="button"
							className="button small primary"
							disabled={resume.isPending}
							onClick={() => resume.mutate()}
						>
							Resume filtering
						</button>
					) : (
						<button
							type="button"
							className="button small"
							disabled={pause.isPending}
							onClick={() => pause.mutate()}
						>
							Pause 10 min
						</button>
					)
				) : null}
				<button
					type="button"
					className="button small"
					onClick={() => {
						const next = theme === 'dark' ? 'light' : 'dark'
						setTheme(next)
						setThemeState(next)
					}}
				>
					{theme === 'dark' ? 'Light theme' : 'Dark theme'}
				</button>
				{currentToken() === null ? null : (
					<button
						type="button"
						className="button small"
						onClick={() => {
							clearToken()
							queryClient.clear()
							void navigate({ to: '/login' })
						}}
					>
						Sign out
					</button>
				)}
			</header>
			<nav className="nav" aria-label="Pages">
				<Link to="/" activeOptions={{ exact: true }}>
					Dashboard
				</Link>
				<Link to="/querylog">Query log</Link>
			</nav>
			<ErrorNotice error={status.error ?? pause.error ?? resume.error} />
			<main>
				<Outlet />
			</main>
		</div>
	)
}
