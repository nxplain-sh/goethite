import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, Outlet, useNavigate } from '@tanstack/react-router'

import { clearToken, currentToken } from '../auth'
import { api, call } from '../api/client'
import { statusQuery } from '../api/queries'
import { DocsLinks } from './DocsLinks'
import { ClusterBadges, ErrorNotice, ProtectionBadge } from './ui'

/** How long the pause button pauses filtering. */
const PAUSE_SECONDS = 600

/** The frame around every signed-in page. */
export function Shell() {
	const status = useQuery(statusQuery)
	const queryClient = useQueryClient()
	const navigate = useNavigate()
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
				{status.data?.cluster ? <ClusterBadges cluster={status.data.cluster} /> : null}
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
				<Link to="/settings" className="button small">
					Settings
				</Link>
				<DocsLinks />
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
				<Link to="/" activeOptions={{ exact: true, includeSearch: false }}>
					Dashboard
				</Link>
				<Link to="/querylog" activeOptions={{ includeSearch: false }}>
					Query log
				</Link>
				<Link to="/lists">Lists</Link>
				<Link to="/rules">Rules</Link>
				<Link to="/records">Records</Link>
				<Link to="/groups">Groups</Link>
				<Link to="/clients">Clients</Link>
				<Link to="/schedules">Schedules</Link>
				<Link to="/audit">Audit log</Link>
				<Link to="/leak-test">Leak test</Link>
			</nav>
			<ErrorNotice error={status.error ?? pause.error ?? resume.error} />
			{(status.data?.problems ?? []).map((problem) => (
				<div key={problem} className="notice error" role="alert">
					This node: {problem}
				</div>
			))}
			{(status.data?.cluster?.problems ?? []).map((problem) => (
				<div key={problem} className="notice error" role="alert">
					Cluster: {problem}
				</div>
			))}
			<main>
				<Outlet />
			</main>
		</div>
	)
}
