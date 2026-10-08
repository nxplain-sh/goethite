import type { QueryClient } from '@tanstack/react-query'
import {
	Link,
	Outlet,
	createRootRouteWithContext,
	createRoute,
	createRouter,
} from '@tanstack/react-router'

import { OUTCOMES } from './api/client'
import type { LogSearch } from './api/queries'
import { safeRedirect } from './auth'
import { Shell } from './components/Shell'
import { Dashboard } from './pages/Dashboard'
import { Login } from './pages/Login'
import { QueryLog } from './pages/QueryLog'

// Validators return every key they know, `undefined` when the value is not
// valid: the router merges their result over the raw query parameters, so a
// key left out would keep its raw, unchecked value.

function logSearch(search: Record<string, unknown>): LogSearch {
	const name = search['name']
	const before = Number(search['before'])
	return {
		name: typeof name === 'string' && name !== '' ? name.slice(0, 255) : undefined,
		outcome: OUTCOMES.find((candidate) => candidate === search['outcome']),
		before: Number.isSafeInteger(before) && before > 0 ? before : undefined,
	}
}

function NotFound() {
	return (
		<div className="panel">
			<h1>Not found</h1>
			<p>There is no page here.</p>
			<Link to="/">Back to the dashboard</Link>
		</div>
	)
}

const rootRoute = createRootRouteWithContext<{ queryClient: QueryClient }>()({
	component: Outlet,
	notFoundComponent: NotFound,
})

const loginRoute = createRoute({
	getParentRoute: () => rootRoute,
	path: '/login',
	validateSearch: (search: Record<string, unknown>): { redirect?: string | undefined } => ({
		redirect: safeRedirect(search['redirect']),
	}),
	component: function LoginPage() {
		return <Login redirect={loginRoute.useSearch().redirect} />
	},
})

const appRoute = createRoute({
	getParentRoute: () => rootRoute,
	id: 'app',
	component: Shell,
})

const dashboardRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/',
	component: Dashboard,
})

const queryLogRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/querylog',
	validateSearch: logSearch,
	component: function QueryLogPage() {
		return <QueryLog search={queryLogRoute.useSearch()} />
	},
})

const routeTree = rootRoute.addChildren([
	loginRoute,
	appRoute.addChildren([dashboardRoute, queryLogRoute]),
])

export function createAppRouter(queryClient: QueryClient) {
	return createRouter({
		routeTree,
		context: { queryClient },
		defaultPreload: 'intent',
		scrollRestoration: true,
	})
}

declare module '@tanstack/react-router' {
	interface Register {
		router: ReturnType<typeof createAppRouter>
	}
}
