import type { QueryClient } from '@tanstack/react-query'
import {
	Link,
	Outlet,
	createRootRouteWithContext,
	createRoute,
	createRouter,
	lazyRouteComponent,
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

// The configuration pages load on first use: the dashboard and the query
// log stay small.
const lists = () => import('./pages/Lists')
const rules = () => import('./pages/Rules')
const groups = () => import('./pages/Groups')
const clients = () => import('./pages/Clients')
const schedules = () => import('./pages/Schedules')
const ListEditor = lazyRouteComponent(lists, 'ListEditor')
const RuleEditor = lazyRouteComponent(rules, 'RuleEditor')
const GroupEditor = lazyRouteComponent(groups, 'GroupEditor')
const ClientEditor = lazyRouteComponent(clients, 'ClientEditor')
const ScheduleEditor = lazyRouteComponent(schedules, 'ScheduleEditor')

const listsRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/lists',
	component: lazyRouteComponent(lists, 'Lists'),
})

const listEditorRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/lists/$id',
	component: function ListEditorPage() {
		return <ListEditor id={listEditorRoute.useParams().id} />
	},
})

const rulesRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/rules',
	component: lazyRouteComponent(rules, 'Rules'),
})

const ruleEditorRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/rules/$id',
	component: function RuleEditorPage() {
		return <RuleEditor id={ruleEditorRoute.useParams().id} />
	},
})

const groupsRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/groups',
	component: lazyRouteComponent(groups, 'Groups'),
})

const groupEditorRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/groups/$id',
	component: function GroupEditorPage() {
		return <GroupEditor id={groupEditorRoute.useParams().id} />
	},
})

const clientsRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/clients',
	component: lazyRouteComponent(clients, 'Clients'),
})

const clientEditorRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/clients/$id',
	component: function ClientEditorPage() {
		return <ClientEditor id={clientEditorRoute.useParams().id} />
	},
})

const schedulesRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/schedules',
	component: lazyRouteComponent(schedules, 'Schedules'),
})

const scheduleEditorRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/schedules/$id',
	component: function ScheduleEditorPage() {
		return <ScheduleEditor id={scheduleEditorRoute.useParams().id} />
	},
})

const settingsRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/settings',
	component: lazyRouteComponent(() => import('./pages/Settings'), 'Settings'),
})

const auditRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/audit',
	component: lazyRouteComponent(() => import('./pages/Audit'), 'Audit'),
})

const routeTree = rootRoute.addChildren([
	loginRoute,
	appRoute.addChildren([
		dashboardRoute,
		queryLogRoute,
		listsRoute,
		listEditorRoute,
		rulesRoute,
		ruleEditorRoute,
		groupsRoute,
		groupEditorRoute,
		clientsRoute,
		clientEditorRoute,
		schedulesRoute,
		scheduleEditorRoute,
		settingsRoute,
		auditRoute,
	]),
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
