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
import { Dashboard, RANGES, type RangeId } from './pages/Dashboard'
import { Login } from './pages/Login'
import { QueryLog } from './pages/QueryLog'

// Validators return every key they know, `undefined` when the value is not
// valid: the router merges their result over the raw query parameters, so a
// key left out would keep its raw, unchecked value.

/** A non-empty string of at most 255 characters, if `value` is one. */
function text(value: unknown): string | undefined {
	return typeof value === 'string' && value !== '' ? value.slice(0, 255) : undefined
}

/** `value`, if it is a time the API can read. */
function time(value: unknown): string | undefined {
	return typeof value === 'string' && value.length <= 64 && !Number.isNaN(Date.parse(value))
		? value
		: undefined
}

function logSearch(search: Record<string, unknown>): LogSearch {
	const before = Number(search['before'])
	return {
		name: text(search['name']),
		outcome: OUTCOMES.find((candidate) => candidate === search['outcome']),
		client: text(search['client']),
		since: time(search['since']),
		until: time(search['until']),
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
	validateSearch: (search: Record<string, unknown>): { range?: RangeId | undefined } => ({
		range: RANGES.find((range) => range.id === search['range'])?.id,
	}),
	component: function DashboardPage() {
		return <Dashboard range={dashboardRoute.useSearch().range} />
	},
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
const FindLists = lazyRouteComponent(() => import('./pages/FindLists'), 'FindLists')
const RuleEditor = lazyRouteComponent(rules, 'RuleEditor')
const GroupEditor = lazyRouteComponent(groups, 'GroupEditor')
const ClientEditor = lazyRouteComponent(clients, 'ClientEditor')
const ScheduleEditor = lazyRouteComponent(schedules, 'ScheduleEditor')

const listsRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/lists',
	component: lazyRouteComponent(lists, 'Lists'),
})

const findListsRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/lists/find',
	component: FindLists,
})

/** What a new list starts with, such as a list found in the directory. */
export interface ListDraft {
	name?: string | undefined
	url?: string | undefined
	comment?: string | undefined
}

const listEditorRoute = createRoute({
	getParentRoute: () => appRoute,
	path: '/lists/$id',
	validateSearch: (search: Record<string, unknown>): ListDraft => {
		const url = search['url']
		return {
			name: text(search['name'])?.slice(0, 100),
			url: typeof url === 'string' && url.startsWith('https://') && url.length <= 2048 ? url : undefined,
			comment: text(search['comment']),
		}
	},
	component: function ListEditorPage() {
		return <ListEditor id={listEditorRoute.useParams().id} draft={listEditorRoute.useSearch()} />
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
		findListsRoute,
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
