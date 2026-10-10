import { queryOptions } from '@tanstack/react-query'

import { api, call, type QueryOutcome } from './client'

export const statusQuery = queryOptions({
	queryKey: ['status'],
	queryFn: () => call(api.GET('/api/v1/status')),
	refetchInterval: 5_000,
})

/** The signed-in user; a 401 sends the page to the login. */
export const sessionQuery = queryOptions({
	queryKey: ['session'],
	queryFn: () => call(api.GET('/api/v1/auth/session')),
	staleTime: 30_000,
})

/** The users with access to the API; admins only. */
export const usersQuery = queryOptions({
	queryKey: ['users'],
	queryFn: () => call(api.GET('/api/v1/users')),
})

export const statsQuery = (hours: number) =>
	queryOptions({
		queryKey: ['stats', hours],
		// A cluster's, added up; a node on its own answers with its own.
		queryFn: () => call(api.GET('/api/v1/stats', { params: { query: { hours, scope: 'cluster' } } })),
		refetchInterval: 10_000,
	})

export const listsQuery = queryOptions({
	queryKey: ['lists'],
	queryFn: () => call(api.GET('/api/v1/lists')),
	refetchInterval: 30_000,
})

/** goethite's recommended lists and presets: built in, so fetched once. */
export const recommendedQuery = queryOptions({
	queryKey: ['recommended'],
	queryFn: () => call(api.GET('/api/v1/lists/recommended')),
	staleTime: Number.POSITIVE_INFINITY,
})

/** How big the recommended lists say they are, as the node read them (it keeps them a day). */
export const recommendedSizesQuery = queryOptions({
	queryKey: ['recommended', 'sizes'],
	queryFn: () => call(api.GET('/api/v1/lists/recommended/sizes')),
	staleTime: 3_600_000,
	retry: false,
	select: (sizes) => new Map(sizes.lists.map((size) => [size.id, size.entries])),
})

/** The FilterLists directory, as the node fetched it (it keeps it a day). */
export const directoryQuery = queryOptions({
	queryKey: ['directory'],
	queryFn: () => call(api.GET('/api/v1/lists/directory')),
	staleTime: 3_600_000,
	retry: false,
})

/** One list's details from the FilterLists directory. */
export const directoryListQuery = (id: number) =>
	queryOptions({
		queryKey: ['directory', id],
		queryFn: () => call(api.GET('/api/v1/lists/directory/{id}', { params: { path: { id } } })),
		staleTime: 3_600_000,
		retry: false,
	})

/** The services groups can block, from the catalog the node downloads. */
export const servicesQuery = queryOptions({
	queryKey: ['services'],
	queryFn: () => call(api.GET('/api/v1/services')),
	staleTime: 3_600_000,
	retry: false,
})

export const clientsQuery = queryOptions({
	queryKey: ['clients'],
	queryFn: () => call(api.GET('/api/v1/clients')),
	staleTime: 30_000,
	select: (clients) => new Map(clients.map((client) => [client.id, client.spec.name])),
})

/** What the query log page shows. */
export interface LogSearch {
	name?: string | undefined
	outcome?: QueryOutcome | undefined
	/** A client address, client ID or group ID. */
	client?: string | undefined
	/** Entries at or after this time (RFC 3339). */
	since?: string | undefined
	/** Entries before this time (RFC 3339). */
	until?: string | undefined
	before?: number | undefined
}

/** How many entries one page shows. */
export const LOG_PAGE = 500

/** Whether a search shows the newest entries as they come. */
export function isLive(search: LogSearch): boolean {
	return search.before === undefined && search.until === undefined
}

export const queryLogQuery = (search: LogSearch) =>
	queryOptions({
		queryKey: ['querylog', search],
		queryFn: () =>
			call(
				api.GET('/api/v1/querylog', {
					params: {
						query: {
							limit: LOG_PAGE,
							...(search.name === undefined ? {} : { name: search.name }),
							...(search.outcome === undefined ? {} : { outcome: search.outcome }),
							...(search.client === undefined ? {} : { client: search.client }),
							...(search.since === undefined ? {} : { since: search.since }),
							...(search.until === undefined ? {} : { until: search.until }),
							...(search.before === undefined ? {} : { before: search.before }),
						},
					},
				}),
			),
		// The newest page follows the log live; older pages and closed time
		// windows stand still.
		refetchInterval: isLive(search) ? 3_000 : false,
		placeholderData: (previous) => previous,
	})
