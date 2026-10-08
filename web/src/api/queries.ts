import { queryOptions } from '@tanstack/react-query'

import { api, call, type QueryOutcome } from './client'

export const statusQuery = queryOptions({
	queryKey: ['status'],
	queryFn: () => call(api.GET('/api/v1/status')),
	refetchInterval: 5_000,
})

export const statsQuery = (hours: number) =>
	queryOptions({
		queryKey: ['stats', hours],
		// A cluster's, added up; a node on its own answers with its own.
		queryFn: () =>
			call(api.GET('/api/v1/stats', { params: { query: { hours, scope: 'cluster' } } })),
		refetchInterval: 10_000,
	})

export const listsQuery = queryOptions({
	queryKey: ['lists'],
	queryFn: () => call(api.GET('/api/v1/lists')),
	refetchInterval: 30_000,
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
	before?: number | undefined
}

/** How many entries one page shows. */
export const LOG_PAGE = 500

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
							...(search.before === undefined ? {} : { before: search.before }),
						},
					},
				}),
			),
		// The newest page follows the log live; older pages stand still.
		refetchInterval: search.before === undefined ? 3_000 : false,
		placeholderData: (previous) => previous,
	})
