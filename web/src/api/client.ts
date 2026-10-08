// The typed API client, generated from crates/goethite-api/openapi.json
// (`npm run api` regenerates src/api/schema.d.ts).

import createClient from 'openapi-fetch'

import { currentToken } from '../auth'
import type { components, paths } from './schema'

export type Schemas = components['schemas']
export type Status = Schemas['Status']
export type StatsReport = Schemas['StatsReport']
export type QueryEntry = Schemas['QueryEntry']
export type QueryOutcome = Schemas['QueryOutcome']
export type List = Schemas['List']
export type ListSpec = Schemas['ListSpec']
export type ListStatus = Schemas['ListStatus']
export type RecommendedList = Schemas['RecommendedList']
export type Directory = Schemas['Directory']
export type DirectoryEntry = Schemas['DirectoryEntry']
export type DirectoryList = Schemas['DirectoryList']
export type Rule = Schemas['Rule']
export type RuleSpec = Schemas['RuleSpec']
export type Group = Schemas['Group']
export type GroupSpec = Schemas['GroupSpec']
export type GroupList = Schemas['GroupList']
export type Client = Schemas['Client']
export type ClientSpec = Schemas['ClientSpec']
export type Schedule = Schemas['Schedule']
export type ScheduleSpec = Schemas['ScheduleSpec']
export type Window = Schemas['Window']
export type Weekday = Schemas['Weekday']
export type Settings = Schemas['Settings']
export type SettingsSpec = Schemas['SettingsSpec']
export type BlockResponseKind = Schemas['BlockResponseKind']
export type ManagedBy = Schemas['ManagedBy']
export type AuditEntry = Schemas['AuditEntry']
export type ClusterStatus = Schemas['ClusterStatus']

/** The If-Match header for a change based on `revision`. */
export function ifMatch(revision: number): { 'If-Match': string } {
	return { 'If-Match': `"${revision}"` }
}

/** Every outcome, in display order. */
export const OUTCOMES: readonly QueryOutcome[] = [
	'blocked',
	'safe_search',
	'cached',
	'forwarded',
	'local',
	'rejected',
	'failed',
]

/** An error answer from the API. */
export class ApiError extends Error {
	readonly status: number
	readonly code: string

	constructor(status: number, code: string, message: string) {
		super(message)
		this.name = 'ApiError'
		this.status = status
		this.code = code
	}
}

export const api = createClient<paths>({ baseUrl: '' })

api.use({
	onRequest({ request }) {
		const value = currentToken()
		if (value !== null) {
			request.headers.set('Authorization', `Bearer ${value}`)
		}
		return request
	},
})

type Result<T> =
	| { data: T; error?: never; response: Response }
	| { data?: never; error: unknown; response: Response }

/** The answer's data, or an [ApiError]. */
export async function call<T>(request: Promise<Result<T>>): Promise<T> {
	const result = await request
	if (result.error === undefined && result.response.ok) {
		return result.data as T
	}
	const detail: unknown =
		typeof result.error === 'object' && result.error !== null && 'error' in result.error
			? result.error.error
			: undefined
	const field = (name: string): string | undefined => {
		if (typeof detail === 'object' && detail !== null && name in detail) {
			const value: unknown = (detail as Record<string, unknown>)[name]
			return typeof value === 'string' ? value : undefined
		}
		return undefined
	}
	throw new ApiError(
		result.response.status,
		field('code') ?? 'error',
		field('message') ?? `HTTP ${result.response.status}`,
	)
}

/** A message for any error a query or mutation can end with. */
export function describe(error: unknown): string {
	if (error instanceof ApiError) {
		return error.message
	}
	if (error instanceof TypeError) {
		return 'Cannot reach goethite. Is it running?'
	}
	return error instanceof Error ? error.message : String(error)
}
