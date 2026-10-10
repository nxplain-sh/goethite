import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from '@tanstack/react-router'
import { Suspense, lazy, useMemo, useState } from 'react'

import type { ClusterStatus, Status } from '../api/client'
import { type LogSearch, clientsQuery, listsQuery, statsQuery, statusQuery } from '../api/queries'
import { saveRule } from '../api/resources'
import { HEALTH, health } from '../cluster/health'
import { ErrorBoundary } from '../components/ErrorBoundary'
import { type Bucket, buckets } from '../dashboard/buckets'
import { ErrorNotice, Panel, Stat } from '../components/ui'
import { bytes, count, dateTime, millis, percent } from '../format'

/** The time ranges the dashboard shows, and the size of each bar. */
export const RANGES = [
	{ id: '24h', label: '24 hours', short: '24 h', hours: 24, each: 1, per: 'hour' },
	{ id: '7d', label: '7 days', short: '7 days', hours: 168, each: 6, per: '6 hours' },
	{ id: '30d', label: '30 days', short: '30 days', hours: 720, each: 24, per: 'day' },
] as const

export type RangeId = (typeof RANGES)[number]['id']

/** Totals, trends, top lists and the node's health, over a time range. */
export function Dashboard({ range: rangeId }: { range: RangeId | undefined }) {
	const range = RANGES.find((candidate) => candidate.id === rangeId) ?? RANGES[0]
	const stats = useQuery(statsQuery(range.hours))
	const status = useQuery(statusQuery)
	const lists = useQuery(listsQuery)
	const clients = useQuery(clientsQuery)
	const navigate = useNavigate()
	const totals = stats.data?.totals
	const from = stats.data?.from
	// The query log over the same range, narrowed by `filter`.
	const log = (filter: LogSearch): LogSearch => ({ ...(from === undefined ? {} : { since: from }), ...filter })
	const cluster = (stats.data?.nodes?.length ?? 0) > 1 ? ', cluster' : ''
	// Kept between renders: the chart redraws when its data changes.
	const report = stats.data
	const series = useMemo(
		() => (report === undefined ? undefined : buckets(report, range.hours, range.each)),
		[report, range],
	)

	return (
		<div className="grid-page">
			<div className="page-head">
				<h1 className="sr-only">Dashboard</h1>
				<nav className="segmented" aria-label="Time range">
					{RANGES.map((candidate) => (
						<Link
							key={candidate.id}
							to="/"
							search={candidate.id === '24h' ? {} : { range: candidate.id }}
							aria-current={candidate.id === range.id ? 'true' : undefined}
						>
							{candidate.label}
						</Link>
					))}
				</nav>
			</div>
			<ErrorNotice error={stats.error ?? lists.error} />
			<div className="stats">
				<Stat
					label={`Queries, ${range.short}${cluster}`}
					value={totals ? count(totals.queries) : '…'}
					search={log({})}
					{...(totals && totals.queries > 0
						? { detail: `${millis(totals.elapsed_us / totals.queries)} average` }
						: {})}
				/>
				<Stat
					label="Blocked"
					tone="blocked"
					value={totals ? count(totals.blocked) : '…'}
					search={log({ outcome: 'blocked' })}
					{...(totals ? { detail: percent(totals.blocked, totals.queries) } : {})}
				/>
				<Stat
					label="Cached"
					tone="cached"
					value={totals ? count(totals.cached) : '…'}
					search={log({ outcome: 'cached' })}
					{...(totals ? { detail: percent(totals.cached, totals.queries) } : {})}
				/>
				<Stat
					label="Forwarded"
					value={totals ? count(totals.forwarded) : '…'}
					search={log({ outcome: 'forwarded' })}
				/>
				<Stat
					label="Failed"
					value={totals ? count(totals.failed) : '…'}
					search={log({ outcome: 'failed' })}
					{...(totals ? { detail: `${count(totals.safe_search)} safe search` } : {})}
				/>
			</div>
			{series ? (
				<Panel title={`Queries per ${range.per}`}>
					<TimeChart
						data={series}
						range={range.label}
						onOpen={(bucket) =>
							void navigate({
								to: '/querylog',
								search: { since: bucket.start.toISOString(), until: bucket.end.toISOString() },
							})
						}
					/>
				</Panel>
			) : null}
			<div className="grid">
				<TopPanel
					title="Top blocked"
					entries={stats.data?.top_blocked}
					search={(key) => log({ name: host(key), outcome: 'blocked' })}
					action={{ label: 'Allow', verb: 'Allow', rule: (name) => `@@||${name}^` }}
				/>
				<TopPanel
					title="Top names"
					entries={stats.data?.top_names}
					search={(key) => log({ name: host(key) })}
					action={{ label: 'Block', verb: 'Block', rule: (name) => `||${name}^` }}
				/>
				<TopPanel
					title="Top clients"
					entries={stats.data?.top_clients}
					names={clients.data}
					search={(key) => log({ client: key })}
				/>
			</div>
			{(stats.data?.unreachable?.length ?? 0) > 0 ? (
				<div className="notice">
					Counts from {stats.data?.unreachable?.join(', ')} are missing: it could not be reached.
				</div>
			) : null}
			{status.data ? (
				<div className="grid">
					{status.data.cluster ? <ClusterPanel cluster={status.data.cluster} /> : null}
					<Upstreams status={status.data} />
					<Filter status={status.data} names={listNames(lists.data)} />
					<Node status={status.data} />
				</div>
			) : null}
		</div>
	)
}

function listNames(lists: { id: string; spec: { name: string } }[] | undefined): Map<string, string> {
	return new Map((lists ?? []).map((list) => [list.id, list.spec.name]))
}

/** A name from the statistics without its final dot: `ads.example`. */
function host(name: string): string {
	return name.endsWith('.') ? name.slice(0, -1) : name
}

// The chart library loads after the rest of the dashboard.
const QueriesChart = lazy(() => import('../components/QueriesChart'))

/** The chart, with a summary for screen readers and a hint for everyone. */
function TimeChart({ data, range, onOpen }: { data: Bucket[]; range: string; onOpen: (bucket: Bucket) => void }) {
	const busiest = data.reduce<Bucket | undefined>(
		(best, bucket) => (best === undefined || bucket.queries > best.queries ? bucket : best),
		undefined,
	)
	const total = data.reduce((sum, bucket) => sum + bucket.queries, 0)
	const description =
		busiest === undefined || total === 0
			? `No queries in the last ${range}.`
			: `${count(total)} queries in the last ${range}; the busiest was ${busiest.title} with ${count(busiest.queries)}.`
	return (
		<>
			<ErrorBoundary fallback={<p className="muted">The chart cannot be shown: {description}</p>}>
				<Suspense fallback={<div className="chart-placeholder" aria-busy="true" />}>
					<QueriesChart data={data} description={description} onOpen={onOpen} />
				</Suspense>
			</ErrorBoundary>
			<div className="legend">
				<span className="all">All queries</span>
				<span className="blocked">Blocked</span>
				<span className="hint">Click a bar to see its queries.</span>
			</div>
		</>
	)
}

/** What a top list's rows can do, besides opening the query log. */
interface QuickRule {
	label: string
	verb: string
	rule: (name: string) => string
}

function TopPanel({
	title,
	entries,
	names,
	search,
	action,
}: {
	title: string
	entries: { key: string; count: number }[] | undefined
	names?: Map<string, string> | undefined
	search: (key: string) => LogSearch
	action?: QuickRule
}) {
	return (
		<Panel title={title}>
			{entries === undefined ? (
				<p className="muted">Loading…</p>
			) : entries.length === 0 ? (
				<p className="muted">Nothing yet.</p>
			) : (
				<table className="table top">
					<tbody>
						{entries.slice(0, 10).map((entry) => (
							<TopRow
								key={entry.key}
								count={entry.count}
								label={names?.get(entry.key) ?? host(entry.key)}
								search={search(entry.key)}
								name={host(entry.key)}
								action={action}
							/>
						))}
					</tbody>
				</table>
			)}
		</Panel>
	)
}

/**
 * One entry of a top list: its count and a link to its queries, and its
 * quick rule, asked for in a row of its own so the columns keep their
 * widths.
 */
function TopRow({
	count: hits,
	label,
	search,
	name,
	action,
}: {
	count: number
	label: string
	search: LogSearch
	name: string
	action: QuickRule | undefined
}) {
	const queryClient = useQueryClient()
	const [asking, setAsking] = useState(false)
	const rule = action?.rule(name) ?? ''
	const add = useMutation({
		mutationFn: () =>
			saveRule(undefined, { rule, enabled: true, comment: 'Added from the dashboard.', managed_by: 'api' }),
		onSuccess: async () => {
			await queryClient.invalidateQueries({ queryKey: ['rules'] })
			await queryClient.invalidateQueries({ queryKey: ['status'] })
		},
	})
	const columns = action === undefined ? 2 : 3
	return (
		<>
			<tr>
				<td className="num">{count(hits)}</td>
				<td className="name">
					<Link to="/querylog" search={search}>
						{label}
					</Link>
				</td>
				{action === undefined ? null : (
					<td className="actions-cell">
						{add.isSuccess ? (
							<span className="badge ok">ADDED</span>
						) : (
							<button
								type="button"
								className="button small"
								aria-expanded={asking}
								onClick={() => setAsking(!asking)}
							>
								{action.label}
							</button>
						)}
					</td>
				)}
			</tr>
			{action !== undefined && (asking || add.isSuccess) ? (
				<tr className="follow-up">
					<td colSpan={columns}>
						{add.isSuccess ? (
							<span role="status">
								Added the rule <Link to="/rules">{rule}</Link>.
							</span>
						) : (
							<div className="quick-rule" role="group" aria-label={`${action.verb} ${name}?`}>
								<span className="mono">{rule}</span>
								<button
									type="button"
									className="button small primary"
									disabled={add.isPending}
									onClick={() => add.mutate()}
								>
									{`${action.verb} ${name}`}
								</button>
								<button type="button" className="button small" onClick={() => setAsking(false)}>
									Cancel
								</button>
							</div>
						)}
						<ErrorNotice error={add.error} />
					</td>
				</tr>
			) : null}
		</>
	)
}

function Upstreams({ status }: { status: Status }) {
	if (status.recursion != null) {
		return <Recursion recursion={status.recursion} />
	}
	return (
		<Panel title="Upstreams">
			<table className="table">
				<thead>
					<tr>
						<th>Address</th>
						<th>Protocol</th>
						<th>State</th>
					</tr>
				</thead>
				<tbody>
					{status.upstreams.map((upstream) => (
						<tr key={upstream.address}>
							<td className="name">{upstream.address}</td>
							<td>{upstream.protocol.toUpperCase()}</td>
							<td>
								{upstream.healthy ? (
									<span className="badge ok">UP</span>
								) : (
									<span className="badge blocked">DOWN · {upstream.consecutive_failures} failures</span>
								)}
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</Panel>
	)
}

/** Resolving from the root servers down, instead of asking upstreams. */
function Recursion({ recursion }: { recursion: NonNullable<Status['recursion']> }) {
	return (
		<Panel title="Recursion">
			<p>
				Resolving from the root servers down
				{recursion.qname_minimisation ? ', showing each server as little of a name as it needs' : ''}
				{recursion.ipv6 ? ', over IPv4 and IPv6' : ', over IPv4'}.
			</p>
			<dl className="setup">
				<dt>Queries sent</dt>
				<dd className="mono">
					{count(recursion.sent)} ({count(recursion.tcp)} over TCP)
				</dd>
				<dt>Timed out</dt>
				<dd className="mono">{count(recursion.timeouts)}</dd>
				<dt>Unresolved</dt>
				<dd className="mono">{count(recursion.failures)}</dd>
				<dt>DNSSEC</dt>
				<dd className="mono">
					{recursion.dnssec
						? `${count(recursion.secure ?? 0)} secure, ${count(recursion.insecure ?? 0)} insecure, ${count(recursion.bogus ?? 0)} bogus`
						: 'not validated'}
				</dd>
				<dt>Known</dt>
				<dd className="mono">
					{count(recursion.zones)} zones, {count(recursion.servers)} servers
				</dd>
			</dl>
		</Panel>
	)
}

function Filter({ status, names }: { status: Status; names: Map<string, string> }) {
	return (
		<Panel title="Filter">
			<p>
				<strong className="mono">{count(status.filter.rules)}</strong> rules in{' '}
				<span className="mono">{bytes(status.filter.memory_bytes)}</span>
			</p>
			{status.lists.length === 0 ? (
				<p className="muted">No filter lists: only custom rules apply.</p>
			) : (
				<table className="table">
					<thead>
						<tr>
							<th>List</th>
							<th>Rules</th>
							<th>State</th>
						</tr>
					</thead>
					<tbody>
						{status.lists.map((list) => {
							const problem = list.error ?? list.download_error
							return (
								<tr key={list.id}>
									<td>
										<Link to="/lists/$id" params={{ id: list.id }}>
											{names.get(list.id) ?? list.id}
										</Link>
									</td>
									<td className="num">{list.rules == null ? '–' : count(list.rules)}</td>
									<td>
										{problem == null ? (
											<span className="badge ok">OK</span>
										) : (
											<span className="badge blocked" title={problem}>
												PROBLEM
											</span>
										)}
										{problem == null ? null : <div className="muted">{problem}</div>}
									</td>
								</tr>
							)
						})}
					</tbody>
				</table>
			)}
		</Panel>
	)
}

function ClusterPanel({ cluster }: { cluster: ClusterStatus }) {
	const { label, tone } = HEALTH[health(cluster)]
	return (
		<Panel title="Cluster">
			<table className="table">
				<tbody>
					<tr>
						<td>Health</td>
						<td>
							<span className={`badge ${tone}`}>{label}</span>
						</td>
					</tr>
					<tr>
						<td>Leader</td>
						<td className="name">
							{cluster.leader ?? <span className="badge blocked">NONE</span>}
						</td>
					</tr>
					<tr>
						<td>Changes</td>
						<td>
							{cluster.writable ? (
								<span className="badge ok">WRITABLE</span>
							) : (
								<span className="badge blocked">READ-ONLY</span>
							)}
						</td>
					</tr>
					{(cluster.members ?? []).map((member) => (
						<tr key={member.node}>
							<td className="name">
								{member.node}
								{member.this_node ? <span className="muted"> (this node)</span> : null}
							</td>
							<td>
								{member.reachable ? (
									<span className="badge ok">UP</span>
								) : (
									<span className="badge blocked">DOWN</span>
								)}{' '}
								{member.state ? <span className="badge">{member.state.toUpperCase()}</span> : null}{' '}
								{member.witness ? <span className="badge">WITNESS</span> : null}{' '}
								<span className="muted">
									{member.membership === 'configured' ? 'not in the cluster yet' : member.membership}
								</span>
								{member.error ? <div className="muted">{member.error}</div> : null}
							</td>
						</tr>
					))}
					{cluster.sync?.last_copy ? (
						<tr>
							<td>Last change</td>
							<td className="name">{dateTime(cluster.sync.last_copy)}</td>
						</tr>
					) : null}
				</tbody>
			</table>
			<Link to="/cluster" className="button small panel-link">
				Open the cluster
			</Link>
		</Panel>
	)
}

function Node({ status }: { status: Status }) {
	const cache = status.cache
	return (
		<Panel title="Node">
			<table className="table">
				<tbody>
					<tr>
						<td>Running since</td>
						<td className="name">{dateTime(status.started_at)}</td>
					</tr>
					{cache == null ? null : (
						<tr>
							<td>Cache</td>
							<td className="name">
								{count(cache.entries)} entries, {percent(cache.hits, cache.hits + cache.misses)} hits
							</td>
						</tr>
					)}
					<tr>
						<td>Query log</td>
						<td className="name">
							{status.query_log.enabled ? `${count(status.query_log.entries)} entries` : 'off'}
							{status.query_log.dropped > 0 ? `, ${count(status.query_log.dropped)} dropped` : ''}
						</td>
					</tr>
				</tbody>
			</table>
		</Panel>
	)
}
