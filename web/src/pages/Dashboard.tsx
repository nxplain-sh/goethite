import { useQuery } from '@tanstack/react-query'

import type { ClusterStatus, StatsReport, Status } from '../api/client'
import { clientsQuery, listsQuery, statsQuery, statusQuery } from '../api/queries'
import { ErrorNotice, Panel, Stat } from '../components/ui'
import { bytes, count, dateTime, millis, percent } from '../format'

const HOURS = 24
const HOUR_MS = 3_600_000

/** Totals, trends, top lists and the node's health. */
export function Dashboard() {
	const stats = useQuery(statsQuery(HOURS))
	const status = useQuery(statusQuery)
	const lists = useQuery(listsQuery)
	const clients = useQuery(clientsQuery)
	const totals = stats.data?.totals

	return (
		<div className="grid-page">
			<h1 className="sr-only">Dashboard</h1>
			<ErrorNotice error={stats.error ?? lists.error} />
			<div className="stats">
				<Stat
					label={(stats.data?.nodes?.length ?? 0) > 1 ? 'Queries, 24 h, cluster' : 'Queries, 24 h'}
					value={totals ? count(totals.queries) : '…'}
					{...(totals && totals.queries > 0
						? { detail: `${millis(totals.elapsed_us / totals.queries)} average` }
						: {})}
				/>
				<Stat
					label="Blocked"
					tone="blocked"
					value={totals ? count(totals.blocked) : '…'}
					{...(totals ? { detail: percent(totals.blocked, totals.queries) } : {})}
				/>
				<Stat
					label="Cached"
					tone="cached"
					value={totals ? count(totals.cached) : '…'}
					{...(totals ? { detail: percent(totals.cached, totals.queries) } : {})}
				/>
				<Stat label="Forwarded" value={totals ? count(totals.forwarded) : '…'} />
				<Stat
					label="Failed"
					value={totals ? count(totals.failed) : '…'}
					{...(totals ? { detail: `${count(totals.safe_search)} safe search` } : {})}
				/>
			</div>
			{stats.data ? (
				<Panel title="Queries per hour">
					<HourChart report={stats.data} />
				</Panel>
			) : null}
			<div className="grid">
				<TopPanel title="Top blocked" entries={stats.data?.top_blocked} />
				<TopPanel title="Top names" entries={stats.data?.top_names} />
				<TopPanel title="Top clients" entries={stats.data?.top_clients} names={clients.data} />
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

/** Queries and blocked queries for each of the last 24 hours. */
function HourChart({ report }: { report: StatsReport }) {
	const end = Date.parse(report.to)
	const first = Math.floor(end / HOUR_MS) * HOUR_MS - (HOURS - 1) * HOUR_MS
	const slots = Array.from({ length: HOURS }, () => ({ queries: 0, blocked: 0 }))
	for (const point of report.hours) {
		const slot = slots[Math.floor((Date.parse(point.start) - first) / HOUR_MS)]
		if (slot) {
			slot.queries = point.counters.queries
			slot.blocked = point.counters.blocked
		}
	}
	const max = Math.max(1, ...slots.map((slot) => slot.queries))
	const width = 24
	const height = 100
	const bar = (value: number) => (value / max) * (height - 4)
	return (
		<>
			<svg
				className="chart"
				viewBox={`0 0 ${HOURS * width} ${height}`}
				preserveAspectRatio="none"
				role="img"
				aria-label={`Queries per hour over the last ${HOURS} hours; the busiest hour had ${count(max)}.`}
			>
				{slots.map((slot, index) => {
					const x = index * width + 3
					return (
						<g key={index}>
							<title>
								{`${dateTime(new Date(first + index * HOUR_MS).toISOString())}: ${count(slot.queries)} queries, ${count(slot.blocked)} blocked`}
							</title>
							<rect className="all" x={x} y={height - bar(slot.queries)} width={width - 6} height={bar(slot.queries)} />
							<rect className="blocked" x={x} y={height - bar(slot.blocked)} width={width - 6} height={bar(slot.blocked)} />
						</g>
					)
				})}
				<line className="axis" x1="0" y1={height} x2={HOURS * width} y2={height} />
			</svg>
			<div className="legend">
				<span className="all">All queries</span>
				<span className="blocked">Blocked</span>
			</div>
		</>
	)
}

function TopPanel({
	title,
	entries,
	names,
}: {
	title: string
	entries: { key: string; count: number }[] | undefined
	names?: Map<string, string> | undefined
}) {
	return (
		<Panel title={title}>
			{entries === undefined ? (
				<p className="muted">Loading…</p>
			) : entries.length === 0 ? (
				<p className="muted">Nothing yet.</p>
			) : (
				<table className="table">
					<tbody>
						{entries.slice(0, 10).map((entry) => (
							<tr key={entry.key}>
								<td className="num">{count(entry.count)}</td>
								<td className="name">{names?.get(entry.key) ?? entry.key}</td>
							</tr>
						))}
					</tbody>
				</table>
			)}
		</Panel>
	)
}

function Upstreams({ status }: { status: Status }) {
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
									<td>{names.get(list.id) ?? list.id}</td>
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
	const { peer } = cluster
	return (
		<Panel title="Cluster">
			<table className="table">
				<tbody>
					<tr>
						<td>This node</td>
						<td className="name">
							{cluster.node} <span className="badge">{cluster.role.toUpperCase()}</span>
						</td>
					</tr>
					<tr>
						<td>Peer</td>
						<td className="name">
							{peer.node}{' '}
							{peer.reachable ? (
								<span className="badge ok">UP</span>
							) : (
								<span className="badge blocked">DOWN</span>
							)}
							{peer.role ? <span className="muted"> {peer.role}</span> : null}
							{peer.error ? <div className="muted">{peer.error}</div> : null}
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
					{cluster.sync?.last_copy ? (
						<tr>
							<td>Last copy</td>
							<td className="name">{dateTime(cluster.sync.last_copy)}</td>
						</tr>
					) : null}
				</tbody>
			</table>
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
