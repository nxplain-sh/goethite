import { Link } from '@tanstack/react-router'
import type { ReactNode } from 'react'

import { type ClusterStatus, describe, type QueryOutcome, type Status } from '../api/client'
import type { LogSearch } from '../api/queries'
import { clock } from '../format'

const OUTCOME: Record<QueryOutcome, { label: string; tone: string }> = {
	blocked: { label: 'BLOCKED', tone: 'blocked' },
	safe_search: { label: 'SAFE SEARCH', tone: 'accent' },
	cached: { label: 'CACHED', tone: 'cached' },
	forwarded: { label: 'FORWARDED', tone: 'ok' },
	local: { label: 'LOCAL', tone: '' },
	rejected: { label: 'REJECTED', tone: 'inverted' },
	failed: { label: 'FAILED', tone: 'inverted' },
}

/** How an answer came about, in words; color only reinforces it. */
export function OutcomeBadge({ outcome }: { outcome: QueryOutcome }) {
	const { label, tone } = OUTCOME[outcome]
	return <span className={`badge ${tone}`}>{label}</span>
}

/** The label for an outcome, for menus. */
export function outcomeLabel(outcome: QueryOutcome): string {
	return OUTCOME[outcome].label
}

/** Whether filtering is on, paused or off. */
export function ProtectionBadge({ status }: { status: Status }) {
	if (status.paused_until != null) {
		return <span className="badge accent">PAUSED UNTIL {clock(status.paused_until)}</span>
	}
	return status.protection ? (
		<span className="badge ok">FILTERING ON</span>
	) : (
		<span className="badge blocked">FILTERING OFF</span>
	)
}

/** What this node does in its cluster, and how many members are up, in words. */
export function ClusterBadges({ cluster }: { cluster: ClusterStatus }) {
	const others = (cluster.members ?? []).filter((member) => !member.this_node)
	const up = others.filter((member) => member.reachable).length
	return (
		<>
			<span className="badge">
				{cluster.node} · {(cluster.state ?? 'unknown').toUpperCase()}
			</span>
			<span className={up === others.length ? 'badge ok' : 'badge blocked'}>
				{up}/{others.length} MEMBERS UP
			</span>
		</>
	)
}

/** A titled box. */
export function Panel({ title, children }: { title: string; children: ReactNode }) {
	return (
		<section className="panel" aria-label={title}>
			<h2>{title}</h2>
			{children}
		</section>
	)
}

/** One number with a label; with `search`, a link to those queries. */
export function Stat({
	label,
	value,
	detail,
	tone,
	search,
}: {
	label: string
	value: string
	detail?: string
	tone?: 'blocked' | 'cached'
	search?: LogSearch
}) {
	const body = (
		<>
			<div className="label">{label}</div>
			<div className="value">{value}</div>
			{detail === undefined ? null : <div className="detail">{detail}</div>}
		</>
	)
	return search === undefined ? (
		<div className={`stat ${tone ?? ''}`}>{body}</div>
	) : (
		<Link to="/querylog" search={search} className={`stat ${tone ?? ''}`}>
			{body}
		</Link>
	)
}

/** An error from a query or mutation, if there is one. */
export function ErrorNotice({ error }: { error: unknown }) {
	if (error === null || error === undefined) {
		return null
	}
	return (
		<div className="notice error" role="alert">
			{describe(error)}
		</div>
	)
}
