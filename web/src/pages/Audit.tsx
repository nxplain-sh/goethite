import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import type { AuditEntry } from '../api/client'
import { AUDIT_PAGE, auditQuery } from '../api/resources'
import { ErrorNotice } from '../components/ui'
import { dateTime } from '../format'

/** Who changed what, newest first. */
export function Audit() {
	// The ID older entries come before; none for the newest page.
	const [before, setBefore] = useState<number | undefined>(undefined)
	const [pages, setPages] = useState<(number | undefined)[]>([])
	const audit = useQuery(auditQuery(before))
	const entries = audit.data ?? []
	const oldest = entries[entries.length - 1]

	return (
		<div className="grid-page">
			<h1>Audit log</h1>
			<p className="muted">
				Every change to lists, rules, local records, groups, clients, schedules and settings: who made it,
				from where, and the resource before and after.
			</p>
			<ErrorNotice error={audit.error} />
			<div className="panel">
				<table className="table">
					<thead>
						<tr>
							<th>When</th>
							<th>Who</th>
							<th>What</th>
							<th>Resource</th>
							<th />
						</tr>
					</thead>
					<tbody>
						{entries.map((entry) => (
							<AuditRow key={entry.id} entry={entry} />
						))}
					</tbody>
				</table>
				{audit.data?.length === 0 ? <p className="muted">Nothing changed yet.</p> : null}
				<div className="actions">
					{before === undefined ? null : (
						<button
							type="button"
							className="button small"
							onClick={() => {
								setBefore(pages[pages.length - 1])
								setPages(pages.slice(0, -1))
							}}
						>
							Newer
						</button>
					)}
					{oldest === undefined || entries.length < AUDIT_PAGE ? null : (
						<button
							type="button"
							className="button small"
							onClick={() => {
								setPages([...pages, before])
								setBefore(oldest.id)
							}}
						>
							Older
						</button>
					)}
				</div>
			</div>
		</div>
	)
}

function actor(entry: AuditEntry): string {
	const parts: string[] = [entry.actor.kind]
	if (entry.actor.address != null) parts.push(entry.actor.address)
	if (entry.actor.node != null) parts.push(`via ${entry.actor.node}`)
	return parts.join(' · ')
}

function AuditRow({ entry }: { entry: AuditEntry }) {
	const [open, setOpen] = useState(false)
	const changed = entry.before != null || entry.after != null
	return (
		<>
			<tr>
				<td className="mono">{dateTime(entry.time)}</td>
				<td>{actor(entry)}</td>
				<td>
					<span className="badge">{entry.action.toUpperCase()}</span>
					{entry.detail == null ? null : <div className="muted">{entry.detail}</div>}
				</td>
				<td>
					{entry.kind == null ? null : <span>{entry.kind} </span>}
					{entry.resource == null ? null : <span className="mono">{entry.resource}</span>}
				</td>
				<td className="actions-cell">
					{changed ? (
						<button
							type="button"
							className="button small"
							aria-expanded={open}
							onClick={() => setOpen(!open)}
						>
							{open ? 'Hide' : 'Show'} change
						</button>
					) : null}
				</td>
			</tr>
			{open ? (
				<tr>
					<td colSpan={5}>
						<div className="change">
							<div>
								<h3>Before</h3>
								<pre>{entry.before == null ? '(none)' : JSON.stringify(entry.before, null, 2)}</pre>
							</div>
							<div>
								<h3>After</h3>
								<pre>{entry.after == null ? '(none)' : JSON.stringify(entry.after, null, 2)}</pre>
							</div>
						</div>
					</td>
				</tr>
			) : null}
		</>
	)
}
