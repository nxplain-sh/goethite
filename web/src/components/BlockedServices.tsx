import { useQuery } from '@tanstack/react-query'
import { useId, useState } from 'react'

import type { Schedule, Service } from '../api/client'
import { servicesQuery } from '../api/queries'
import type { BlockedServiceForm } from '../forms/forms'
import { count, dateTime } from '../format'
import { ErrorNotice } from './ui'

/** What the catalog's kinds of service are called. */
const KIND_LABEL: Record<string, string> = {
	ai: 'AI',
	cdn: 'CDNs',
	dating: 'Dating',
	gambling: 'Gambling',
	gaming: 'Gaming',
	hosting: 'Hosting',
	messenger: 'Messengers',
	privacy: 'Privacy',
	shopping: 'Shopping',
	social_network: 'Social networks',
	software: 'Software',
	streaming: 'Streaming',
	other: 'Other',
}

/** A kind of service, as people call it. */
export function kindLabel(kind: string): string {
	const known = KIND_LABEL[kind]
	if (known !== undefined) return known
	const words = kind.replaceAll('_', ' ')
	return words.charAt(0).toUpperCase() + words.slice(1)
}

/** The services in `services`, by kind, kinds by label. */
function byKind(services: Service[]): [string, Service[]][] {
	const kinds = new Map<string, Service[]>()
	for (const service of services) {
		kinds.set(service.group, [...(kinds.get(service.group) ?? []), service])
	}
	return [...kinds].sort(([a], [b]) => kindLabel(a).localeCompare(kindLabel(b)))
}

/** The services a group blocks: toggles by kind, each blocked always or during a schedule. */
export function BlockedServices({
	value,
	onChange,
	schedules,
}: {
	value: BlockedServiceForm[]
	onChange: (value: BlockedServiceForm[]) => void
	schedules: Schedule[]
}) {
	const catalog = useQuery(servicesQuery)
	const [search, setSearch] = useState('')
	const id = useId()
	const services = catalog.data?.services ?? []
	const named = new Map(services.map((service) => [service.id, service.name]))
	const blocked = new Set(value.map((entry) => entry.service))
	// One row per service, in the order they were blocked.
	const rows = [...blocked]
	const needle = search.trim().toLowerCase()
	const shown = services.filter(
		(service) =>
			needle === '' ||
			service.name.toLowerCase().includes(needle) ||
			kindLabel(service.group).toLowerCase().includes(needle),
	)

	const toggle = (service: string, on: boolean) =>
		onChange(on ? [...value, { service, schedule: '' }] : value.filter((entry) => entry.service !== service))
	const setWhen = (service: string, schedule: string) => {
		// One entry for the service, during the chosen schedule.
		const first = value.findIndex((entry) => entry.service === service)
		onChange(
			value.flatMap((entry, at) =>
				entry.service !== service ? [entry] : at === first ? [{ service, schedule }] : [],
			),
		)
	}

	return (
		<fieldset className="subform">
			<legend>Blocked services</legend>
			<p className="muted">
				Blocks every name a service uses, whatever the lists say, while the group is filtered.
			</p>
			<ErrorNotice error={catalog.error} />
			{catalog.isPending ? <p className="muted">Loading the services…</p> : null}
			{rows.length === 0 ? (
				<p className="muted">No blocked services.</p>
			) : (
				<table className="table">
					<thead>
						<tr>
							<th>Blocked</th>
							<th>When</th>
							<th>
								<span className="sr-only">Actions</span>
							</th>
						</tr>
					</thead>
					<tbody>
						{rows.map((service) => {
							const entries = value.filter((entry) => entry.service === service)
							const name = named.get(service)
							return (
								<tr key={service}>
									<td>
										{name ?? <span className="mono">{service}</span>}
										{name === undefined && catalog.data !== undefined ? (
											<div className="hint">Not in the catalog: blocks nothing.</div>
										) : null}
									</td>
									<td>
										<select
											className="select"
											aria-label={`When ${name ?? service} is blocked`}
											value={entries[0]?.schedule ?? ''}
											onChange={(event) => setWhen(service, event.target.value)}
										>
											<option value="">Always</option>
											{schedules.map((schedule) => (
												<option key={schedule.id} value={schedule.id}>
													During {schedule.spec.name}
												</option>
											))}
										</select>
										{entries.length > 1 ? (
											<div className="hint">and during {count(entries.length - 1)} more</div>
										) : null}
									</td>
									<td className="actions-cell">
										<button
											type="button"
											className="button small"
											aria-label={`Unblock ${name ?? service}`}
											onClick={() => toggle(service, false)}
										>
											Unblock
										</button>
									</td>
								</tr>
							)
						})}
					</tbody>
				</table>
			)}
			{catalog.data === undefined ? null : (
				<>
					<div className="field">
						<label htmlFor={`${id}-search`}>Find a service</label>
						<input
							id={`${id}-search`}
							className="input sans"
							type="search"
							value={search}
							spellCheck={false}
							autoComplete="off"
							placeholder="TikTok, gaming…"
							onChange={(event) => setSearch(event.target.value)}
						/>
					</div>
					{shown.length === 0 ? <p className="muted">No service matches.</p> : null}
					{byKind(shown).map(([kind, members]) => (
						<div key={kind} className="services">
							<h3>{kindLabel(kind)}</h3>
							<ul>
								{members.map((service) => (
									<li key={service.id}>
										<label className="check">
											<input
												type="checkbox"
												checked={blocked.has(service.id)}
												onChange={(event) => toggle(service.id, event.target.checked)}
											/>
											{service.name}
										</label>
									</li>
								))}
							</ul>
						</div>
					))}
					<p className="hint">
						{count(services.length)} services from{' '}
						<a
							href="https://github.com/AdguardTeam/HostlistsRegistry"
							target="_blank"
							rel="noreferrer noopener"
						>
							AdGuard's HostlistsRegistry
						</a>{' '}
						({catalog.data.license}),{' '}
						{catalog.data.source.startsWith('https://')
							? 'which this node downloads with the lists'
							: `which this node reads from ${catalog.data.source}`}
						{catalog.data.downloaded_at == null
							? ''
							: `; this copy is from ${dateTime(catalog.data.downloaded_at)}`}
						.
					</p>
					{catalog.data.error == null ? null : (
						<p className="hint">The last download failed: {catalog.data.error}</p>
					)}
					{services.length === 0 && catalog.data.error == null ? (
						<p className="muted">This node has not downloaded the catalog yet.</p>
					) : null}
				</>
			)}
		</fieldset>
	)
}
