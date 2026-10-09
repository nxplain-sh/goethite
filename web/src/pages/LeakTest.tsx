import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { api, call } from '../api/client'
import { allClientsQuery, groupsQuery } from '../api/resources'
import { ErrorNotice } from '../components/ui'
import { PROTOCOL_LABEL, clock, dateTime } from '../format'
import { type LeakTest as Test, type Verdict, distinct, fromElsewhere, host, verdict } from '../forms/leak'

/** How long one image may take to load or fail. */
const PROBE_TIMEOUT_MS = 5_000

/** How long the result is polled for lookups that arrive late. */
const POLLS = 10

/**
 * Loads `url` as an image, which makes the browser look its host up:
 * settles when it loads, fails (as it will: no one answers for the name),
 * or after a while.
 */
function probe(url: string): Promise<void> {
	return new Promise((resolve) => {
		const image = new Image()
		const timer = window.setTimeout(resolve, PROBE_TIMEOUT_MS)
		const done = () => {
			window.clearTimeout(timer)
			resolve()
		}
		image.onload = done
		image.onerror = done
		image.referrerPolicy = 'no-referrer'
		image.src = url
	})
}

/** Starts a test and has this browser look up its names. */
async function runTest(): Promise<Test> {
	const test = await call(api.POST('/api/v1/leak-tests'))
	const scheme = window.location.protocol === 'https:' ? 'https:' : 'http:'
	await Promise.all(test.names.map((name, i) => probe(`${scheme}//${host(name)}/goethite-leak-test.gif?${i}`)))
	return test
}

const leakTestQuery = (id: string) => ({
	queryKey: ['leak-tests', id],
	queryFn: () => call(api.GET('/api/v1/leak-tests/{id}', { params: { path: { id } } })),
})

/** Whether this device's lookups reach goethite: the DNS leak test. */
export function LeakTest() {
	const queryClient = useQueryClient()
	const [shown, setShown] = useState<string | null>(null)
	const run = useMutation({
		mutationFn: runTest,
		onSuccess: (test) => {
			setShown(test.id)
			void queryClient.invalidateQueries({ queryKey: ['leak-tests'] })
		},
	})
	const result = useQuery({
		...leakTestQuery(shown ?? ''),
		enabled: shown !== null,
		// Lookups can arrive a little late: look again for a while.
		refetchInterval: (query) => (query.state.dataUpdateCount < POLLS ? 2_000 : false),
	})
	const recent = useQuery({
		queryKey: ['leak-tests'],
		queryFn: () => call(api.GET('/api/v1/leak-tests')),
		refetchInterval: 10_000,
	})
	const clients = useQuery(allClientsQuery)
	const groups = useQuery(groupsQuery)
	const names = {
		client: new Map((clients.data ?? []).map((client) => [client.id, client.spec.name])),
		group: new Map((groups.data ?? []).map((group) => [group.id, group.spec.name])),
	}

	return (
		<div className="grid-page">
			<h1>DNS leak test</h1>
			<p className="muted">
				Checks whether this device&apos;s lookups reach goethite. The browser looks up eight names that only
				goethite answers; the ones that arrive show how this device reaches goethite. Names that never
				arrive were asked of another resolver: a leak, past goethite&apos;s filtering.
			</p>
			<div className="panel">
				<p>
					Run it on the device you want to check, in the browser you use there. To check another device,
					open this page on it.
				</p>
				<div className="actions">
					<button type="button" className="button" disabled={run.isPending} onClick={() => run.mutate()}>
						{run.isPending ? 'Looking names up…' : shown === null ? 'Run the test' : 'Run it again'}
					</button>
				</div>
			</div>
			<ErrorNotice error={run.error ?? result.error ?? recent.error} />
			{result.data === undefined || run.isPending ? null : <Result test={result.data} names={names} />}
			<Recent tests={recent.data?.tests ?? []} shown={shown} onShow={setShown} />
		</div>
	)
}

type Names = { client: Map<string, string>; group: Map<string, string> }

const VERDICT: Record<Verdict, { badge: string; label: string }> = {
	none: { badge: 'blocked', label: 'LEAK' },
	partial: { badge: 'blocked', label: 'PARTIAL LEAK' },
	all: { badge: 'ok', label: 'NO LEAK' },
}

function Result({ test, names }: { test: Test; names: Names }) {
	const outcome = verdict(test)
	const elsewhere = fromElsewhere(test)
	const protocols = distinct(test.lookups, (lookup) => PROTOCOL_LABEL[lookup.protocol])
	const addresses = distinct(test.lookups, (lookup) => lookup.address)
	const clients = distinct(test.lookups, (lookup) => lookup.client ?? null).map(
		(id) => names.client.get(id) ?? id,
	)
	const groups = distinct(test.lookups, (lookup) => lookup.group ?? null).map((id) => names.group.get(id) ?? id)
	const filtering = distinct(test.lookups, (lookup) => lookup.filtering)
	return (
		<section className="panel" aria-label="Result">
			<h2>
				<span className={`badge ${VERDICT[outcome].badge}`}>{VERDICT[outcome].label}</span>{' '}
				{test.reached} of {test.names.length} lookups reached goethite
			</h2>
			<Explanation outcome={outcome} />
			{test.lookups.length === 0 ? null : (
				<dl className="setup">
					<dt>Over</dt>
					<dd>{protocols.join(', ')}</dd>
					<dt>From</dt>
					<dd className="mono">{addresses.join(', ')}</dd>
					<dt>As</dt>
					<dd>
						{clients.length === 0 ? 'no known client' : clients.join(', ')}, in{' '}
						{groups.length === 0 ? 'no group' : `the group ${groups.join(', ')}`}
					</dd>
					<dt>Filtering</dt>
					<dd>
						{filtering.includes(true)
							? filtering.includes(false)
								? 'on for some of the lookups'
								: 'on'
							: 'off: the group does not filter, or protection is off or paused'}
					</dd>
				</dl>
			)}
			{elsewhere !== null && elsewhere.length > 0 ? (
				<p className="notice">
					The lookups came from {elsewhere.join(', ')}, while this browser reached goethite&apos;s web UI
					from {test.requested_by}. That may be this device&apos;s other address; if it is not, something in
					between, often the router, forwards its lookups. goethite then sees every device behind it as one
					client, and cannot filter them apart: set the devices&apos; DNS to goethite itself.
				</p>
			) : null}
			{test.lookups.length === 0 ? null : (
				<table className="table">
					<thead>
						<tr>
							<th>Time</th>
							<th>Name</th>
							<th>Type</th>
							<th>Over</th>
							<th>From</th>
						</tr>
					</thead>
					<tbody>
						{test.lookups.map((lookup, i) => (
							<tr key={`${lookup.probe}-${lookup.qtype}-${i}`}>
								<td className="mono">{clock(lookup.time)}</td>
								<td className="mono">
									{lookup.probe} of {test.names.length}
								</td>
								<td className="mono">{lookup.qtype}</td>
								<td>{PROTOCOL_LABEL[lookup.protocol]}</td>
								<td className="mono">{lookup.address}</td>
							</tr>
						))}
					</tbody>
				</table>
			)}
		</section>
	)
}

function Explanation({ outcome }: { outcome: Verdict }) {
	switch (outcome) {
		case 'all':
			return (
				<p>
					Every lookup reached goethite: this browser&apos;s lookups are filtered as shown here. A browser
					that asks another resolver first and only falls back to the system&apos;s for names it cannot find
					would pass too, since the test names exist nowhere else.
				</p>
			)
		case 'partial':
			return (
				<p>
					Some lookups went to another resolver. Usually the device or the router has a second DNS server
					besides goethite, and the device asks both: remove the other one, or make it another goethite
					node.
				</p>
			)
		case 'none':
			return (
				<p>
					None of the lookups reached goethite, so this browser asks another resolver. Common causes: secure
					DNS (DNS over HTTPS) turned on in the browser, a VPN, or DNS servers set on the device. Turn them
					off or point them at goethite; a browser&apos;s secure DNS can use goethite&apos;s own DNS over HTTPS.
				</p>
			)
	}
}

function Recent({ tests, shown, onShow }: { tests: Test[]; shown: string | null; onShow: (id: string) => void }) {
	if (tests.length === 0) {
		return null
	}
	return (
		<section className="panel" aria-label="Recent tests">
			<h2>Recent tests</h2>
			<p className="muted">Tests from any device in the last hour, kept on this node only.</p>
			<table className="table">
				<thead>
					<tr>
						<th>When</th>
						<th>Started from</th>
						<th>Reached</th>
						<th />
					</tr>
				</thead>
				<tbody>
					{tests.map((test) => (
						<tr key={test.id}>
							<td>{dateTime(test.created_at)}</td>
							<td className="mono">{test.requested_by ?? 'unknown'}</td>
							<td>
								<span className={`badge ${VERDICT[verdict(test)].badge}`}>{VERDICT[verdict(test)].label}</span>{' '}
								{test.reached} of {test.names.length}
							</td>
							<td className="actions-cell">
								{test.id === shown ? null : (
									<button type="button" className="button small" onClick={() => onShow(test.id)}>
										Show
									</button>
								)}
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</section>
	)
}
