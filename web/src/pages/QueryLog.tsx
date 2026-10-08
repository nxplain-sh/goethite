import { useQuery } from '@tanstack/react-query'
import { createColumnHelper, tableFeatures, useTable } from '@tanstack/react-table'
import { useNavigate } from '@tanstack/react-router'
import { useVirtualizer } from '@tanstack/react-virtual'
import { type FormEvent, useRef, useState } from 'react'

import { OUTCOMES, type QueryEntry, type QueryOutcome } from '../api/client'
import { LOG_PAGE, type LogSearch, clientsQuery, queryLogQuery } from '../api/queries'
import { ErrorNotice, OutcomeBadge, outcomeLabel } from '../components/ui'
import { clock, count, millis } from '../format'

const features = tableFeatures({})
const column = createColumnHelper<typeof features, QueryEntry>()
const columns = column.columns([
	column.accessor('time', { header: 'Time', cell: (info) => clock(info.getValue()) }),
	column.accessor('client', { header: 'Client', cell: (info) => <ClientName entry={info.row.original} /> }),
	column.accessor('qtype', { header: 'Type' }),
	column.accessor('name', { header: 'Name' }),
	column.accessor('outcome', {
		header: 'Answer',
		cell: (info) => <OutcomeBadge outcome={info.getValue()} />,
	}),
	column.display({ id: 'detail', header: 'Why', cell: (info) => detail(info.row.original) }),
	column.accessor('elapsed_us', { header: 'Time taken', cell: (info) => millis(info.getValue()) }),
])
const RIGHT_ALIGNED = new Set(['elapsed_us'])
const NO_ROWS: QueryEntry[] = []

/** How a query arrived, as people call it. */
const PROTOCOL_LABEL: Record<QueryEntry['protocol'], string> = {
	udp: 'UDP',
	tcp: 'TCP',
	dot: 'DoT',
	doh: 'DoH',
}

/** A known client's name over its address; just the address otherwise. Encrypted queries say so. */
function ClientName({ entry }: { entry: QueryEntry }) {
	const names = useQuery(clientsQuery).data
	const name = entry.client_id == null ? undefined : names?.get(entry.client_id)
	const via =
		entry.protocol === 'udp' || entry.protocol === 'tcp' ? null : (
			<span className="muted">{` · ${PROTOCOL_LABEL[entry.protocol]}`}</span>
		)
	return name === undefined ? (
		<>
			{entry.client}
			{via}
		</>
	) : (
		<>
			<span className="client-name">{name}</span>
			<br />
			<span className="muted">{entry.client}</span>
			{via}
		</>
	)
}

/** What decided the answer: the rule, CNAME and upstream, as known. */
function detail(entry: QueryEntry): string {
	const parts: string[] = []
	if (entry.rule != null) parts.push(entry.rule)
	if (entry.cname != null) parts.push(`via CNAME ${entry.cname}`)
	if (entry.upstream != null) parts.push(entry.upstream)
	if (entry.rcode !== 'NOERROR') parts.push(entry.rcode)
	return parts.join(' · ')
}

/** The query log, newest first, following new queries live. */
export function QueryLog({ search }: { search: LogSearch }) {
	const navigate = useNavigate({ from: '/querylog' })
	const log = useQuery(queryLogQuery(search))
	const [name, setName] = useState(search.name ?? '')
	const table = useTable({
		features,
		columns,
		data: log.data?.entries ?? NO_ROWS,
		getRowId: (entry) => String(entry.id),
	})
	const rows = table.getRowModel().rows
	const scroller = useRef<HTMLDivElement>(null)
	const virtualizer = useVirtualizer({
		count: rows.length,
		getScrollElement: () => scroller.current,
		estimateSize: () => 30,
		getItemKey: (index) => rows[index]?.id ?? index,
		overscan: 12,
	})
	const live = search.before === undefined
	const older = log.data?.next

	const go = (next: LogSearch) => void navigate({ search: next })
	const submit = (event: FormEvent) => {
		event.preventDefault()
		const trimmed = name.trim()
		const { name: _, before: __, ...rest } = search
		go(trimmed === '' ? rest : { ...rest, name: trimmed })
	}
	const setOutcome = (value: string) => {
		const { outcome: _, before: __, ...rest } = search
		const outcome = OUTCOMES.find((candidate) => candidate === value)
		go(outcome === undefined ? rest : { ...rest, outcome })
	}
	const latest = () => {
		const { before: _, ...rest } = search
		go(rest)
	}

	return (
		<div className="grid-page">
			<h1>Query log</h1>
			<form className="log-tools" onSubmit={submit} role="search">
				<label className="field">
					Name contains
					<input
						className="input"
						type="search"
						value={name}
						spellCheck={false}
						placeholder="ads.example"
						onChange={(event) => setName(event.target.value)}
					/>
				</label>
				<label className="field">
					Answer
					<select
						className="select"
						value={search.outcome ?? ''}
						onChange={(event) => setOutcome(event.target.value)}
					>
						<option value="">All answers</option>
						{OUTCOMES.map((outcome: QueryOutcome) => (
							<option key={outcome} value={outcome}>
								{outcomeLabel(outcome)}
							</option>
						))}
					</select>
				</label>
				<button type="submit" className="button primary">
					Search
				</button>
			</form>
			<ErrorNotice error={log.error} />
			<div className="log">
				<div className="log-scroll" ref={scroller}>
					<div className="log-row head" role="row">
						{table.getHeaderGroups()[0]?.headers.map((header) => (
							<div
								key={header.id}
								role="columnheader"
								className={RIGHT_ALIGNED.has(header.column.id) ? 'cell right' : 'cell'}
							>
								<table.FlexRender header={header} />
							</div>
						))}
					</div>
					<div role="rowgroup" style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
						{virtualizer.getVirtualItems().map((item) => {
							const row = rows[item.index]
							if (row === undefined) return null
							return (
								<div
									key={row.id}
									role="row"
									className="log-row"
									data-index={item.index}
									ref={virtualizer.measureElement}
									style={{ position: 'absolute', top: 0, left: 0, right: 0, transform: `translateY(${item.start}px)` }}
								>
									{row.getAllCells().map((cell) => (
										<div
											key={cell.id}
											role="cell"
											className={RIGHT_ALIGNED.has(cell.column.id) ? 'cell right' : 'cell'}
										>
											<table.FlexRender cell={cell} />
										</div>
									))}
								</div>
							)
						})}
					</div>
					{log.data && rows.length === 0 ? <p className="muted log-empty">No queries match.</p> : null}
				</div>
				<div className="log-footer">
					<span>
						{live ? <span className="badge ok">LIVE</span> : <span className="badge">OLDER</span>}{' '}
						{count(rows.length)} entries{rows.length === LOG_PAGE ? ' (one page)' : ''}
					</span>
					{live ? null : (
						<button type="button" className="button small" onClick={latest}>
							Newest
						</button>
					)}
					{older == null ? null : (
						<button type="button" className="button small" onClick={() => go({ ...search, before: older })}>
							Older
						</button>
					)}
				</div>
			</div>
		</div>
	)
}
