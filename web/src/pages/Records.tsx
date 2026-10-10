import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { type FormEvent, useState } from 'react'

import type { DnsRecord, RecordKind } from '../api/client'
import { deleteRecord, recordQuery, recordsQuery, saveRecord } from '../api/resources'
import { DeleteButton, Editor, Loading, ManagedBadge } from '../components/editor'
import { CheckField, SelectField, TextField } from '../components/form'
import { ErrorNotice } from '../components/ui'
import {
	isRecordTtl,
	recordForm,
	type RecordForm,
	recordSpec,
	recordValueHint,
} from '../forms/forms'
import { count } from '../format'

const KINDS: readonly { value: RecordKind; label: string }[] = [
	{ value: 'A', label: 'A (IPv4 address)' },
	{ value: 'AAAA', label: 'AAAA (IPv6 address)' },
	{ value: 'CNAME', label: 'CNAME (another name)' },
]

/** Local DNS records: names goethite answers itself, for every client. */
export function Records() {
	const records = useQuery(recordsQuery)
	const [filter, setFilter] = useState('')
	const needle = filter.trim().toLowerCase()
	const matching = (records.data ?? []).filter(
		(record) =>
			needle === '' ||
			record.spec.name.includes(needle) ||
			record.spec.value.toLowerCase().includes(needle) ||
			(record.spec.comment ?? '').toLowerCase().includes(needle),
	)
	return (
		<div className="grid-page">
			<h1>Local records</h1>
			<p className="muted">
				Names goethite answers itself, for every client and before any filter: devices on your network,
				such as <span className="mono">nas.lan</span>, or every name below one, such as{' '}
				<span className="mono">*.home.example</span>. A name with records answers only from them.
			</p>
			<AddRecord />
			<ErrorNotice error={records.error} />
			<div className="panel">
				<div className="page-head">
					<label className="field grow">
						Filter
						<input
							className="input"
							type="search"
							value={filter}
							spellCheck={false}
							placeholder="nas"
							onChange={(event) => setFilter(event.target.value)}
						/>
					</label>
					<span className="muted">
						{count(matching.length)} of {count(records.data?.length ?? 0)} records
					</span>
				</div>
				<table className="table">
					<thead>
						<tr>
							<th>Name</th>
							<th>Type</th>
							<th>Value</th>
							<th>On</th>
							<th />
						</tr>
					</thead>
					<tbody>
						{matching.map((record) => (
							<RecordRow key={record.id} record={record} />
						))}
					</tbody>
				</table>
				{records.data?.length === 0 ? <p className="muted">No local records yet.</p> : null}
			</div>
		</div>
	)
}

function AddRecord() {
	const queryClient = useQueryClient()
	const [form, setForm] = useState<RecordForm>(() => recordForm())
	const add = useMutation({
		mutationFn: () => saveRecord(undefined, recordSpec(form)),
		onSuccess: async () => {
			setForm(recordForm())
			await queryClient.invalidateQueries({ queryKey: ['records'] })
		},
	})
	const ready = form.name.trim() !== '' && form.value.trim() !== ''
	const submit = (event: FormEvent) => {
		event.preventDefault()
		if (ready) add.mutate()
	}
	return (
		<form className="panel add-form" onSubmit={submit}>
			<label className="field grow">
				Name
				<input
					className="input"
					value={form.name}
					spellCheck={false}
					autoComplete="off"
					placeholder="nas.lan"
					onChange={(event) => setForm({ ...form, name: event.target.value })}
				/>
			</label>
			<label className="field">
				Type
				<select
					className="select"
					value={form.kind}
					onChange={(event) => {
						const kind = KINDS.find((option) => option.value === event.target.value)?.value
						if (kind !== undefined) setForm({ ...form, kind })
					}}
				>
					{KINDS.map((option) => (
						<option key={option.value} value={option.value}>
							{option.value}
						</option>
					))}
				</select>
			</label>
			<label className="field grow">
				Value
				<input
					className="input"
					value={form.value}
					spellCheck={false}
					autoComplete="off"
					placeholder={form.kind === 'CNAME' ? 'nas.lan' : form.kind === 'AAAA' ? 'fd00::10' : '192.168.1.10'}
					onChange={(event) => setForm({ ...form, value: event.target.value })}
				/>
			</label>
			<button type="submit" className="button primary" disabled={add.isPending || !ready}>
				Add
			</button>
			<ErrorNotice error={add.error} />
		</form>
	)
}

function RecordRow({ record }: { record: DnsRecord }) {
	const queryClient = useQueryClient()
	const refresh = () => queryClient.invalidateQueries({ queryKey: ['records'] })
	const enabled = record.spec.enabled ?? true
	const [pending, setPending] = useState<boolean | undefined>(undefined)
	const toggle = useMutation({
		mutationFn: () => saveRecord(record, { ...record.spec, enabled: !enabled }),
		onSettled: async () => {
			await refresh()
			setPending(undefined)
		},
	})
	const remove = useMutation({ mutationFn: () => deleteRecord(record), onSettled: refresh })
	return (
		<tr>
			<td className="name">
				<Link to="/records/$id" params={{ id: record.id }}>
					{record.spec.name}
				</Link>{' '}
				<ManagedBadge managedBy={record.spec.managed_by} />
				<ErrorNotice error={toggle.error ?? remove.error} />
			</td>
			<td className="mono">{record.spec.type}</td>
			<td className="mono">{record.spec.value}</td>
			<td>
				<input
					type="checkbox"
					aria-label={`Answer ${record.spec.name} ${record.spec.type}`}
					checked={pending ?? enabled}
					disabled={toggle.isPending}
					onChange={() => {
						setPending(!enabled)
						toggle.mutate()
					}}
				/>
			</td>
			<td className="actions-cell">
				<DeleteButton what="record" small pending={remove.isPending} onDelete={() => remove.mutate()} />
			</td>
		</tr>
	)
}

/** An existing record (`id`), or a new one ("new"). */
export function RecordEditor({ id }: { id: string }) {
	const isNew = id === 'new'
	const query = useQuery({ ...recordQuery(id), enabled: !isNew })
	if (!isNew && query.data === undefined) {
		return <Loading error={query.error} what="record" />
	}
	return (
		<RecordFields
			key={query.data?.revision ?? 'new'}
			stored={query.data}
			reload={() => void query.refetch()}
		/>
	)
}

function RecordFields({ stored, reload }: { stored: DnsRecord | undefined; reload: () => void }) {
	const [form, setForm] = useState<RecordForm>(() => recordForm(stored?.spec))
	const set =
		<K extends keyof RecordForm>(key: K) =>
		(value: RecordForm[K]) =>
			setForm((previous) => ({ ...previous, [key]: value }))
	return (
		<Editor
			title={stored === undefined ? 'New record' : stored.spec.name}
			what="record"
			back="/records"
			backLabel="Local records"
			stored={stored}
			queryKey={['records']}
			save={() => saveRecord(stored, recordSpec(form, stored?.spec.managed_by))}
			remove={stored === undefined ? undefined : () => deleteRecord(stored)}
			reload={reload}
			canSave={form.name.trim() !== '' && form.value.trim() !== '' && isRecordTtl(form.ttl)}
		>
			<TextField
				label="Name"
				value={form.name}
				onChange={set('name')}
				placeholder="nas.lan"
				hint="A name, or *. and a name for every name below it (not that name itself)."
				required
			/>
			<SelectField label="Type" value={form.kind} onChange={set('kind')} options={KINDS} />
			<TextField
				label="Value"
				value={form.value}
				onChange={set('value')}
				hint={recordValueHint(form.kind)}
				required
			/>
			<TextField
				label="Time to live, in seconds"
				type="number"
				value={form.ttl}
				onChange={set('ttl')}
				hint="How long clients may keep the answer: 0 to 86,400."
			/>
			<CheckField label="Enabled" checked={form.enabled} onChange={set('enabled')} />
			<TextField label="Comment" value={form.comment} onChange={set('comment')} mono={false} />
		</Editor>
	)
}
