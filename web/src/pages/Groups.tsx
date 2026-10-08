import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { useId, useState } from 'react'

import type { Group } from '../api/client'
import { listsQuery } from '../api/queries'
import {
	allClientsQuery,
	deleteGroup,
	groupQuery,
	groupsQuery,
	saveGroup,
	schedulesQuery,
} from '../api/resources'
import { BlockedServices } from '../components/BlockedServices'
import { Editor, Loading, ManagedBadge } from '../components/editor'
import { CheckField, TextField } from '../components/form'
import { ErrorNotice } from '../components/ui'
import { DEFAULT_GROUP, groupForm, type GroupForm, groupSpec } from '../forms/forms'
import { count } from '../format'

/** Client groups: which lists and services filter whom, and when. */
export function Groups() {
	const groups = useQuery(groupsQuery)
	const clients = useQuery(allClientsQuery)
	const members = new Map<string, number>()
	for (const client of clients.data ?? []) {
		const group = client.spec.group ?? DEFAULT_GROUP
		members.set(group, (members.get(group) ?? 0) + 1)
	}
	return (
		<div className="grid-page">
			<div className="page-head">
				<h1>Groups</h1>
				<Link to="/groups/$id" params={{ id: 'new' }} className="button primary">
					New group
				</Link>
			</div>
			<p className="muted">
				A group decides the filtering of its clients: which lists and blocked services, during which
				schedules, and safe search. Clients in no other group are in the default group.
			</p>
			<ErrorNotice error={groups.error ?? clients.error} />
			<div className="panel">
				<table className="table">
					<thead>
						<tr>
							<th>Name</th>
							<th>Filtering</th>
							<th>Safe search</th>
							<th>Lists</th>
							<th>Blocked services</th>
							<th>Clients</th>
						</tr>
					</thead>
					<tbody>
						{(groups.data ?? []).map((group) => (
							<tr key={group.id}>
								<td>
									<Link to="/groups/$id" params={{ id: group.id }}>
										{group.spec.name}
									</Link>{' '}
									{group.id === DEFAULT_GROUP ? <span className="badge">DEFAULT</span> : null}{' '}
									<ManagedBadge managedBy={group.spec.managed_by} />
								</td>
								<td>{onOff(group.spec.filtering ?? true)}</td>
								<td>{onOff(group.spec.safe_search ?? false)}</td>
								<td className="num">{count(group.spec.lists?.length ?? 0)}</td>
								<td className="num">
									{count(new Set(group.spec.blocked_services?.map((entry) => entry.service)).size)}
								</td>
								<td className="num">
									{group.id === DEFAULT_GROUP ? 'the rest' : count(members.get(group.id) ?? 0)}
								</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</div>
	)
}

function onOff(on: boolean) {
	return on ? <span className="badge ok">ON</span> : <span className="badge">OFF</span>
}

/** An existing group (`id`), or a new one ("new"). */
export function GroupEditor({ id }: { id: string }) {
	const isNew = id === 'new'
	const query = useQuery({ ...groupQuery(id), enabled: !isNew })
	if (!isNew && query.data === undefined) {
		return <Loading error={query.error} what="group" />
	}
	return (
		<GroupFields key={query.data?.revision ?? 'new'} stored={query.data} reload={() => void query.refetch()} />
	)
}

function GroupFields({ stored, reload }: { stored: Group | undefined; reload: () => void }) {
	const [form, setForm] = useState<GroupForm>(() => groupForm(stored?.spec))
	const lists = useQuery(listsQuery)
	const schedules = useQuery(schedulesQuery)
	const set =
		<K extends keyof GroupForm>(key: K) =>
		(value: GroupForm[K]) =>
			setForm((previous) => ({ ...previous, [key]: value }))
	const setEntry = (index: number, change: Partial<GroupForm['lists'][number]>) =>
		set('lists')(form.lists.map((entry, at) => (at === index ? { ...entry, ...change } : entry)))
	const isDefault = stored?.id === DEFAULT_GROUP
	const rowId = useId()
	// goethite refuses to delete a group that has clients.
	const clients = useQuery({ ...allClientsQuery, enabled: stored !== undefined })
	const members = (clients.data ?? []).filter((client) => client.spec.group === stored?.id).length

	return (
		<Editor
			title={stored === undefined ? 'New group' : stored.spec.name}
			what="group"
			back="/groups"
			backLabel="Groups"
			stored={stored}
			queryKey={['groups']}
			save={() => saveGroup(stored, groupSpec(form, stored?.spec.managed_by))}
			// The default group always exists.
			remove={
				stored === undefined || isDefault || clients.data === undefined || members > 0
					? undefined
					: () => deleteGroup(stored)
			}
			reload={reload}
			canSave={form.name.trim() !== ''}
		>
			{members === 0 || isDefault ? null : (
				<p className="muted">
					{count(members)} {members === 1 ? 'client is' : 'clients are'} in this group: move them to
					another group before deleting it.
				</p>
			)}
			{isDefault ? (
				<p className="muted">The default group covers every client that is in no other group.</p>
			) : null}
			<TextField label="Name" value={form.name} onChange={set('name')} mono={false} required />
			<CheckField
				label="Filtering"
				checked={form.filtering}
				onChange={set('filtering')}
				hint="Off: the group's clients are not filtered at all."
			/>
			<CheckField
				label="Safe search"
				checked={form.safeSearch}
				onChange={set('safeSearch')}
				hint="Search engines answer with their safe-search versions."
			/>
			<fieldset className="subform">
				<legend>Lists</legend>
				<ErrorNotice error={lists.error ?? schedules.error} />
				{form.lists.length === 0 ? <p className="muted">No lists: only custom rules filter.</p> : null}
				{form.lists.map((entry, index) => (
					<div className="row" key={index}>
						<div className="field grow">
							<label htmlFor={`${rowId}-list-${index}`}>List</label>
							<select
								id={`${rowId}-list-${index}`}
								className="select"
								value={entry.list}
								onChange={(event) => setEntry(index, { list: event.target.value })}
							>
								<option value="">Choose a list</option>
								{(lists.data ?? []).map((list) => (
									<option key={list.id} value={list.id}>
										{list.spec.name}
									</option>
								))}
							</select>
						</div>
						<div className="field grow">
							<label htmlFor={`${rowId}-when-${index}`}>When</label>
							<select
								id={`${rowId}-when-${index}`}
								className="select"
								value={entry.schedule}
								onChange={(event) => setEntry(index, { schedule: event.target.value })}
							>
								<option value="">Always</option>
								{(schedules.data ?? []).map((schedule) => (
									<option key={schedule.id} value={schedule.id}>
										During {schedule.spec.name}
									</option>
								))}
							</select>
						</div>
						<button
							type="button"
							className="button small"
							aria-label={`Remove list ${index + 1}`}
							onClick={() => set('lists')(form.lists.filter((_, at) => at !== index))}
						>
							Remove
						</button>
					</div>
				))}
				<p>
					<button
						type="button"
						className="button small"
						onClick={() => set('lists')([...form.lists, { list: '', schedule: '' }])}
					>
						Add a list
					</button>
				</p>
			</fieldset>
			<BlockedServices
				value={form.blockedServices}
				onChange={set('blockedServices')}
				schedules={schedules.data ?? []}
			/>
			<TextField label="Comment" value={form.comment} onChange={set('comment')} mono={false} />
		</Editor>
	)
}
