import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { useState } from 'react'

import {
	api,
	call,
	type Group,
	ifMatch,
	type List,
	type ListStatus,
} from '../api/client'
import { listsQuery, statusQuery } from '../api/queries'
import {
	deleteList,
	groupQuery,
	groupsQuery,
	listQuery,
	refreshLists,
	saveList,
	settingsQuery,
} from '../api/resources'
import { Editor, Loading, ManagedBadge } from '../components/editor'
import { RecommendedLists } from './RecommendedLists'
import { CheckField, SelectField, TextField } from '../components/form'
import { ErrorNotice } from '../components/ui'
import { DEFAULT_GROUP, listForm, type ListForm, listSpec } from '../forms/forms'
import type { ListDraft } from '../router'
import { count, dateTime } from '../format'

/** Every filter list, with how it is doing. */
export function Lists() {
	const lists = useQuery(listsQuery)
	const status = useQuery(statusQuery)
	const settings = useQuery(settingsQuery)
	const queryClient = useQueryClient()
	const refresh = useMutation({
		mutationFn: refreshLists,
		onSettled: () => queryClient.invalidateQueries({ queryKey: ['status'] }),
	})
	const states = new Map((status.data?.lists ?? []).map((state) => [state.id, state]))

	return (
		<div className="grid-page">
			<div className="page-head">
				<h1>Filter lists</h1>
				<Link to="/lists/$id" params={{ id: 'new' }} className="button primary">
					New list
				</Link>
				<Link to="/lists/find" className="button">
					Find lists
				</Link>
				<button
					type="button"
					className="button"
					disabled={refresh.isPending}
					onClick={() => refresh.mutate()}
				>
					Download again now
				</button>
			</div>
			<p className="muted">
				A list filters the clients of the groups that use it. Downloaded lists are refreshed{' '}
				{settings.data === undefined
					? 'regularly'
					: `every ${settings.data.spec.list_update_hours ?? 24} hours`}{' '}
				(see <Link to="/settings">Settings</Link>).
			</p>
			<ErrorNotice error={lists.error ?? refresh.error} />
			{refresh.isSuccess ? (
				<div className="notice" role="status">
					Downloading the lists again; their state below follows.
				</div>
			) : null}
			{lists.data?.length === 0 ? (
				<p className="panel">No filter lists yet: only custom rules filter.</p>
			) : (
				<div className="panel">
					<table className="table">
						<thead>
							<tr>
								<th>Name</th>
								<th>From</th>
								<th>Rules</th>
								<th>State</th>
							</tr>
						</thead>
						<tbody>
							{(lists.data ?? []).map((list) => (
								<ListRow key={list.id} list={list} state={states.get(list.id)} />
							))}
						</tbody>
					</table>
				</div>
			)}
			<RecommendedLists lists={lists.data} states={states} />
		</div>
	)
}

function ListRow({ list, state }: { list: List; state: ListStatus | undefined }) {
	const problem = state?.error ?? state?.download_error
	const skipped = (state?.unsupported ?? 0) + (state?.invalid ?? 0)
	return (
		<tr>
			<td>
				<Link to="/lists/$id" params={{ id: list.id }}>
					{list.spec.name}
				</Link>{' '}
				<ManagedBadge managedBy={list.spec.managed_by} />
			</td>
			<td className="name">{list.spec.url ?? list.spec.path}</td>
			<td className="num">
				{state?.rules == null ? '–' : count(state.rules)}
				{skipped > 0 ? (
					<div className="muted" title="Lines a DNS server cannot apply, such as cosmetic or path rules">
						{count(skipped)} skipped
					</div>
				) : null}
			</td>
			<td>
				{list.spec.enabled === false ? (
					<span className="badge">OFF</span>
				) : problem == null ? (
					<span className="badge ok">OK</span>
				) : (
					<span className="badge blocked">PROBLEM</span>
				)}
				{problem == null ? null : <div className="muted">{problem}</div>}
				{state?.last_success == null ? null : (
					<div className="muted">updated {dateTime(state.last_success)}</div>
				)}
			</td>
		</tr>
	)
}

/** A new list (`id` "new"), started from `draft`, or an existing one. */
export function ListEditor({ id, draft }: { id: string; draft?: ListDraft }) {
	const isNew = id === 'new'
	const query = useQuery({ ...listQuery(id), enabled: !isNew })
	if (!isNew && query.data === undefined) {
		return <Loading error={query.error} what="list" />
	}
	return (
		<ListFields
			key={query.data?.revision ?? 'new'}
			stored={query.data}
			draft={isNew ? draft : undefined}
			reload={() => void query.refetch()}
		/>
	)
}

function ListFields({
	stored,
	draft,
	reload,
}: {
	stored: List | undefined
	draft?: ListDraft | undefined
	reload: () => void
}) {
	const [form, setForm] = useState<ListForm>(() => ({
		...listForm(stored?.spec),
		...(draft?.name === undefined ? {} : { name: draft.name }),
		...(draft?.url === undefined ? {} : { source: 'url' as const, location: draft.url }),
		...(draft?.comment === undefined ? {} : { comment: draft.comment }),
	}))
	const [useInDefault, setUseInDefault] = useState(true)
	const queryClient = useQueryClient()
	// Terraform's default group is left to Terraform.
	const defaultGroup = useQuery({ ...groupQuery(DEFAULT_GROUP), enabled: stored === undefined })
	const canUseDefault =
		defaultGroup.data !== undefined && defaultGroup.data.spec.managed_by !== 'terraform'
	// goethite refuses to delete a list a group uses: deleting takes it out of
	// them first, unless Terraform manages one of them.
	const groups = useQuery({ ...groupsQuery, enabled: stored !== undefined })
	const users = usersOf(groups.data ?? [], stored?.id)
	const terraformUser = terraformUserOf(users)
	const remove =
		stored === undefined || terraformUser !== undefined || groups.data === undefined
			? undefined
			: async () => {
					// The groups as they are now: the ones shown can be older than a
					// change, such as this list joining the default group.
					const current = usersOf(
						await queryClient.fetchQuery({ ...groupsQuery, staleTime: 0 }),
						stored.id,
					)
					const managed = terraformUserOf(current)
					if (managed !== undefined) {
						throw new Error(
							`Terraform manages ${managed.spec.name}, which now uses this list: take it out there first.`,
						)
					}
					for (const group of current) {
						await withoutList(group, stored.id)
					}
					await queryClient.invalidateQueries({ queryKey: ['groups'] })
					await deleteList(stored)
				}
	const set =
		<K extends keyof ListForm>(key: K) =>
		(value: ListForm[K]) =>
			setForm((previous) => ({ ...previous, [key]: value }))

	const save = async () => {
		const spec = listSpec(form, stored?.spec.managed_by)
		const saved = await saveList(stored, spec)
		if (stored === undefined && useInDefault && canUseDefault) {
			await addToDefaultGroup(saved.id)
			await queryClient.invalidateQueries({ queryKey: ['groups'] })
		}
		return saved
	}

	return (
		<Editor
			title={stored === undefined ? 'New filter list' : stored.spec.name}
			what="list"
			back="/lists"
			backLabel="Filter lists"
			stored={stored}
			queryKey={['lists']}
			save={save}
			remove={remove}
			reload={reload}
			canSave={form.name.trim() !== '' && form.location.trim() !== ''}
		>
			{users.length === 0 ? null : (
				<p className="muted">
					Used by {users.map((group) => group.spec.name).join(', ')}.{' '}
					{terraformUser === undefined
						? 'Deleting it takes it out of them.'
						: `Terraform manages ${terraformUser.spec.name}: take the list out of it there before deleting it.`}
				</p>
			)}
			<TextField label="Name" value={form.name} onChange={set('name')} mono={false} required />
			<SelectField
				label="Source"
				value={form.source}
				onChange={set('source')}
				options={[
					{ value: 'url', label: 'Downloaded from a URL' },
					{ value: 'path', label: 'A file on the node' },
				]}
			/>
			{form.source === 'url' ? (
				<TextField
					label="URL"
					value={form.location}
					onChange={set('location')}
					placeholder="https://lists.example/ads.txt"
					hint="An https:// URL. goethite keeps the last good copy if a download fails."
					required
				/>
			) : (
				<TextField
					label="Path"
					value={form.location}
					onChange={set('location')}
					placeholder="/etc/goethite/lists/local.txt"
					hint="An absolute path in the local lists directory ([filter] local_lists_dir; /etc/goethite/lists with the packages). In a cluster, on every node."
					required
				/>
			)}
			<CheckField label="Enabled" checked={form.enabled} onChange={set('enabled')} />
			{stored === undefined && canUseDefault ? (
				<CheckField
					label="Use it in the default group"
					checked={useInDefault}
					onChange={setUseInDefault}
					hint="The default group covers every client that is in no other group."
				/>
			) : null}
			<TextField label="Comment" value={form.comment} onChange={set('comment')} mono={false} />
		</Editor>
	)
}

/** The groups that use a list. */
function usersOf(groups: readonly Group[], list: string | undefined) {
	return groups.filter((group) => (group.spec.lists ?? []).some((entry) => entry.list === list))
}

/** One of `groups` that Terraform manages, if any. */
function terraformUserOf(groups: readonly Group[]) {
	return groups.find((group) => group.spec.managed_by === 'terraform')
}

/** Takes a list out of a group. */
async function withoutList(group: Group, list: string) {
	await call(
		api.PUT('/api/v1/groups/{id}', {
			params: { path: { id: group.id }, header: ifMatch(group.revision) },
			body: {
				...group.spec,
				lists: (group.spec.lists ?? []).filter((entry) => entry.list !== list),
			},
		}),
	)
}

/** Adds a new list to the default group, so it filters at once. */
async function addToDefaultGroup(list: string) {
	const group = await call(
		api.GET('/api/v1/groups/{id}', { params: { path: { id: DEFAULT_GROUP } } }),
	)
	await call(
		api.PUT('/api/v1/groups/{id}', {
			params: { path: { id: DEFAULT_GROUP }, header: ifMatch(group.revision) },
			body: { ...group.spec, lists: [...(group.spec.lists ?? []), { list, schedule: null }] },
		}),
	)
}
