import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { type ReactNode, useId, useState } from 'react'

import type { Group, List, ListSpec, ListStatus, Preset, RecommendedList } from '../api/client'
import { recommendedQuery, recommendedSizesQuery } from '../api/queries'
import { groupsQuery, saveGroup, saveList } from '../api/resources'
import { ErrorNotice } from '../components/ui'
import { DEFAULT_GROUP } from '../forms/forms'
import {
	baseListsInUse,
	excludedInUse,
	nodeList,
	type Plan,
	planPreset,
	planSwitch,
} from '../forms/recommended'
import { count } from '../format'

/** What each optional topic is for. */
const TOPICS: Record<string, string> = {
	'Bypass prevention': 'Stops devices from going around goethite.',
	'Device trackers':
		"Pick HaGeZi's list for each vendor you have, or Perflyst's for TVs, not both. Best for a group with those devices: an app may stop working.",
	Family: "For a group of children's devices.",
	Hardening: 'For people who know what they are blocking.',
}

/** A recommended list as the node keeps it. */
function specFor(item: RecommendedList): ListSpec {
	return {
		name: item.name,
		url: item.url,
		enabled: true,
		comment: `From goethite's recommended lists (${item.license}).`,
		managed_by: 'api',
	}
}

/** Carries out `plan`: new lists, lists turned on, the groups, then lists turned off. */
async function applyPlan(plan: Plan) {
	const created = new Map<string, string>()
	for (const item of plan.create) {
		const list = await saveList(undefined, specFor(item))
		created.set(item.id, list.id)
	}
	for (const list of plan.enable) {
		await saveList(list, { ...list.spec, enabled: true })
	}
	for (const { group, lists } of plan.groups) {
		await saveGroup(group, {
			...group.spec,
			lists: lists.flatMap((entry) => {
				if ('list' in entry) return [entry]
				const id = created.get(entry.created.id)
				return id === undefined ? [] : [{ list: id, schedule: entry.schedule }]
			}),
		})
	}
	// Last, so no group goes unprotected in between.
	for (const list of plan.disable) {
		await saveList(list, { ...list.spec, enabled: false })
	}
}

function useApply() {
	const queryClient = useQueryClient()
	return useMutation({
		mutationFn: applyPlan,
		onSettled: async () => {
			await queryClient.invalidateQueries({ queryKey: ['lists'] })
			await queryClient.invalidateQueries({ queryKey: ['groups'] })
			await queryClient.invalidateQueries({ queryKey: ['status'] })
		},
	})
}

/** goethite's recommended lists by category, with presets of them. */
export function RecommendedLists({
	lists,
	states,
}: {
	lists: List[] | undefined
	states: Map<string, ListStatus>
}) {
	const recommended = useQuery(recommendedQuery)
	const sizes = useQuery(recommendedSizesQuery)
	const groups = useQuery(groupsQuery)
	// `?? []` too for an API older than this page, as a development build
	// serving a newer web/dist can be.
	const catalog = recommended.data?.lists ?? []
	const presets = recommended.data?.presets ?? []
	const have = lists ?? []
	const base = baseListsInUse(catalog, have)
	const row = (item: RecommendedList) => (
		<RecommendedRow
			key={item.id}
			item={item}
			catalog={catalog}
			lists={have}
			groups={groups.data ?? []}
			stated={sizes.data?.get(item.id)}
			state={(() => {
				const list = nodeList(have, item)
				return list === undefined ? undefined : states.get(list.id)
			})()}
		/>
	)
	const of = (category: RecommendedList['category']) => catalog.filter((item) => item.category === category)
	const topics = [...new Set(of('optional').map((item) => item.topic ?? 'Other'))]

	return (
		<section className="panel" aria-label="Recommended lists">
			<h2>Recommended lists</h2>
			<p className="muted">
				Each checked to download and read cleanly. Sizes are what each list says it has, or what goethite read
				once it is added; lines a DNS server cannot apply, such as cosmetic or path rules, are skipped and
				counted. Looking for something else?{' '}
				<Link to="/lists/find">Find lists in the FilterLists directory</Link>.
			</p>
			<ErrorNotice error={recommended.error ?? groups.error} />
			{presets.length === 0 ? null : (
				<Presets presets={presets} catalog={catalog} lists={have} groups={groups.data ?? []} />
			)}
			{base.length > 1 ? (
				<div className="notice" role="status">
					Overlap: {base.map((item) => item.name).join(' and ')} are all on. Base lists overlap a lot, so one
					is enough; turn the others off, or use a preset.
				</div>
			) : null}
			<Category title="Base list" hint="Pick one: base lists overlap a lot, so a second adds little.">
				{of('base').map(row)}
			</Category>
			<Category title="Security" hint="Stack these on the base list.">
				{of('security').map(row)}
			</Category>
			<h3>Optional</h3>
			<p className="muted">Off unless you want them, by topic.</p>
			{topics.map((topic) => (
				<Category key={topic} title={topic} hint={TOPICS[topic] ?? ''} level={4}>
					{of('optional')
						.filter((item) => (item.topic ?? 'Other') === topic)
						.map(row)}
				</Category>
			))}
			<details className="legacy">
				<summary>Legacy lists</summary>
				<p className="muted">Already included in HaGeZi's and OISD's lists: only worth it on their own.</p>
				<table className="table recommended">
					<tbody>{of('legacy').map(row)}</tbody>
				</table>
			</details>
		</section>
	)
}

function Category({
	title,
	hint,
	level = 3,
	children,
}: {
	title: string
	hint: string
	level?: 3 | 4
	children: ReactNode
}) {
	const Heading = level === 3 ? 'h3' : 'h4'
	return (
		<div className="category">
			<Heading>{title}</Heading>
			{hint === '' ? null : <p className="muted">{hint}</p>}
			<table className="table recommended">
				<tbody>{children}</tbody>
			</table>
		</div>
	)
}

function RecommendedRow({
	item,
	catalog,
	lists,
	groups,
	stated,
	state,
}: {
	item: RecommendedList
	catalog: RecommendedList[]
	lists: List[]
	groups: Group[]
	stated: number | undefined
	state: ListStatus | undefined
}) {
	const apply = useApply()
	const [confirming, setConfirming] = useState(false)
	const list = nodeList(lists, item)
	const on = list !== undefined && list.spec.enabled !== false
	const excluded = excludedInUse(catalog, item, lists)
	const fallback = groups.find((group) => group.id === DEFAULT_GROUP)
	const plan = planSwitch(catalog, item, lists, groups, fallback)
	const skipped = (state?.unsupported ?? 0) + (state?.invalid ?? 0)
	const size =
		state?.rules != null
			? `${count(state.rules)} rules${skipped > 0 ? `, ${count(skipped)} lines skipped` : ''}`
			: stated === undefined
				? null
				: `about ${count(stated)} entries`
	const action =
		excluded.length > 0
			? `Switch from ${excluded.map((other) => other.spec.name).join(', ')}`
			: on
				? null
				: list === undefined
					? 'Add'
					: 'Turn on'

	return (
		<>
			<tr>
				<td>
					<div className="recommended-head">
						<strong>{item.name}</strong>
						{item.recommended ? <span className="badge accent">★ RECOMMENDED</span> : null}
						{item.badge == null ? null : <span className="badge">{item.badge.toUpperCase()}</span>}
						{item.default ? <span className="badge cached">DEFAULT</span> : null}
					</div>
					<div>{item.description}</div>
					{item.note == null ? null : <div className="note">{item.note}</div>}
					<div className="muted">
						{item.maintainer} · {item.license}
						{size === null ? '' : ` · ${size}`} ·{' '}
						<a href={item.homepage} target="_blank" rel="noreferrer noopener">
							home page
						</a>
					</div>
					<ErrorNotice error={apply.error} />
				</td>
				<td className="actions-cell">
					{action === null ? (
						<span className="badge ok">ADDED</span>
					) : (
						<button
							type="button"
							className="button small"
							disabled={apply.isPending}
							aria-label={`${action}: ${item.name}`}
							onClick={() => (excluded.length > 0 ? setConfirming(true) : apply.mutate(plan))}
						>
							{action}
						</button>
					)}
				</td>
			</tr>
			{confirming ? (
				<tr>
					<td colSpan={2}>
						<PlanPreview
							plan={plan}
							action={`Switch to ${item.name}`}
							pending={apply.isPending}
							onApply={() => apply.mutate(plan, { onSuccess: () => setConfirming(false) })}
							onCancel={() => setConfirming(false)}
						/>
					</td>
				</tr>
			) : null}
		</>
	)
}

/** What a plan changes, to confirm before it is carried out. */
function PlanPreview({
	plan,
	action,
	pending,
	onApply,
	onCancel,
}: {
	plan: Plan
	action: string
	pending: boolean
	onApply: () => void
	onCancel: () => void
}) {
	return (
		<div className="subform" role="group" aria-label={action}>
			<ul className="plan">
				{plan.create.length === 0 ? null : (
					<li>New, downloaded at once: {plan.create.map((item) => item.name).join(', ')}</li>
				)}
				{plan.enable.length === 0 ? null : (
					<li>Turned on: {plan.enable.map((list) => list.spec.name).join(', ')}</li>
				)}
				{plan.summary.map(({ group, joins, leaves }) => (
					<li key={group.id}>
						{group.spec.name}:{joins.length === 0 ? '' : ` uses ${joins.join(', ')}`}
						{joins.length > 0 && leaves.length > 0 ? ';' : ''}
						{leaves.length === 0 ? '' : ` no longer uses ${leaves.join(', ')}`}
						{joins.length === 0 && leaves.length === 0 ? ' no change' : ''}
					</li>
				))}
				{plan.disable.length === 0 ? null : (
					<li>Turned off, no group uses them: {plan.disable.map((list) => list.spec.name).join(', ')}</li>
				)}
			</ul>
			<div className="actions">
				<button type="button" className="button primary small" disabled={pending} onClick={onApply}>
					{action}
				</button>
				<button type="button" className="button small" onClick={onCancel}>
					Cancel
				</button>
			</div>
		</div>
	)
}

/** The presets, each to apply to a group after seeing what changes. */
function Presets({
	presets,
	catalog,
	lists,
	groups,
}: {
	presets: Preset[]
	catalog: RecommendedList[]
	lists: List[]
	groups: Group[]
}) {
	const [chosen, setChosen] = useState<Preset | null>(null)
	const names = new Map(catalog.map((item) => [item.id, item.name]))
	return (
		<div className="category">
			<h3>Presets</h3>
			<p className="muted">
				A set of lists for a group, in one step. Recommended lists the preset does not have leave the group;
				your own lists stay.
			</p>
			<div className="presets">
				{presets.map((preset) => (
					<article key={preset.id} className="preset" aria-label={`Preset ${preset.name}`}>
						<div className="recommended-head">
							<strong>{preset.name}</strong>
							{preset.default ? <span className="badge cached">DEFAULT</span> : null}
						</div>
						<p>{preset.description}</p>
						<ul className="muted">
							{preset.lists.map((id) => (
								<li key={id}>{names.get(id) ?? id}</li>
							))}
						</ul>
						<button
							type="button"
							className="button small"
							aria-expanded={chosen?.id === preset.id}
							onClick={() => setChosen(chosen?.id === preset.id ? null : preset)}
						>
							Use for a group
						</button>
					</article>
				))}
			</div>
			{chosen === null ? null : (
				<ApplyPreset
					key={chosen.id}
					preset={chosen}
					catalog={catalog}
					lists={lists}
					groups={groups}
					onDone={() => setChosen(null)}
				/>
			)}
		</div>
	)
}

function ApplyPreset({
	preset,
	catalog,
	lists,
	groups,
	onDone,
}: {
	preset: Preset
	catalog: RecommendedList[]
	lists: List[]
	groups: Group[]
	onDone: () => void
}) {
	const id = useId()
	const apply = useApply()
	const [groupId, setGroupId] = useState(
		groups.some((group) => group.id === DEFAULT_GROUP) ? DEFAULT_GROUP : (groups[0]?.id ?? ''),
	)
	const group = groups.find((candidate) => candidate.id === groupId)
	const plan = group === undefined ? undefined : planPreset(catalog, preset, lists, group, groups)
	return (
		<div className="subform apply-preset">
			<div className="field">
				<label htmlFor={`${id}-group`}>Use {preset.name} for</label>
				<select
					id={`${id}-group`}
					className="select"
					value={groupId}
					onChange={(event) => setGroupId(event.target.value)}
				>
					{groups.map((candidate) => (
						<option key={candidate.id} value={candidate.id}>
							{candidate.spec.name}
						</option>
					))}
				</select>
			</div>
			<ErrorNotice error={apply.error} />
			{plan === undefined ? null : plan.summary.length === 0 ? (
				<p className="muted">This group already uses exactly these lists.</p>
			) : (
				<PlanPreview
					plan={plan}
					action={`Use ${preset.name}`}
					pending={apply.isPending}
					onApply={() => apply.mutate(plan, { onSuccess: onDone })}
					onCancel={onDone}
				/>
			)}
		</div>
	)
}
