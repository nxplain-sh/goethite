import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { type FormEvent, useState } from 'react'

import type { Rule } from '../api/client'
import { deleteRule, ruleQuery, rulesQuery, saveRule } from '../api/resources'
import { DeleteButton, Editor, Loading, ManagedBadge } from '../components/editor'
import { CheckField, TextField } from '../components/form'
import { ErrorNotice } from '../components/ui'
import { ruleForm, type RuleForm, ruleSpec } from '../forms/forms'
import { count } from '../format'

/** How many rules the table shows at once; the filter narrows them. */
const SHOWN = 500

/** Custom rules: added here, applied to every client while filtering is on. */
export function Rules() {
	const rules = useQuery(rulesQuery)
	const [filter, setFilter] = useState('')
	const needle = filter.trim().toLowerCase()
	const matching = (rules.data ?? []).filter(
		(rule) =>
			needle === '' ||
			rule.spec.rule.toLowerCase().includes(needle) ||
			(rule.spec.comment ?? '').toLowerCase().includes(needle),
	)

	return (
		<div className="grid-page">
			<h1>Custom rules</h1>
			<p className="muted">
				They apply to every client while filtering is on, in any group. Any syntax the filter lists use works:{' '}
				<span className="mono">||ads.example^</span> blocks a domain and its subdomains,{' '}
				<span className="mono">@@||good.example^</span> allows one.
			</p>
			<AddRule />
			<ErrorNotice error={rules.error} />
			<div className="panel">
				<div className="page-head">
					<label className="field grow">
						Filter
						<input
							className="input"
							type="search"
							value={filter}
							spellCheck={false}
							placeholder="tracker"
							onChange={(event) => setFilter(event.target.value)}
						/>
					</label>
					<span className="muted">
						{count(matching.length)} of {count(rules.data?.length ?? 0)} rules
						{matching.length > SHOWN ? `, the first ${count(SHOWN)} shown` : ''}
					</span>
				</div>
				<table className="table">
					<thead>
						<tr>
							<th>Rule</th>
							<th>Comment</th>
							<th>On</th>
							<th />
						</tr>
					</thead>
					<tbody>
						{matching.slice(0, SHOWN).map((rule) => (
							<RuleRow key={rule.id} rule={rule} />
						))}
					</tbody>
				</table>
				{rules.data?.length === 0 ? <p className="muted">No custom rules yet.</p> : null}
			</div>
		</div>
	)
}

function AddRule() {
	const queryClient = useQueryClient()
	const [rule, setRule] = useState('')
	const add = useMutation({
		mutationFn: () => saveRule(undefined, ruleSpec({ rule, enabled: true, comment: '' })),
		onSuccess: async () => {
			setRule('')
			await queryClient.invalidateQueries({ queryKey: ['rules'] })
		},
	})
	const submit = (event: FormEvent) => {
		event.preventDefault()
		if (rule.trim() !== '') add.mutate()
	}
	return (
		<form className="panel add-form" onSubmit={submit}>
			<label className="field grow">
				New rule
				<input
					className="input"
					value={rule}
					spellCheck={false}
					autoComplete="off"
					placeholder="||tracker.example^"
					onChange={(event) => setRule(event.target.value)}
				/>
			</label>
			<button type="submit" className="button primary" disabled={add.isPending || rule.trim() === ''}>
				Add
			</button>
			<ErrorNotice error={add.error} />
		</form>
	)
}

function RuleRow({ rule }: { rule: Rule }) {
	const queryClient = useQueryClient()
	const refresh = () => queryClient.invalidateQueries({ queryKey: ['rules'] })
	const enabled = rule.spec.enabled ?? true
	// The new state, shown at once while it is saved; what goethite stores
	// afterwards, whether it took the change or not.
	const [pending, setPending] = useState<boolean | undefined>(undefined)
	const toggle = useMutation({
		mutationFn: () => saveRule(rule, { ...rule.spec, enabled: !enabled }),
		onSettled: async () => {
			await refresh()
			setPending(undefined)
		},
	})
	const remove = useMutation({ mutationFn: () => deleteRule(rule), onSettled: refresh })
	return (
		<tr>
			<td className="name">
				<Link to="/rules/$id" params={{ id: rule.id }}>
					{rule.spec.rule}
				</Link>{' '}
				<ManagedBadge managedBy={rule.spec.managed_by} />
				<ErrorNotice error={toggle.error ?? remove.error} />
			</td>
			<td>{rule.spec.comment}</td>
			<td>
				<input
					type="checkbox"
					aria-label={`Use ${rule.spec.rule}`}
					checked={pending ?? enabled}
					disabled={toggle.isPending}
					onChange={() => {
						setPending(!enabled)
						toggle.mutate()
					}}
				/>
			</td>
			<td className="actions-cell">
				<DeleteButton what="rule" small pending={remove.isPending} onDelete={() => remove.mutate()} />
			</td>
		</tr>
	)
}

/** An existing rule (`id`), or a new one ("new"). */
export function RuleEditor({ id }: { id: string }) {
	const isNew = id === 'new'
	const query = useQuery({ ...ruleQuery(id), enabled: !isNew })
	if (!isNew && query.data === undefined) {
		return <Loading error={query.error} what="rule" />
	}
	return (
		<RuleFields key={query.data?.revision ?? 'new'} stored={query.data} reload={() => void query.refetch()} />
	)
}

function RuleFields({ stored, reload }: { stored: Rule | undefined; reload: () => void }) {
	const [form, setForm] = useState<RuleForm>(() => ruleForm(stored?.spec))
	const set =
		<K extends keyof RuleForm>(key: K) =>
		(value: RuleForm[K]) =>
			setForm((previous) => ({ ...previous, [key]: value }))
	return (
		<Editor
			title={stored === undefined ? 'New rule' : 'Rule'}
			what="rule"
			back="/rules"
			backLabel="Custom rules"
			stored={stored}
			queryKey={['rules']}
			save={() => saveRule(stored, ruleSpec(form, stored?.spec.managed_by))}
			remove={stored === undefined ? undefined : () => deleteRule(stored)}
			reload={reload}
			canSave={form.rule.trim() !== ''}
		>
			<TextField
				label="Rule"
				value={form.rule}
				onChange={set('rule')}
				placeholder="||tracker.example^"
				required
			/>
			<CheckField label="Enabled" checked={form.enabled} onChange={set('enabled')} />
			<TextField label="Comment" value={form.comment} onChange={set('comment')} mono={false} />
		</Editor>
	)
}
