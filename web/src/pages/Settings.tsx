import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { type FormEvent, useState } from 'react'

import { ApiError, type BlockResponseKind, type Settings as Stored } from '../api/client'
import { saveSettings, settingsQuery } from '../api/resources'
import { Loading } from '../components/editor'
import { CheckField, SelectField, TextField } from '../components/form'
import { ErrorNotice } from '../components/ui'

/** The node's (or the cluster's) filtering settings. */
export function Settings() {
	const query = useQuery(settingsQuery)
	// Kept here: saving fetches the new revision, which rebuilds the form.
	const [saved, setSaved] = useState(false)
	if (query.data === undefined) {
		return <Loading error={query.error} what="settings" />
	}
	return (
		<SettingsForm
			key={query.data.revision}
			stored={query.data}
			reload={() => void query.refetch()}
			saved={saved}
			setSaved={setSaved}
		/>
	)
}

const BLOCK_RESPONSES: readonly { value: BlockResponseKind; label: string }[] = [
	{ value: 'null_ip', label: '0.0.0.0 and :: (null IP)' },
	{ value: 'nxdomain', label: 'No such name (NXDOMAIN)' },
	{ value: 'refused', label: 'Refused (REFUSED)' },
]

function SettingsForm({
	stored,
	reload,
	saved,
	setSaved,
}: {
	stored: Stored
	reload: () => void
	saved: boolean
	setSaved: (saved: boolean) => void
}) {
	const queryClient = useQueryClient()
	const [protection, setProtection] = useState(stored.spec.protection ?? true)
	const [blockResponse, setBlockResponse] = useState<BlockResponseKind>(
		stored.spec.block_response ?? 'null_ip',
	)
	const [blockedTtl, setBlockedTtl] = useState(String(stored.spec.blocked_ttl ?? 10))
	const [updateHours, setUpdateHours] = useState(String(stored.spec.list_update_hours ?? 24))
	const save = useMutation({
		mutationFn: () =>
			saveSettings(stored.revision, {
				protection,
				block_response: blockResponse,
				blocked_ttl: Number(blockedTtl),
				list_update_hours: Number(updateHours),
			}),
		onMutate: () => setSaved(false),
		onSuccess: async () => {
			setSaved(true)
			await queryClient.invalidateQueries({ queryKey: ['settings'] })
			await queryClient.invalidateQueries({ queryKey: ['status'] })
		},
	})
	const ttl = Number(blockedTtl)
	const hours = Number(updateHours)
	const valid =
		Number.isInteger(ttl) && ttl >= 0 && ttl <= 86_400 && Number.isInteger(hours) && hours >= 1 && hours <= 168
	const changedMeanwhile = save.error instanceof ApiError && save.error.code === 'revision_mismatch'

	const submit = (event: FormEvent) => {
		event.preventDefault()
		save.mutate()
	}
	return (
		<div className="grid-page editor">
			<h1>Settings</h1>
			<p className="muted">
				Filtering settings for this node (in a cluster, for both). Revision {stored.revision}.
			</p>
			<ErrorNotice error={save.error} />
			{changedMeanwhile ? (
				<p>
					<button type="button" className="button small" onClick={reload}>
						Load the current settings
					</button>
				</p>
			) : null}
			{saved ? (
				<div className="notice" role="status">
					Saved.
				</div>
			) : null}
			<form className="panel form" onSubmit={submit}>
				<fieldset className="fields" disabled={save.isPending}>
					<CheckField
						label="Filtering"
						checked={protection}
						onChange={setProtection}
						hint="The master switch: off, nothing is filtered for anyone. To stop for a while, pause instead."
					/>
					<SelectField
						label="Blocked names are answered with"
						value={blockResponse}
						onChange={setBlockResponse}
						options={BLOCK_RESPONSES}
					/>
					<TextField
						label="Time to live of blocked answers, in seconds"
						type="number"
						value={blockedTtl}
						onChange={setBlockedTtl}
						hint="0 to 86,400. Short, so unblocking takes effect soon."
					/>
					<TextField
						label="Download lists every … hours"
						type="number"
						value={updateHours}
						onChange={setUpdateHours}
						hint="1 to 168."
					/>
				</fieldset>
				<div className="actions">
					<button type="submit" className="button primary" disabled={!valid || save.isPending}>
						Save
					</button>
				</div>
			</form>
		</div>
	)
}
