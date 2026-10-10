import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { type FormEvent, useState } from 'react'

import { ApiError, type BlockResponseKind, type Settings as Stored } from '../api/client'
import { statusQuery } from '../api/queries'
import { checkUpdate, flushCache, saveSettings, settingsQuery } from '../api/resources'
import { Loading } from '../components/editor'
import { CheckField, SelectField, TextAreaField, TextField } from '../components/form'
import { ErrorNotice } from '../components/ui'
import { isAccessEntry, parseAccessEntries } from '../forms/forms'

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
	{ value: 'custom_ip', label: 'An address of my own' },
]

/** A permissive check; the API validates the address again. */
const looksLikeIpv4 = (value: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(value)
const looksLikeIpv6 = (value: string) => value.includes(':')

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
	const [blockingIpv4, setBlockingIpv4] = useState(stored.spec.blocking_ipv4 ?? '')
	const [blockingIpv6, setBlockingIpv6] = useState(stored.spec.blocking_ipv6 ?? '')
	const [blockedTtl, setBlockedTtl] = useState(String(stored.spec.blocked_ttl ?? 10))
	const [updateHours, setUpdateHours] = useState(String(stored.spec.list_update_hours ?? 24))
	const [allowedText, setAllowedText] = useState((stored.spec.access?.allowed ?? []).join('\n'))
	const [blockedText, setBlockedText] = useState((stored.spec.access?.blocked ?? []).join('\n'))
	const allowed = parseAccessEntries(allowedText)
	const blocked = parseAccessEntries(blockedText)
	const badAllowed = allowed.filter((entry) => !isAccessEntry(entry))
	const badBlocked = blocked.filter((entry) => !isAccessEntry(entry))
	const save = useMutation({
		mutationFn: () =>
			saveSettings(stored.revision, {
				protection,
				block_response: blockResponse,
				blocking_ipv4: blockingIpv4.trim() === '' ? null : blockingIpv4.trim(),
				blocking_ipv6: blockingIpv6.trim() === '' ? null : blockingIpv6.trim(),
				blocked_ttl: Number(blockedTtl),
				list_update_hours: Number(updateHours),
				access: { allowed, blocked },
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
	const v4 = blockingIpv4.trim()
	const v6 = blockingIpv6.trim()
	const customIpOk =
		blockResponse !== 'custom_ip' ||
		((v4 === '' || looksLikeIpv4(v4)) && (v6 === '' || looksLikeIpv6(v6)) && (v4 !== '' || v6 !== ''))
	const valid =
		Number.isInteger(ttl) &&
		ttl >= 0 &&
		ttl <= 86_400 &&
		Number.isInteger(hours) &&
		hours >= 1 &&
		hours <= 168 &&
		customIpOk &&
		badAllowed.length === 0 &&
		badBlocked.length === 0 &&
		allowed.length <= 10_000 &&
		blocked.length <= 10_000
	const changedMeanwhile = save.error instanceof ApiError && save.error.code === 'revision_mismatch'

	const submit = (event: FormEvent) => {
		event.preventDefault()
		save.mutate()
	}
	const status = useQuery(statusQuery)
	const check = useMutation({ mutationFn: checkUpdate })
	const flush = useMutation({ mutationFn: flushCache })
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
					{blockResponse === 'custom_ip' ? (
						<>
							<TextField
								label="Blocked A answers"
								value={blockingIpv4}
								onChange={setBlockingIpv4}
								placeholder="192.168.1.10"
								hint="An IPv4 address, for blocked A queries. Empty answers 0.0.0.0."
							/>
							<TextField
								label="Blocked AAAA answers"
								value={blockingIpv6}
								onChange={setBlockingIpv6}
								placeholder="fd00::10"
								hint="An IPv6 address, for blocked AAAA queries. Empty answers ::."
							/>
						</>
					) : null}
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
				<fieldset className="subform" disabled={save.isPending}>
					<legend>Who may use goethite</legend>
					<TextAreaField
						label="Allowed clients"
						value={allowedText}
						onChange={setAllowedText}
						placeholder={'192.168.1.0/24\nfd00::/64\nanna-phone'}
						hint={
							badAllowed.length > 0
								? `Not an address, a network or a client ID: ${badAllowed.join(', ')}.`
								: allowed.length > 0
									? `Only these ${allowed.length} entries are answered, and this machine itself. Make sure your own devices are on the list.`
									: 'Addresses, networks or client IDs, one per line. Empty: every client is answered.'
						}
					/>
					<TextAreaField
						label="Blocked clients"
						value={blockedText}
						onChange={setBlockedText}
						placeholder={'192.168.1.66\nguest'}
						hint={
							badBlocked.length > 0
								? `Not an address, a network or a client ID: ${badBlocked.join(', ')}.`
								: 'Never answered, even when allowed: addresses, networks or client IDs, one per line. UDP queries get no answer; other connections are closed.'
						}
					/>
				</fieldset>
				<div className="actions">
					<button type="submit" className="button primary" disabled={!valid || save.isPending}>
						Save
					</button>
				</div>
			</form>
			<section className="panel">
				<h2>Cache</h2>
				<p className="muted">
					A fresh answer stays cached until its time to live runs out. Emptying the cache makes the next query
					for a name reach the upstreams again; filtering and local records are not affected.
				</p>
				<button
					type="button"
					className="button small"
					disabled={flush.isPending}
					onClick={() => flush.mutate()}
				>
					{flush.isPending ? 'Emptying…' : 'Empty the cache'}
				</button>
				{flush.isSuccess ? (
					<div className="notice" role="status">
						The cache is empty.
					</div>
				) : null}
				<ErrorNotice error={flush.error} />
			</section>
			<section className="panel">
				<h2>Version</h2>
				<p className="muted">
					This node runs goethite <span className="mono">{status.data?.version ?? '…'}</span>.
				</p>
				<button
					type="button"
					className="button small"
					disabled={check.isPending}
					onClick={() => check.mutate()}
				>
					{check.isPending ? 'Checking…' : 'Check for updates'}
				</button>
				{check.data ? (
					<div className="notice" role="status">
						{check.data.newer ? (
							<>
								goethite <span className="mono">{check.data.latest}</span> is available:{' '}
								<a href={check.data.url} target="_blank" rel="noreferrer">
									release notes
								</a>
								. Upgrade the package or binary as usual; the running node hands over without dropping
								queries.
							</>
						) : (
							<>
								The newest release is goethite <span className="mono">{check.data.latest}</span>
								{check.data.latest === check.data.current
									? ', which this node runs.'
									: `, and this node runs ${check.data.current}.`}
							</>
						)}
					</div>
				) : null}
				<ErrorNotice error={check.error} />
			</section>
		</div>
	)
}
