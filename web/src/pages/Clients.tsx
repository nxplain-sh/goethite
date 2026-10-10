import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { useState } from 'react'

import type { Client, Status } from '../api/client'
import { statusQuery } from '../api/queries'
import { allClientsQuery, clientQuery, deleteClient, groupsQuery, saveClient } from '../api/resources'
import { Editor, Loading, ManagedBadge } from '../components/editor'
import { SelectField, TextAreaField, TextField } from '../components/form'
import { ErrorNotice } from '../components/ui'
import {
	clientForm,
	type ClientForm,
	clientSpec,
	DEFAULT_GROUP,
	isClientId,
	parseAddresses,
	parseClientIds,
} from '../forms/forms'
import { count } from '../format'

/** How many clients the table shows at once; the filter narrows them. */
const SHOWN = 500

/** Devices and networks, and their groups. */
export function Clients() {
	const clients = useQuery(allClientsQuery)
	const groups = useQuery(groupsQuery)
	const names = new Map((groups.data ?? []).map((group) => [group.id, group.spec.name]))
	const [filter, setFilter] = useState('')
	const needle = filter.trim().toLowerCase()
	const matching = (clients.data ?? []).filter(
		(client) =>
			needle === '' ||
			client.spec.name.toLowerCase().includes(needle) ||
			client.spec.addresses.some((address) => address.includes(needle)) ||
			(client.spec.ids ?? []).some((id) => id.includes(needle)),
	)
	return (
		<div className="grid-page">
			<div className="page-head">
				<h1>Clients</h1>
				<Link to="/clients/$id" params={{ id: 'new' }} className="button primary">
					New client
				</Link>
			</div>
			<p className="muted">
				A client is a device or network, known by its addresses or its client IDs. A query belongs to the
				client whose ID it carries (over DNS over TLS, HTTPS or QUIC), or else to the client with the most
				specific matching address; its group decides the filtering.
			</p>
			<ErrorNotice error={clients.error ?? groups.error} />
			<div className="panel">
				<div className="page-head">
					<label className="field grow">
						Filter
						<input
							className="input"
							type="search"
							value={filter}
							spellCheck={false}
							placeholder="name, address or client ID"
							onChange={(event) => setFilter(event.target.value)}
						/>
					</label>
					<span className="muted">
						{count(matching.length)} of {count(clients.data?.length ?? 0)} clients
						{matching.length > SHOWN ? `, the first ${count(SHOWN)} shown` : ''}
					</span>
				</div>
				<table className="table">
					<thead>
						<tr>
							<th>Name</th>
							<th>Addresses</th>
							<th>Client IDs</th>
							<th>Group</th>
						</tr>
					</thead>
					<tbody>
						{matching.slice(0, SHOWN).map((client) => (
							<tr key={client.id}>
								<td>
									<Link to="/clients/$id" params={{ id: client.id }}>
										{client.spec.name}
									</Link>{' '}
									<ManagedBadge managedBy={client.spec.managed_by} />
								</td>
								<td className="name">{client.spec.addresses.join(', ')}</td>
								<td className="name">{(client.spec.ids ?? []).join(', ')}</td>
								<td>{names.get(client.spec.group ?? DEFAULT_GROUP) ?? client.spec.group}</td>
							</tr>
						))}
					</tbody>
				</table>
				{clients.data?.length === 0 ? (
					<p className="muted">No clients yet: every query is filtered by the default group.</p>
				) : null}
			</div>
		</div>
	)
}

/** An existing client (`id`), or a new one ("new"). */
export function ClientEditor({ id }: { id: string }) {
	const isNew = id === 'new'
	const query = useQuery({ ...clientQuery(id), enabled: !isNew })
	if (!isNew && query.data === undefined) {
		return <Loading error={query.error} what="client" />
	}
	return (
		<ClientFields
			key={query.data?.revision ?? 'new'}
			stored={query.data}
			reload={() => void query.refetch()}
		/>
	)
}

function ClientFields({ stored, reload }: { stored: Client | undefined; reload: () => void }) {
	const [form, setForm] = useState<ClientForm>(() => clientForm(stored?.spec))
	const groups = useQuery(groupsQuery)
	const set =
		<K extends keyof ClientForm>(key: K) =>
		(value: ClientForm[K]) =>
			setForm((previous) => ({ ...previous, [key]: value }))
	const addresses = parseAddresses(form.addresses)
	const ids = parseClientIds(form.ids)
	const invalidIds = ids.filter((id) => !isClientId(id))
	const encrypted = useQuery(statusQuery).data?.encrypted
	return (
		<Editor
			title={stored === undefined ? 'New client' : stored.spec.name}
			what="client"
			back="/clients"
			backLabel="Clients"
			stored={stored}
			queryKey={['clients']}
			save={() => saveClient(stored, clientSpec(form, stored?.spec.managed_by))}
			remove={stored === undefined ? undefined : () => deleteClient(stored)}
			reload={reload}
			canSave={
				form.name.trim() !== '' &&
				(addresses.length > 0 || ids.length > 0) &&
				invalidIds.length === 0 &&
				ids.length <= 16
			}
		>
			<TextField label="Name" value={form.name} onChange={set('name')} mono={false} required />
			<TextAreaField
				label="Addresses"
				value={form.addresses}
				onChange={set('addresses')}
				placeholder={'192.168.1.23\n192.168.50.0/24\nfd00::23'}
				hint={`IP addresses or networks, one per line: ${count(addresses.length)} of up to 64. None is fine for a client with a client ID.`}
			/>
			<TextAreaField
				label="Client IDs"
				value={form.ids}
				onChange={set('ids')}
				placeholder={'anna-phone\nliving-room-tv'}
				hint={
					invalidIds.length > 0
						? `Not a client ID: ${invalidIds.join(', ')}. Use lowercase letters, digits and hyphens, not at either end.`
						: `Names the device over DNS over TLS, HTTPS or QUIC, on any network: one per line, ${count(ids.length)} of up to 16.`
				}
			/>
			{ids.length > 0 && invalidIds.length === 0 ? (
				<ClientIdUse id={ids[0] ?? ''} encrypted={encrypted} />
			) : null}
			<SelectField
				label="Group"
				value={form.group}
				onChange={set('group')}
				options={(groups.data ?? [{ id: DEFAULT_GROUP, spec: { name: 'Default' } }]).map((group) => ({
					value: group.id,
					label: group.spec.name,
				}))}
			/>
			<TextField label="Comment" value={form.comment} onChange={set('comment')} mono={false} />
		</Editor>
	)
}

/** The port of an address such as `0.0.0.0:443` or `[::]:443`. */
function port(address: string): string {
	return address.slice(address.lastIndexOf(':') + 1)
}

/** How a device uses its client ID with this node. */
function ClientIdUse({ id, encrypted }: { id: string; encrypted: Status['encrypted'] }) {
	if (encrypted == null) {
		return (
			<p className="hint">
				This node does not serve DNS over TLS or HTTPS: client IDs take effect once{' '}
				<span className="mono">[server.tls]</span> is set up in its config file.
			</p>
		)
	}
	const host = encrypted.server_name ?? 'your-server'
	const https = encrypted.doh[0]
	const tls = encrypted.dot[0]
	const quic = encrypted.doq[0]
	const httpsPort = https === undefined || port(https) === '443' ? '' : `:${port(https)}`
	return (
		<div className="subform" role="note" aria-label="Using the client ID">
			<p>Set up the device with:</p>
			<dl className="setup">
				{https === undefined ? null : (
					<>
						<dt>DNS over HTTPS</dt>
						<dd className="mono">{`https://${host}${httpsPort}/dns-query/${id}`}</dd>
					</>
				)}
				{tls === undefined || encrypted.server_name == null ? null : (
					<>
						<dt>DNS over TLS</dt>
						<dd className="mono">
							{`${id}.${encrypted.server_name}`}
							{port(tls) === '853' ? null : <span className="muted">{` (port ${port(tls)})`}</span>}
						</dd>
					</>
				)}
				{quic === undefined || encrypted.server_name == null ? null : (
					<>
						<dt>DNS over QUIC</dt>
						<dd className="mono">{`quic://${id}.${encrypted.server_name}${port(quic) === '853' ? '' : `:${port(quic)}`}`}</dd>
					</>
				)}
				{https === undefined || encrypted.odoh !== true ? null : (
					<>
						<dt>Oblivious DoH target</dt>
						<dd className="mono">{`https://${host}${httpsPort}/dns-query/${id}`}</dd>
					</>
				)}
			</dl>
			{https === undefined || encrypted.odoh !== true ? null : (
				<p className="hint">
					Through an Oblivious DoH proxy, goethite sees the proxy's address, not the device's: with the ID in
					the target path it still knows the device, without it the device is anonymous and filtered as the
					proxy is.
				</p>
			)}
			{encrypted.server_name == null ? (
				<p className="hint">
					With <span className="mono">server_name</span> set in <span className="mono">[server.tls]</span>,
					DNS over TLS and QUIC can carry the ID too, as <span className="mono">{`${id}.<server name>`}</span>
					.
				</p>
			) : null}
		</div>
	)
}
