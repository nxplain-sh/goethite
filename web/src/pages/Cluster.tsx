import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { api, ApiError, call, type ClusterStatus } from '../api/client'
import { statusQuery } from '../api/queries'
import {
	canRemove,
	canTakeOver,
	type ConfigVersion,
	HEALTH,
	type Health,
	health,
	lag,
	leaderConfig,
	type Member,
	otherLeaders,
	quorum,
	quorumText,
} from '../cluster/health'
import { DOCS_URL } from '../components/DocsLinks'
import { ErrorNotice, Panel } from '../components/ui'
import { ago, dateTime } from '../format'

/** The HA guide's section on getting a cluster back. */
const RECOVERY_DOCS = `${DOCS_URL}ha/#when-the-cluster-cannot-elect-a-leader`

/** The cluster this node is in: how it is doing, each member, and the ways back when it cannot elect a leader. */
export function Cluster() {
	const status = useQuery(statusQuery)
	const data = status.data
	if (data === undefined) {
		return <ErrorNotice error={status.error} />
	}
	const cluster = data.cluster
	if (cluster == null) {
		return (
			<div className="grid-page">
				<h1>Cluster</h1>
				<div className="panel">
					<p>
						This node is not in a cluster. Nodes that share one configuration, with a witness and a floating
						IP, are set up in their config files: see{' '}
						<a href={`${DOCS_URL}ha/`} target="_blank" rel="noopener noreferrer">
							High availability
						</a>
						.
					</p>
				</div>
			</div>
		)
	}
	const reference = leaderConfig(cluster)
	return (
		<div className="grid-page">
			<div className="page-head">
				<h1>Cluster</h1>
				<span className="muted mono">
					{cluster.cluster == null ? 'in no cluster yet' : `cluster ${cluster.cluster}`} · term{' '}
					{cluster.term ?? 0}
				</span>
			</div>
			<HealthBand cluster={cluster} />
			<section className="members" aria-label="Members">
				{(cluster.members ?? []).map((member) => (
					<MemberCard
						key={member.node}
						cluster={cluster}
						member={member}
						reference={reference}
						thisVersion={data.version}
					/>
				))}
			</section>
			<div className="grid">
				{cluster.sync == null ? null : <SyncPanel sync={cluster.sync} leader={cluster.leader} />}
				<Recovery cluster={cluster} />
			</div>
		</div>
	)
}

/** How the cluster is doing, in a word and a sentence, and what that rests on. */
function HealthBand({ cluster }: { cluster: ClusterStatus }) {
	const state = health(cluster)
	const { label, tone } = HEALTH[state]
	const down = (cluster.members ?? []).filter((member) => !member.reachable).map((member) => member.node)
	return (
		<section className={`health ${tone}`} aria-label="Health">
			<div className="health-label">{label}</div>
			<p>{sentence(state, cluster, down)}</p>
			<dl className="health-facts">
				<div>
					<dt>Leader</dt>
					<dd>{cluster.leader ?? 'none'}</dd>
				</div>
				<div>
					<dt>Changes</dt>
					<dd>{cluster.writable ? 'work' : 'refused'}</dd>
				</div>
				<div>
					<dt>Voters</dt>
					<dd>{quorumText(quorum(cluster))}</dd>
				</div>
				<div>
					<dt>This node</dt>
					<dd>
						{cluster.node}, {cluster.state ?? 'unknown'}, config version {cluster.config.version}
					</dd>
				</div>
			</dl>
		</section>
	)
}

function sentence(state: Health, cluster: ClusterStatus, down: string[]): string {
	switch (state) {
		case 'waiting':
			return "This node waits to be added: a cluster's leader adds it once it lists this node in its config file. Until then it answers DNS with its own configuration."
		case 'no-leader':
			return 'Configuration changes are frozen until most voters reach each other again. Every member keeps answering DNS.'
		case 'read-only':
			return `${cluster.leader ?? 'The leader'} leads, but changes through this node are refused: ${
				cluster.sync?.error ?? cluster.problems[0] ?? 'see the problems above'
			}.`
		case 'degraded':
			return down.length > 0
				? `Changes work, but ${list(down)} ${down.length === 1 ? 'is' : 'are'} down.`
				: 'Changes work, but something needs a look: see the problems above.'
		case 'healthy':
			return 'Every member is up, and changes work.'
	}
}

/** `a`, `a and b`, `a, b and c`. */
function list(items: string[]): string {
	return items.length <= 1
		? items.join('')
		: `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`
}

const STATE_LABEL: Record<NonNullable<Member['state']>, string> = {
	leader: 'LEADER',
	follower: 'FOLLOWER',
	candidate: 'CANDIDATE',
	learner: 'LEARNER',
	stopped: 'STOPPED',
	unknown: 'UNKNOWN',
}

/** One member, as last seen: what it does, whether it votes, and how far behind the leader it is. */
function MemberCard({
	cluster,
	member,
	reference,
	thisVersion,
}: {
	cluster: ClusterStatus
	member: Member
	reference: ConfigVersion | undefined
	thisVersion: string
}) {
	const leads = member.node === cluster.leader
	const classes = [
		'member',
		leads ? 'leader' : '',
		member.state === 'follower' ? 'follower' : '',
		member.witness ? 'witness' : '',
		member.reachable ? '' : 'down',
	]
		.filter(Boolean)
		.join(' ')
	// A learner's state says what its membership says.
	const showState = member.state != null && !(member.state === 'learner' && member.membership === 'learner')
	return (
		<article className={classes} aria-label={member.node}>
			<header>
				<h2>{member.node}</h2>
				{member.this_node ? <span className="this-node">this node</span> : null}
			</header>
			<div className="badges">
				{member.reachable ? (
					<span className="badge ok">UP</span>
				) : (
					<span className="badge blocked">DOWN</span>
				)}
				{showState && member.state != null ? (
					<span className="badge">{STATE_LABEL[member.state]}</span>
				) : null}
				<span className="badge">
					{member.membership === 'voter'
						? 'VOTER'
						: member.membership === 'learner'
							? 'LEARNER'
							: 'NOT ADDED YET'}
				</span>
				{member.witness ? <span className="badge">WITNESS</span> : null}
			</div>
			<dl className="facts">
				<dt>Address</dt>
				<dd className="mono">{member.address}</dd>
				<dt>Version</dt>
				<dd>
					<span className="mono">{member.version ?? '–'}</span>
					{member.version != null && member.version !== thisVersion ? (
						<span className="badge blocked">NOT {thisVersion}</span>
					) : null}
				</dd>
				<dt>Config</dt>
				<dd>
					{member.config == null ? (
						'–'
					) : (
						<>
							<span className="mono">version {member.config.version}</span>
							{leads ? null : <LagNote config={member.config} reference={reference} />}
						</>
					)}
				</dd>
				{member.matched == null ? null : (
					<>
						<dt>Log</dt>
						<dd className="mono">holds entry {member.matched}</dd>
					</>
				)}
				{member.checked_at == null ? null : (
					<>
						<dt>Checked</dt>
						<dd>{ago(member.checked_at)}</dd>
					</>
				)}
			</dl>
			{member.error == null ? null : <p className="member-error">{member.error}</p>}
			{canRemove(cluster, member) ? <RemoveMember node={member.node} /> : null}
		</article>
	)
}

function LagNote({ config, reference }: { config: ConfigVersion; reference: ConfigVersion | undefined }) {
	const behind = lag(config, reference)
	switch (behind.kind) {
		case 'behind':
			return (
				<span className="badge accent">
					{behind.changes} {behind.changes === 1 ? 'CHANGE' : 'CHANGES'} BEHIND
				</span>
			)
		case 'other':
			return <span className="badge blocked">OTHER HISTORY</span>
		default:
			return null
	}
}

/** How this node follows the leader. */
function SyncPanel({
	sync,
	leader,
}: {
	sync: NonNullable<ClusterStatus['sync']>
	leader: ClusterStatus['leader']
}) {
	return (
		<Panel title="Following the leader">
			<dl className="facts">
				<dt>Leader</dt>
				<dd className="mono">{leader ?? 'none'}</dd>
				<dt>Last heard</dt>
				<dd>{sync.last_contact == null ? 'never' : ago(sync.last_contact)}</dd>
				<dt>Last change</dt>
				<dd>{sync.last_copy == null ? 'none yet' : `${dateTime(sync.last_copy)}, ${ago(sync.last_copy)}`}</dd>
			</dl>
			{sync.error == null ? null : <p className="member-error">{sync.error}</p>}
		</Panel>
	)
}

/** Takes the cluster over, or joins another, when that is the way out. */
function Recovery({ cluster }: { cluster: ClusterStatus }) {
	const settle = useSettle()
	const takeOver = canTakeOver(cluster)
	const others = otherLeaders(cluster)
	return (
		<Panel title="Recovery">
			{takeOver ? (
				<div className="recovery-action">
					<h3>{cluster.cluster == null ? 'Start a cluster here' : 'Take the cluster over'}</h3>
					<p>
						{cluster.cluster == null
							? `${cluster.node} starts a new cluster as its only voter, with its own configuration, as bootstrap = true would. The members in its config file join as they answer.`
							: `If most voters are gone for good, ${cluster.node} can start a new cluster as its only voter, with its own configuration. The other members join it once they are back and you choose to join on them.`}
					</p>
					<Guarded
						label={cluster.cluster == null ? 'Start a cluster here' : 'Take the cluster over'}
						confirm={
							cluster.cluster == null ? `Start it on ${cluster.node}` : `Take it over from ${cluster.node}`
						}
						force="even though a leader answers: two clusters run until one side joins the other"
						run={(force) => call(api.POST('/api/v1/cluster/promote', { body: { force } }))}
						onDone={settle}
					/>
				</div>
			) : null}
			{others.map((other) => (
				<div key={other.node} className="recovery-action">
					<h3>Join {other.node}&apos;s cluster</h3>
					<p>
						{other.node} leads another cluster. One side has to join the other. To keep this cluster, choose
						to join on {other.node}&apos;s own page instead. To keep {other.node}&apos;s, {cluster.node}{' '}
						leaves this cluster, and {other.node} adds it and replaces its configuration with its own.
					</p>
					<Guarded
						label={`Join ${other.node}'s cluster`}
						confirm={`Leave this cluster for ${other.node}'s`}
						force="even though no leader of another cluster answers: this node is then in no cluster"
						run={(force) => call(api.POST('/api/v1/cluster/demote', { body: { force } }))}
						onDone={settle}
					/>
				</div>
			))}
			{takeOver || others.length > 0 ? null : (
				<p className="muted">
					Nothing to recover: {cluster.leader} leads, and changes go through it. When the cluster cannot elect
					a leader, this page offers to take it over from {cluster.node}.
				</p>
			)}
			<p className="hint">
				These act on this node, {cluster.node}.{' '}
				<a href={RECOVERY_DOCS} target="_blank" rel="noopener noreferrer">
					How recovery works
				</a>
			</p>
		</Panel>
	)
}

/** Removes a member for good, after a second click. */
function RemoveMember({ node }: { node: string }) {
	const settle = useSettle()
	return (
		<div className="member-remove">
			<Guarded
				label="Remove"
				confirm={`Remove ${node} for good`}
				note={`First take ${node} out of every member's config file and restart them, or it is added again.`}
				run={() => call(api.DELETE('/api/v1/cluster/members/{node}', { params: { path: { node } } }))}
				onDone={settle}
				small
			/>
		</div>
	)
}

/** Puts a cluster action's answer in place, and fetches the rest again: the configuration may be another now. */
function useSettle(): (cluster: ClusterStatus) => void {
	const queryClient = useQueryClient()
	return (cluster) => {
		queryClient.setQueryData(statusQuery.queryKey, (old) => (old === undefined ? old : { ...old, cluster }))
		void queryClient.invalidateQueries()
	}
}

/**
 * An action that takes a second click, like Delete: no browser dialog. When
 * goethite refuses it as not applying (409) and the action has a `force`,
 * the refusal offers to do it anyway, saying what that means.
 */
function Guarded({
	label,
	confirm,
	note,
	force,
	run,
	onDone,
	small,
}: {
	label: string
	confirm: string
	note?: string
	force?: string
	run: (force: boolean) => Promise<ClusterStatus>
	onDone: (cluster: ClusterStatus) => void
	small?: boolean
}) {
	const [asking, setAsking] = useState(false)
	const [forced, setForced] = useState(false)
	const action = useMutation({
		mutationFn: () => run(forced),
		onSuccess: (cluster) => {
			setAsking(false)
			setForced(false)
			onDone(cluster)
		},
	})
	const size = small === true ? ' small' : ''
	const refused = action.error instanceof ApiError && action.error.status === 409
	if (!asking) {
		return (
			<div className="guarded">
				<button type="button" className={`button danger-outline${size}`} onClick={() => setAsking(true)}>
					{label}
				</button>
			</div>
		)
	}
	return (
		<div className="guarded">
			{note === undefined ? null : <p className="hint">{note}</p>}
			{refused && force !== undefined ? (
				<label className="check">
					<input type="checkbox" checked={forced} onChange={(event) => setForced(event.target.checked)} />
					Do it anyway, {force}
				</label>
			) : null}
			<span className="confirm">
				<button
					type="button"
					className={`button danger${size}`}
					disabled={action.isPending}
					onClick={() => action.mutate()}
				>
					{confirm}
				</button>
				<button
					type="button"
					className={`button${size}`}
					onClick={() => {
						setAsking(false)
						setForced(false)
						action.reset()
					}}
				>
					Keep it
				</button>
			</span>
			<ErrorNotice error={action.error} />
		</div>
	)
}
