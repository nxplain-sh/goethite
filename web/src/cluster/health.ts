// What the cluster page works out from a node's cluster status: how the
// cluster is doing, how many voters it can lose, how far each member's
// configuration is behind the leader's, and which recovery steps apply.

import type { ClusterStatus, Schemas } from '../api/client'

export type Member = Schemas['MemberStatus']
export type ConfigVersion = Schemas['ConfigVersion']

/**
 * How the cluster is doing, as this node sees it:
 * - `waiting`: this node is in no cluster yet, and waits to be added;
 * - `no-leader`: no leader, so the configuration cannot change;
 * - `read-only`: a leader, but changes through this node are refused;
 * - `degraded`: changes work, but a member is down or something needs a person;
 * - `healthy`: every member is up and nothing needs a person.
 */
export type Health = 'waiting' | 'no-leader' | 'read-only' | 'degraded' | 'healthy'

/** Each health in words; the tone, a badge class, only reinforces it. */
export const HEALTH: Record<Health, { label: string; tone: 'ok' | 'accent' | 'blocked' }> = {
	waiting: { label: 'WAITING TO BE ADDED', tone: 'accent' },
	'no-leader': { label: 'NO LEADER', tone: 'blocked' },
	'read-only': { label: 'READ-ONLY', tone: 'blocked' },
	degraded: { label: 'DEGRADED', tone: 'accent' },
	healthy: { label: 'HEALTHY', tone: 'ok' },
}

export function health(cluster: ClusterStatus): Health {
	if (cluster.cluster == null) {
		return 'waiting'
	}
	if (cluster.leader == null) {
		return 'no-leader'
	}
	if (!cluster.writable) {
		return 'read-only'
	}
	if (cluster.problems.length > 0 || (cluster.members ?? []).some((member) => !member.reachable)) {
		return 'degraded'
	}
	return 'healthy'
}

/** The voters, and how many of them it takes to elect a leader and make a change. */
export interface Quorum {
	/** Members that vote, witnesses included. */
	voters: number
	/** Of those, the ones that answered their last check. */
	up: number
	/** A majority of the voters. */
	needed: number
}

export function quorum(cluster: ClusterStatus): Quorum {
	const voters = (cluster.members ?? []).filter((member) => member.membership === 'voter')
	return {
		voters: voters.length,
		up: voters.filter((member) => member.reachable).length,
		needed: Math.floor(voters.length / 2) + 1,
	}
}

/** The quorum in words: `3 voters, 2 needed: can lose 1`. */
export function quorumText({ voters, up, needed }: Quorum): string {
	if (voters === 0) {
		return 'no voters yet'
	}
	const head = `${voters} ${voters === 1 ? 'voter' : 'voters'}, ${needed} needed`
	if (up < needed) {
		return `${head}: only ${up} up`
	}
	const spare = up - needed
	return `${head}: can lose ${spare === 0 ? 'none' : spare}`
}

/**
 * How a member's configuration compares with the leader's:
 * - `current`: it holds every change the leader had when last checked;
 * - `behind`: it misses `changes` of them;
 * - `other`: it has another history, from another cluster or from before it joined;
 * - `unknown`: there is nothing to compare.
 */
export type Lag =
	| { kind: 'current' }
	| { kind: 'behind'; changes: number }
	| { kind: 'other' }
	| { kind: 'unknown' }

export function lag(config: ConfigVersion | null | undefined, leader: ConfigVersion | undefined): Lag {
	if (config == null || leader === undefined) {
		return { kind: 'unknown' }
	}
	if (config.epoch !== leader.epoch) {
		return { kind: 'other' }
	}
	return config.version < leader.version
		? { kind: 'behind', changes: leader.version - config.version }
		: { kind: 'current' }
}

/** The leader's configuration version, if the leader is known and was reached. */
export function leaderConfig(cluster: ClusterStatus): ConfigVersion | undefined {
	if (cluster.leader == null) {
		return undefined
	}
	const leader = (cluster.members ?? []).find((member) => member.node === cluster.leader)
	return leader?.config ?? undefined
}

/**
 * Whether this node can take the cluster over: there is no leader, so a
 * new cluster with this node as its only voter is the way out.
 */
export function canTakeOver(cluster: ClusterStatus): boolean {
	return cluster.leader == null && cluster.state !== 'leader'
}

/**
 * Members that lead another cluster: they answered as leaders, but this
 * node's cluster has another leader, or none. After a takeover, one side
 * joins the other. A node in no cluster yet joins none: it waits to be added.
 */
export function otherLeaders(cluster: ClusterStatus): Member[] {
	if (cluster.cluster == null) {
		return []
	}
	return (cluster.members ?? []).filter(
		(member) =>
			!member.this_node && member.reachable && member.state === 'leader' && member.node !== cluster.leader,
	)
}

/**
 * Whether to offer removing `member` through this node: another member that
 * is in the cluster and down, not its leader, while changes work. A member
 * taken out of service is stopped; one that answers is, as a rule, still in
 * the config files, and goethite would refuse.
 */
export function canRemove(cluster: ClusterStatus, member: Member): boolean {
	return (
		cluster.writable &&
		!member.this_node &&
		!member.reachable &&
		member.node !== cluster.leader &&
		member.membership !== 'configured'
	)
}
