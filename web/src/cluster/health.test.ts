import { describe, expect, it } from 'vite-plus/test'

import type { ClusterStatus } from '../api/client'
import {
	canRemove,
	canTakeOver,
	health,
	lag,
	leaderConfig,
	type Member,
	otherLeaders,
	quorum,
	quorumText,
} from './health'

const CONFIG = { epoch: 7, version: 6 }

function member(node: string, fields: Partial<Member> = {}): Member {
	return {
		node,
		address: `192.0.2.1:8054`,
		this_node: false,
		membership: 'voter',
		witness: false,
		reachable: true,
		state: 'follower',
		config: CONFIG,
		...fields,
	}
}

/** dns2, dns1 leading, and a witness. */
const MEMBERS: Member[] = [
	member('dns2', { this_node: true }),
	member('dns1', { state: 'leader' }),
	member('witness', { witness: true }),
]

/** The members, with `node` changed by `fields`. */
function changed(node: string, fields: Partial<Member>): Member[] {
	return MEMBERS.map((m) => (m.node === node ? { ...m, ...fields } : m))
}

/** dns2's view of a healthy cluster of dns1, dns2 and a witness, changed by `fields`. */
function cluster(fields: Partial<ClusterStatus> = {}): ClusterStatus {
	return {
		node: 'dns2',
		role: 'replica',
		state: 'follower',
		cluster: '8f1c2e40a7b3d915',
		leader: 'dns1',
		term: 4,
		config: CONFIG,
		writable: true,
		members: MEMBERS,
		peer: { node: 'dns1', address: '192.0.2.11:8054', reachable: true },
		problems: [],
		...fields,
	}
}

describe('health', () => {
	it('is healthy when every member is up and nothing needs a person', () => {
		expect(health(cluster())).toBe('healthy')
	})

	it('is degraded when a member is down or there is a problem', () => {
		expect(health(cluster({ members: changed('witness', { reachable: false }) }))).toBe('degraded')
		expect(health(cluster({ problems: ['the cluster has two voters'] }))).toBe('degraded')
	})

	it('is read-only when changes are refused, worse than a member down', () => {
		expect(health(cluster({ writable: false, problems: ['dns1 runs goethite 0.4.0'] }))).toBe('read-only')
	})

	it('has no leader, or waits to be added when in no cluster', () => {
		expect(health(cluster({ leader: null, writable: false }))).toBe('no-leader')
		expect(health(cluster({ cluster: null, leader: null, writable: false }))).toBe('waiting')
	})
})

describe('quorum', () => {
	it('counts voters, witnesses included, and learners not', () => {
		const members = [...MEMBERS, member('dns3', { membership: 'learner' })]
		const q = quorum(cluster({ members }))
		expect(q).toEqual({ voters: 3, up: 3, needed: 2 })
		expect(quorumText(q)).toBe('3 voters, 2 needed: can lose 1')
	})

	it('says when no voter can be lost, or too few are up', () => {
		expect(quorumText({ voters: 1, up: 1, needed: 1 })).toBe('1 voter, 1 needed: can lose none')
		expect(quorumText({ voters: 3, up: 1, needed: 2 })).toBe('3 voters, 2 needed: only 1 up')
		expect(quorumText({ voters: 0, up: 0, needed: 1 })).toBe('no voters yet')
	})
})

describe('lag', () => {
	it('compares with the leader within one history', () => {
		expect(lag({ epoch: 7, version: 4 }, CONFIG)).toEqual({ kind: 'behind', changes: 2 })
		expect(lag(CONFIG, CONFIG)).toEqual({ kind: 'current' })
		// Checked after the leader was: not behind.
		expect(lag({ epoch: 7, version: 8 }, CONFIG)).toEqual({ kind: 'current' })
	})

	it('cannot compare across histories, or without both versions', () => {
		expect(lag({ epoch: 9, version: 1 }, CONFIG)).toEqual({ kind: 'other' })
		expect(lag(null, CONFIG)).toEqual({ kind: 'unknown' })
		expect(lag(CONFIG, undefined)).toEqual({ kind: 'unknown' })
	})

	it("takes the leader's version from its member entry", () => {
		const members = changed('dns1', { config: { epoch: 7, version: 9 } })
		expect(leaderConfig(cluster({ members }))).toEqual({ epoch: 7, version: 9 })
		expect(leaderConfig(cluster({ leader: null }))).toBeUndefined()
	})
})

describe('recovery', () => {
	it('offers a takeover only without a leader', () => {
		expect(canTakeOver(cluster())).toBe(false)
		expect(canTakeOver(cluster({ leader: null }))).toBe(true)
		expect(canTakeOver(cluster({ cluster: null, leader: null }))).toBe(true)
	})

	it('finds members that lead another cluster', () => {
		// dns1 took over; this node, dns2, still leads the old cluster.
		const members = [
			member('dns2', { this_node: true, state: 'leader' }),
			member('dns1', { state: 'leader', config: { epoch: 9, version: 1 } }),
		]
		const split = cluster({ state: 'leader', leader: 'dns2', members })
		expect(otherLeaders(split).map((m) => m.node)).toEqual(['dns1'])
		expect(otherLeaders(cluster())).toEqual([])
		// Waiting to be added: the leader adds it, nothing to join.
		expect(otherLeaders(cluster({ cluster: null, leader: null }))).toEqual([])
		// Unreachable: last seen leading, not now.
		const gone = members.map((m) => (m.node === 'dns1' ? { ...m, reachable: false } : m))
		expect(otherLeaders(cluster({ state: 'leader', leader: 'dns2', members: gone }))).toEqual([])
	})

	it('removes other members that are in the cluster and down, while changes work', () => {
		const [self, leader, witness] = changed('witness', { reachable: false })
		if (self === undefined || leader === undefined || witness === undefined) {
			throw new Error('three members')
		}
		expect(canRemove(cluster(), witness)).toBe(true)
		expect(canRemove(cluster(), { ...witness, reachable: true })).toBe(false)
		expect(canRemove(cluster(), self)).toBe(false)
		expect(canRemove(cluster(), { ...leader, reachable: false })).toBe(false)
		expect(canRemove(cluster(), { ...witness, membership: 'configured' })).toBe(false)
		expect(canRemove(cluster({ writable: false }), witness)).toBe(false)
	})
})
