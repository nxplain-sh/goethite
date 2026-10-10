import { createFileRoute, Link } from '@tanstack/react-router'
import type { ReactNode } from 'react'

import { Header } from '../components/Header'
import { pageHead } from '../head'
import { site } from '../site'

export const Route = createFileRoute('/')({
	head: () => pageHead({ title: site.title, path: '/' }),
	component: Home,
})

function Home() {
	return (
		<div className="page">
			<Header />
			<main id="content" className="home">
				<section className="hero">
					<h1>goethite</h1>
					<p className="tagline">
						A self-hosted, clustered, security-hardened DNS filtering resolver written in Rust. Block ads and
						trackers for your whole network, without giving up security, speed or uptime.
					</p>
					<p>
						<span className="status">Status: pre-alpha · v0.5</span>
					</p>
					<p className="actions">
						<Link to="/$slug/" params={{ slug: 'quick-start' }} className="button primary">
							Quick start
						</Link>
						<a href={site.repository} className="button">
							View on GitHub
						</a>
					</p>
				</section>

				<aside className="callout caution" aria-labelledby="pre-alpha">
					<p className="callout-title" id="pre-alpha">
						Pre-alpha
					</p>
					<p>
						goethite 0.5 filters and caches DNS, and either forwards it over DNS over TLS or HTTPS or resolves
						it from the root servers with DNSSEC validation. Clients reach it over DNS over TLS, HTTPS, QUIC
						or Oblivious DoH, in per-client groups, managed from a web UI, a terminal UI or a REST API. Nodes
						agree on one configuration with Raft (two nodes and a witness survive losing any one), share a
						floating IP, upgrade without dropping a query and confine themselves with Landlock and seccomp.
						Releases are reproducible and signed, with packages and a container image, and{' '}
						<code>goethite migrate</code> brings a Pi-hole or AdGuard Home over. Try it, but do not rely on it
						yet: an external security review is still ahead, and the cards below are the goals. See the{' '}
						<Link to="/$slug/" params={{ slug: 'changelog' }}>
							changelog
						</Link>
						.
					</p>
				</aside>

				<h2>What goethite aims to be</h2>
				<div className="cards">
					<Card title="Security first" icon={<Padlock />}>
						Memory-safe Rust with no <code>unsafe</code> in the parsing and resolving core, no panics on
						network input, fuzzed parsers, and a written threat model.
					</Card>
					<Card title="Fast and bounded" icon={<Bolt />}>
						Sub-millisecond cached answers and million-rule filter lists in a small, bounded memory footprint,
						with every claim backed by a reproducible benchmark.
					</Card>
					<Card title="Highly available" icon={<Nodes />}>
						Every node resolves on its own. Clustering adds replicated config, a floating IP and zero-downtime
						reloads and upgrades.
					</Card>
					<Card title="Everyday filtering" icon={<List />}>
						Hosts files, domain lists and AdGuard-style rules, per-client groups and schedules, CNAME
						uncloaking and safe search.
					</Card>
				</div>
			</main>
		</div>
	)
}

function Card({ title, icon, children }: { title: string; icon: ReactNode; children: ReactNode }) {
	return (
		<section className="card">
			<h3>
				<span className="card-icon">{icon}</span>
				{title}
			</h3>
			<p>{children}</p>
		</section>
	)
}

function Icon({ children }: { children: ReactNode }) {
	return (
		<svg
			viewBox="0 0 24 24"
			width="24"
			height="24"
			fill="none"
			stroke="currentColor"
			strokeWidth="2.5"
			strokeLinecap="square"
			aria-hidden="true"
		>
			{children}
		</svg>
	)
}

function Padlock() {
	return (
		<Icon>
			<rect x="4" y="11" width="16" height="10" />
			<path d="M8 11V7a4 4 0 0 1 8 0v4" />
		</Icon>
	)
}

function Bolt() {
	return (
		<Icon>
			<path d="M13 2 4 14h7l-1 8 9-12h-7z" />
		</Icon>
	)
}

function Nodes() {
	return (
		<Icon>
			<rect x="3" y="3" width="7" height="7" />
			<rect x="14" y="3" width="7" height="7" />
			<rect x="8.5" y="14" width="7" height="7" />
			<path d="M10 6.5h4M6.5 10l3.5 4M17.5 10 14 14" />
		</Icon>
	)
}

function List() {
	return (
		<Icon>
			<path d="M9 6h11M9 12h11M9 18h11M4 6h1M4 12h1M4 18h1" />
		</Icon>
	)
}
