import { createFileRoute, Link } from '@tanstack/react-router'
import { useState, type ReactNode } from 'react'

import { Header } from '../components/Header'
import { pageHead } from '../head'
import { absolute, site } from '../site'

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
						<span className="status">Status: pre-alpha · v0.6</span>
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

				<section className="install">
					<h2>Install</h2>
					<p>
						One command on Linux, amd64 or arm64: it picks the <code>.deb</code>, the <code>.rpm</code> or the
						tarball for this machine, checks the download against the release's <code>SHA256SUMS</code>, and
						installs goethite without starting it. Prefer to read code before piping it to a shell?{' '}
						<a href={`${site.repository}/blob/main/site/public/install.sh`}>The script</a> is in the
						repository.
					</p>
					<Command>{`curl -fsSL ${absolute('/install.sh')} | sh`}</Command>
					<div className="cards">
						<section className="card">
							<h3>
								<span className="card-icon">
									<Container />
								</span>
								Docker or Podman
							</h3>
							<p>The distroless image serves from an unprivileged account (65532) with no capabilities.</p>
							<Command>{`docker run -d --name goethite --restart unless-stopped \\
  -p 53:53/udp -p 53:53/tcp -v goethite:/var/lib/goethite \\
  ghcr.io/nxplain-sh/goethite:0.6`}</Command>
							<p>
								The{' '}
								<Link to="/$slug/" hash="in-a-container" params={{ slug: 'install' }}>
									install guide
								</Link>{' '}
								has Compose files for one node and for a cluster.
							</p>
						</section>
						<section className="card">
							<h3>
								<span className="card-icon">
									<Wheel />
								</span>
								Kubernetes (Helm)
							</h3>
							<p>
								One node: DNS on port 53, the store on a PersistentVolumeClaim, the pod unprivileged with a
								sysctl to bind the port, or <code>hostNetwork</code> to serve the whole network.
							</p>
							<Command>{`git clone --depth 1 https://github.com/nxplain-sh/goethite
helm install goethite ./goethite/deploy/helm/goethite`}</Command>
							<p>
								The{' '}
								<Link to="/$slug/" hash="on-kubernetes-helm" params={{ slug: 'install' }}>
									install guide
								</Link>{' '}
								covers the values.
							</p>
						</section>
						<section className="card">
							<h3>
								<span className="card-icon">
									<Package />
								</span>
								Packages, tarball or source
							</h3>
							<p>
								Every release has a reproducible, attested <code>.deb</code>, <code>.rpm</code> and tarball,
								checked with <code>gh attestation verify</code>. The{' '}
								<Link to="/$slug/" params={{ slug: 'install' }}>
									install guide
								</Link>{' '}
								walks through each, and <a href={`${site.repository}/releases`}>releases</a> lists them all.
							</p>
						</section>
					</div>
				</section>

				<aside className="callout caution" aria-labelledby="pre-alpha">
					<p className="callout-title" id="pre-alpha">
						Pre-alpha
					</p>
					<p>
						goethite 0.6 filters and caches DNS, and either forwards it over DNS over TLS or HTTPS or resolves
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

/** A command with a copy button, styled like the code blocks on the docs pages. */
function Command({ children }: { children: string }) {
	const [copied, setCopied] = useState(false)

	function copy() {
		void navigator.clipboard.writeText(children).then(() => {
			setCopied(true)
			setTimeout(() => setCopied(false), 2000)
		})
	}

	return (
		<div className="code">
			<pre>
				<code>{children}</code>
			</pre>
			<button type="button" className="copy" onClick={copy}>
				{copied ? 'Copied' : 'Copy'}
			</button>
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

function Container() {
	return (
		<Icon>
			<rect x="3" y="8" width="18" height="12" />
			<path d="M3 12h18M7 8v4M12 8v4M17 8v4M8 4h8l2 4H6z" />
		</Icon>
	)
}

function Wheel() {
	return (
		<Icon>
			<circle cx="12" cy="12" r="9" />
			<circle cx="12" cy="12" r="3" />
			<path d="M12 3v6M12 15v6M3 12h6M15 12h6M5.6 5.6l4.3 4.3M14.1 14.1l4.3 4.3M18.4 5.6l-4.3 4.3M9.9 14.1l-4.3 4.3" />
		</Icon>
	)
}

function Package() {
	return (
		<Icon>
			<path d="M4 8h16v12H4zM4 8l2-4h12l2 4M12 8v12M9 4v4M15 4v4" />
		</Icon>
	)
}
