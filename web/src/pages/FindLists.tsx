import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { useState } from 'react'

import type { DirectoryEntry } from '../api/client'
import { directoryListQuery, directoryQuery, listsQuery } from '../api/queries'
import { ErrorNotice } from '../components/ui'
import { count, dateTime } from '../format'

/** How many matches the page shows; a narrower search finds the others. */
const SHOWN = 100

/** The longest list name goethite keeps. */
const MAX_NAME = 100

/** Searches the FilterLists directory for lists goethite can use. */
export function FindLists() {
	const directory = useQuery(directoryQuery)
	const [search, setSearch] = useState('')
	const [tag, setTag] = useState('')
	const all = directory.data?.lists ?? []
	const tags = [...new Set(all.flatMap((list) => list.tags))].sort()
	const needle = search.trim().toLowerCase()
	const matching = all.filter(
		(list) =>
			(tag === '' || list.tags.includes(tag)) &&
			(needle === '' ||
				list.name.toLowerCase().includes(needle) ||
				list.description.toLowerCase().includes(needle)),
	)

	return (
		<div className="grid-page">
			<p>
				<Link to="/lists">← Filter lists</Link>
			</p>
			<h1>Find lists</h1>
			<p className="muted">
				The <a href="https://filterlists.com" target="_blank" rel="noreferrer noopener">FilterLists</a>{' '}
				directory, as far as goethite can use it: hosts files, domain lists and adblock-style domain rules.
				Allowlists are left out. Adding a list opens it for you to check before it is saved.
			</p>
			{directory.isPending ? <p className="panel">Asking FilterLists…</p> : null}
			<ErrorNotice error={directory.error} />
			{directory.data ? (
				<>
					<div className="log-tools" role="search">
						<label className="field grow">
							Name or description
							<input
								className="input"
								type="search"
								value={search}
								spellCheck={false}
								placeholder="hagezi, tracking, malware…"
								onChange={(event) => setSearch(event.target.value)}
							/>
						</label>
						<label className="field">
							Topic
							<select className="select" value={tag} onChange={(event) => setTag(event.target.value)}>
								<option value="">All topics</option>
								{tags.map((name) => (
									<option key={name} value={name}>
										{name}
									</option>
								))}
							</select>
						</label>
					</div>
					<div className="panel">
						<p className="muted" role="status">
							{count(matching.length)} of {count(all.length)} lists
							{matching.length > SHOWN ? `, the first ${count(SHOWN)} shown: narrow the search` : ''}
						</p>
						<ul className="directory">
							{matching.slice(0, SHOWN).map((list) => (
								<DirectoryRow key={list.id} list={list} />
							))}
						</ul>
						<p className="muted">
							Names, descriptions and licenses are FilterLists' and its contributors', and may be out of
							date: check a list's home page. This node fetched the directory{' '}
							{dateTime(directory.data.fetched_at)} and keeps it for a day.
						</p>
					</div>
				</>
			) : null}
		</div>
	)
}

function DirectoryRow({ list }: { list: DirectoryEntry }) {
	const [open, setOpen] = useState(false)
	return (
		<li>
			<div className="directory-head">
				<strong>{list.name}</strong>
				{list.tags.map((tag) => (
					<span key={tag} className="badge">
						{tag.toUpperCase()}
					</span>
				))}
				<button
					type="button"
					className="button small"
					aria-expanded={open}
					aria-label={`${open ? 'Hide' : 'Show'} ${list.name}`}
					onClick={() => setOpen(!open)}
				>
					{open ? 'Hide' : 'Details'}
				</button>
			</div>
			{list.description === '' ? null : <p className="directory-description">{list.description}</p>}
			<p className="muted">
				{list.syntaxes.join(', ')}
				{list.license == null ? '' : ` · ${list.license}`}
			</p>
			{open ? <DirectoryDetails id={list.id} /> : null}
		</li>
	)
}

/** A list's addresses, each to add after checking. */
function DirectoryDetails({ id }: { id: number }) {
	const details = useQuery(directoryListQuery(id))
	const lists = useQuery(listsQuery)
	const have = new Set((lists.data ?? []).map((list) => list.spec.url))
	if (details.data === undefined) {
		return details.error ? <ErrorNotice error={details.error} /> : <p className="muted">Loading…</p>
	}
	const list = details.data
	const parts = new Set(list.urls.map((url) => url.segment)).size
	return (
		<div className="subform">
			{list.homepage == null ? null : (
				<p>
					<a href={list.homepage} target="_blank" rel="noreferrer noopener">
						Home page
					</a>
				</p>
			)}
			{!list.usable ? (
				<p>goethite cannot use this list.</p>
			) : list.urls.length === 0 ? (
				<p>This list has no https:// address, and goethite downloads nothing else.</p>
			) : (
				<>
					{parts > 1 ? <p className="hint">This list comes in {parts} parts: add each.</p> : null}
					<table className="table">
						<tbody>
							{list.urls.map((url) => {
								const name = (parts > 1 ? `${list.name} (part ${url.segment})` : list.name).slice(
									0,
									MAX_NAME,
								)
								return (
									<tr key={url.url}>
										<td className="name">
											{url.url}
											{url.mirror ? <span className="muted"> (mirror)</span> : null}
										</td>
										<td className="actions-cell">
											{have.has(url.url) ? (
												<span className="badge ok">ADDED</span>
											) : (
												<Link
													to="/lists/$id"
													params={{ id: 'new' }}
													search={{
														name,
														url: url.url,
														comment: `From the FilterLists directory (list ${list.id}).`,
													}}
													className="button small"
													aria-label={`Add ${url.url}`}
												>
													Add
												</Link>
											)}
										</td>
									</tr>
								)
							})}
						</tbody>
					</table>
				</>
			)}
		</div>
	)
}
