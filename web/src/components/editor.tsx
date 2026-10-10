import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from '@tanstack/react-router'
import { type FormEvent, type ReactNode, useState } from 'react'

import { ApiError, type ManagedBy } from '../api/client'
import { MANAGED_LABEL } from '../forms/forms'
import { ErrorNotice } from './ui'

/** The pages an editor goes back to. */
export type IndexPage = '/lists' | '/rules' | '/records' | '/groups' | '/clients' | '/schedules'

/** A stored resource, as far as the editor cares. */
export interface Stored {
	id: string
	revision: number
	spec: { managed_by?: ManagedBy }
}

/**
 * The frame of every editor: the title, who manages the resource, the
 * fields, and Save, Cancel and Delete. After a change, the lists of resources
 * and the status are fetched again and the editor goes back to `back`.
 */
export function Editor({
	title,
	what,
	back,
	backLabel,
	stored,
	queryKey,
	save,
	remove,
	reload,
	canSave,
	children,
}: {
	title: string
	what: string
	back: IndexPage
	backLabel: string
	stored: Stored | undefined
	queryKey: readonly string[]
	save: () => Promise<unknown>
	remove?: (() => Promise<unknown>) | undefined
	reload?: (() => void) | undefined
	canSave: boolean
	children: ReactNode
}) {
	const queryClient = useQueryClient()
	const navigate = useNavigate()
	const done = async () => {
		await queryClient.invalidateQueries({ queryKey })
		await queryClient.invalidateQueries({ queryKey: ['status'] })
		void navigate({ to: back })
	}
	const saving = useMutation({ mutationFn: save, onSuccess: done })
	const deleting = useMutation({ mutationFn: remove ?? (() => Promise.resolve()), onSuccess: done })
	const managedBy = stored?.spec.managed_by
	const error = saving.error ?? deleting.error
	const changedMeanwhile = error instanceof ApiError && error.code === 'revision_mismatch'

	const submit = (event: FormEvent) => {
		event.preventDefault()
		saving.mutate()
	}

	return (
		<div className="grid-page editor">
			<p>
				<Link to={back}>← {backLabel}</Link>
			</p>
			<h1>{title}</h1>
			{stored === undefined ? null : (
				<p className="muted">
					<span className="mono">{stored.id}</span> · revision {stored.revision}
					{managedBy === undefined ? null : <> · managed by {MANAGED_LABEL[managedBy]}</>}
				</p>
			)}
			{managedBy === 'config_file' ? (
				<div className="notice" role="status">
					This {what} comes from the config file's [filter] table: the next `goethite import` puts it back as
					the file says.
				</div>
			) : null}
			<ErrorNotice error={error} />
			{changedMeanwhile && reload !== undefined ? (
				<p>
					<button
						type="button"
						className="button small"
						onClick={() => {
							saving.reset()
							deleting.reset()
							reload()
						}}
					>
						Load the current version
					</button>
				</p>
			) : null}
			<form className="panel form" onSubmit={submit}>
				<fieldset className="fields" disabled={saving.isPending || deleting.isPending}>
					{children}
				</fieldset>
				<div className="actions">
					<button type="submit" className="button primary" disabled={!canSave || saving.isPending}>
						{stored === undefined ? 'Create' : 'Save'}
					</button>
					<Link to={back} className="button">
						Cancel
					</Link>
					{stored === undefined || remove === undefined ? null : (
						<DeleteButton what={what} pending={deleting.isPending} onDelete={() => deleting.mutate()} />
					)}
				</div>
			</form>
		</div>
	)
}

/** Delete, after a second click: no browser dialog. */
export function DeleteButton({
	what,
	pending,
	onDelete,
	small,
}: {
	what: string
	pending: boolean
	onDelete: () => void
	small?: boolean
}) {
	const [asking, setAsking] = useState(false)
	const size = small === true ? ' small' : ''
	if (!asking) {
		return (
			<button type="button" className={`button danger-outline${size}`} onClick={() => setAsking(true)}>
				Delete
			</button>
		)
	}
	return (
		<span className="confirm">
			<button type="button" className={`button danger${size}`} disabled={pending} onClick={onDelete}>
				Delete this {what}
			</button>
			<button type="button" className={`button${size}`} onClick={() => setAsking(false)}>
				Keep it
			</button>
		</span>
	)
}

/** Who manages a resource, as a badge. */
export function ManagedBadge({ managedBy }: { managedBy: ManagedBy | undefined }) {
	if (managedBy === undefined || managedBy === 'api') {
		return null
	}
	return <span className="badge">CONFIG FILE</span>
}

/** The editor's loading and error states, before there is a form. */
export function Loading({ error, what }: { error: unknown; what: string }) {
	if (error instanceof ApiError && error.status === 404) {
		return (
			<div className="panel">
				<h1>Not found</h1>
				<p>There is no such {what}: it may have been deleted.</p>
			</div>
		)
	}
	if (error !== null && error !== undefined) {
		return <ErrorNotice error={error} />
	}
	return <p className="muted">Loading…</p>
}
