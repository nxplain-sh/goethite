import { type ReactNode, useId } from 'react'

/** A labelled control with an optional hint under it. */
function Field({
	label,
	hint,
	children,
}: {
	label: string
	hint?: ReactNode
	children: (id: string, describedBy: string | undefined) => ReactNode
}) {
	const id = useId()
	const hintId = `${id}-hint`
	return (
		<div className="field">
			<label htmlFor={id}>{label}</label>
			{children(id, hint === undefined ? undefined : hintId)}
			{hint === undefined ? null : (
				<div id={hintId} className="hint">
					{hint}
				</div>
			)}
		</div>
	)
}

export function TextField({
	label,
	value,
	onChange,
	hint,
	placeholder,
	required,
	mono,
	type,
	list,
}: {
	label: string
	value: string
	onChange: (value: string) => void
	hint?: ReactNode
	placeholder?: string
	required?: boolean
	mono?: boolean
	type?: 'text' | 'time' | 'number'
	list?: string
}) {
	return (
		<Field label={label} hint={hint}>
			{(id, describedBy) => (
				<input
					id={id}
					className={mono === false ? 'input sans' : 'input'}
					type={type ?? 'text'}
					value={value}
					required={required}
					placeholder={placeholder}
					spellCheck={false}
					autoComplete="off"
					list={list}
					aria-describedby={describedBy}
					onChange={(event) => onChange(event.target.value)}
				/>
			)}
		</Field>
	)
}

export function TextAreaField({
	label,
	value,
	onChange,
	hint,
	placeholder,
	rows,
}: {
	label: string
	value: string
	onChange: (value: string) => void
	hint?: ReactNode
	placeholder?: string
	rows?: number
}) {
	return (
		<Field label={label} hint={hint}>
			{(id, describedBy) => (
				<textarea
					id={id}
					className="input"
					value={value}
					rows={rows ?? 4}
					placeholder={placeholder}
					spellCheck={false}
					aria-describedby={describedBy}
					onChange={(event) => onChange(event.target.value)}
				/>
			)}
		</Field>
	)
}

export function SelectField<T extends string>({
	label,
	value,
	onChange,
	options,
	hint,
}: {
	label: string
	value: T
	onChange: (value: T) => void
	options: readonly { value: T; label: string }[]
	hint?: ReactNode
}) {
	return (
		<Field label={label} hint={hint}>
			{(id, describedBy) => (
				<select
					id={id}
					className="select"
					value={value}
					aria-describedby={describedBy}
					onChange={(event) => {
						const chosen = options.find((option) => option.value === event.target.value)
						if (chosen !== undefined) onChange(chosen.value)
					}}
				>
					{options.map((option) => (
						<option key={option.value} value={option.value}>
							{option.label}
						</option>
					))}
				</select>
			)}
		</Field>
	)
}

export function CheckField({
	label,
	checked,
	onChange,
	hint,
}: {
	label: string
	checked: boolean
	onChange: (checked: boolean) => void
	hint?: ReactNode
}) {
	const id = useId()
	return (
		<div className="field">
			<label className="check">
				<input
					type="checkbox"
					checked={checked}
					aria-describedby={hint === undefined ? undefined : `${id}-hint`}
					onChange={(event) => onChange(event.target.checked)}
				/>
				{label}
			</label>
			{hint === undefined ? null : (
				<div id={`${id}-hint`} className="hint">
					{hint}
				</div>
			)}
		</div>
	)
}
