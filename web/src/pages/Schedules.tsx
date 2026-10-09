import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { useId, useState } from 'react'

import type { Schedule } from '../api/client'
import {
	deleteSchedule,
	groupsQuery,
	saveSchedule,
	scheduleQuery,
	schedulesQuery,
} from '../api/resources'
import { Editor, Loading, ManagedBadge } from '../components/editor'
import { TextField } from '../components/form'
import { ErrorNotice } from '../components/ui'
import {
	describeWindows,
	newWindow,
	scheduleForm,
	type ScheduleForm,
	scheduleSpec,
	toggleDay,
	WEEKDAY_LABEL,
	WEEKDAYS,
	type WindowForm,
} from '../forms/forms'

/** Schedules: when a group's lists apply. */
export function Schedules() {
	const schedules = useQuery(schedulesQuery)
	return (
		<div className="grid-page">
			<div className="page-head">
				<h1>Schedules</h1>
				<Link to="/schedules/$id" params={{ id: 'new' }} className="button primary">
					New schedule
				</Link>
			</div>
			<p className="muted">
				Weekly windows in a time zone. A group can apply a list only during a schedule, such as social
				media blocked during school hours.
			</p>
			<ErrorNotice error={schedules.error} />
			<div className="panel">
				<table className="table">
					<thead>
						<tr>
							<th>Name</th>
							<th>When</th>
							<th>Time zone</th>
						</tr>
					</thead>
					<tbody>
						{(schedules.data ?? []).map((schedule) => (
							<tr key={schedule.id}>
								<td>
									<Link to="/schedules/$id" params={{ id: schedule.id }}>
										{schedule.spec.name}
									</Link>{' '}
									<ManagedBadge managedBy={schedule.spec.managed_by} />
								</td>
								<td className="mono">{describeWindows(schedule.spec.windows)}</td>
								<td className="mono">{schedule.spec.time_zone}</td>
							</tr>
						))}
					</tbody>
				</table>
				{schedules.data?.length === 0 ? <p className="muted">No schedules yet.</p> : null}
			</div>
		</div>
	)
}

/** An existing schedule (`id`), or a new one ("new"). */
export function ScheduleEditor({ id }: { id: string }) {
	const isNew = id === 'new'
	const query = useQuery({ ...scheduleQuery(id), enabled: !isNew })
	if (!isNew && query.data === undefined) {
		return <Loading error={query.error} what="schedule" />
	}
	return (
		<ScheduleFields
			key={query.data?.revision ?? 'new'}
			stored={query.data}
			reload={() => void query.refetch()}
		/>
	)
}

/** The time zones the browser knows, for suggestions. */
function timeZones(): string[] {
	try {
		return Intl.supportedValuesOf('timeZone')
	} catch {
		return []
	}
}

function ScheduleFields({ stored, reload }: { stored: Schedule | undefined; reload: () => void }) {
	const [form, setForm] = useState<ScheduleForm>(() => scheduleForm(stored?.spec))
	const zonesId = useId()
	const set =
		<K extends keyof ScheduleForm>(key: K) =>
		(value: ScheduleForm[K]) =>
			setForm((previous) => ({ ...previous, [key]: value }))
	const setWindow = (index: number, window: WindowForm) =>
		set('windows')(form.windows.map((other, at) => (at === index ? window : other)))
	const complete = form.windows.length > 0 && form.windows.every((window) => window.days.length > 0)
	// goethite refuses to delete a schedule a group uses.
	const groups = useQuery({ ...groupsQuery, enabled: stored !== undefined })
	const users = (groups.data ?? []).filter((group) =>
		(group.spec.lists ?? []).some((entry) => entry.schedule === stored?.id),
	)

	return (
		<Editor
			title={stored === undefined ? 'New schedule' : stored.spec.name}
			what="schedule"
			back="/schedules"
			backLabel="Schedules"
			stored={stored}
			queryKey={['schedules']}
			save={() => saveSchedule(stored, scheduleSpec(form, stored?.spec.managed_by))}
			remove={
				stored === undefined || groups.data === undefined || users.length > 0
					? undefined
					: () => deleteSchedule(stored)
			}
			reload={reload}
			canSave={form.name.trim() !== '' && form.timeZone.trim() !== '' && complete}
		>
			{users.length === 0 ? null : (
				<p className="muted">
					Used by {users.map((group) => group.spec.name).join(', ')}: change them before deleting it.
				</p>
			)}
			<TextField label="Name" value={form.name} onChange={set('name')} mono={false} required />
			<TextField
				label="Time zone"
				value={form.timeZone}
				onChange={set('timeZone')}
				list={zonesId}
				hint="An IANA time zone, such as Europe/Berlin."
				required
			/>
			<datalist id={zonesId}>
				{timeZones().map((zone) => (
					<option key={zone} value={zone} />
				))}
			</datalist>
			<fieldset className="subform">
				<legend>Windows</legend>
				{form.windows.map((window, index) => (
					<div className="window" key={index}>
						<div className="days" role="group" aria-label={`Days of window ${index + 1}`}>
							{WEEKDAYS.map((day) => (
								<label key={day} className="day">
									<input
										type="checkbox"
										checked={window.days.includes(day)}
										onChange={() => setWindow(index, toggleDay(window, day))}
									/>
									{WEEKDAY_LABEL[day]}
								</label>
							))}
						</div>
						<div className="row">
							<TextField
								label="From"
								type="time"
								value={window.start}
								onChange={(start) => setWindow(index, { ...window, start })}
								required
							/>
							<TextField
								label="Until"
								type="time"
								value={window.end}
								onChange={(end) => setWindow(index, { ...window, end })}
								required
							/>
							<button
								type="button"
								className="button small"
								disabled={form.windows.length === 1}
								onClick={() => set('windows')(form.windows.filter((_, at) => at !== index))}
							>
								Remove
							</button>
						</div>
						{window.end <= window.start ? (
							<p className="hint">Runs past midnight into the next day.</p>
						) : null}
						{window.days.length === 0 ? <p className="hint">Choose at least one day.</p> : null}
					</div>
				))}
				<p>
					<button
						type="button"
						className="button small"
						disabled={form.windows.length >= 32}
						onClick={() => set('windows')([...form.windows, newWindow()])}
					>
						Add a window
					</button>
				</p>
			</fieldset>
			<TextField label="Comment" value={form.comment} onChange={set('comment')} mono={false} />
		</Editor>
	)
}
