import { barY, type ChartScene, defineChart, type RenderChartSvgOptions } from '@tanstack/charts'
import { scaleBand } from '@tanstack/charts/scales/band'
import { scaleLinear } from '@tanstack/charts/scales/linear'
import { renderChartSvg } from '@tanstack/charts/svg'
import { tooltip } from '@tanstack/charts/tooltip'
import { Chart } from '@tanstack/react-charts'
import { useMemo } from 'react'

import type { Bucket } from '../dashboard/buckets'
import { count, percent } from '../format'

/** The style TanStack Charts writes on its root `<svg>`, from app.css instead. */
const ROOT_STYLE = ' style="display:block;overflow:visible"'

/**
 * The default SVG markup without its one inline style attribute: the
 * markup is parsed into the page, and the UI's Content Security Policy
 * refuses style attributes. Everything else it sets goes through the DOM's
 * style properties, which the policy allows.
 */
function renderSvg(scene: ChartScene, options: RenderChartSvgOptions): string {
	return renderChartSvg(scene, options).replace(ROOT_STYLE, '')
}

/** A color token from the stylesheet, so the chart follows the design. */
function token(name: string, fallback: string): string {
	const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
	return value === '' ? fallback : value
}

/**
 * All queries per time window, with the blocked ones in front. Hovering or
 * focusing a bar shows its counts; clicking it, or pressing Enter on it,
 * calls `onOpen` with its window.
 */
export default function QueriesChart({
	data,
	description,
	onOpen,
}: {
	data: Bucket[]
	description: string
	onOpen: (bucket: Bucket) => void
}) {
	const definition = useMemo(() => {
		const muted = token('--muted', '#5a5247')
		const blocked = token('--blocked', '#a63d22')
		const ink = token('--ink', '#111111')
		return defineChart({
			marks: [
				barY(data, { id: 'queries', x: 'label', y: 'queries', key: 'id', fill: muted, inset: 2 }),
				barY(data, { id: 'blocked', x: 'label', y: 'blocked', key: 'id', fill: blocked, inset: 2 }),
			],
			scales: {
				x: { scale: scaleBand, axis: { line: { stroke: ink, strokeWidth: 3 } } },
				y: { scale: scaleLinear, nice: true, grid: { stroke: ink, strokeOpacity: 0.12 } },
			},
			tooltip: {
				use: tooltip,
				className: 'chart-tooltip',
				content: (points) => {
					const bucket = points[0]?.datum
					if (bucket === undefined) return { rows: [] }
					return {
						title: bucket.title,
						rows: [
							{ label: 'Queries', value: count(bucket.queries), color: muted },
							{
								label: 'Blocked',
								value: `${count(bucket.blocked)} · ${percent(bucket.blocked, bucket.queries)}`,
								color: blocked,
							},
						],
					}
				},
			},
		})
	}, [data])
	return (
		<Chart
			className="chart-host"
			definition={definition}
			height={200}
			ariaLabel="Queries over time"
			ariaDescription={description}
			renderSvg={renderSvg}
			onSelect={(point) => {
				if (point) onOpen(point.datum)
			}}
		/>
	)
}
