# ADR 0017: Dashboard charts with TanStack Charts

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

The dashboard drew its one chart, queries per hour over 24 hours, as hand-written SVG with a
`<title>` per bar. The user asked for an interactive dashboard and for TanStack's charts, in
keeping with the rest of the web UI (Router, Query, Table, Virtual). `@tanstack/charts` and
`@tanstack/react-charts` reached 1.0.0 on 3 October 2026: a chart grammar on d3 modules with an
SVG renderer, responsive axes, tooltips, pointer and keyboard focus and selection callbacks. The
web UI runs under a strict Content Security Policy that refuses inline style attributes, and has
a size budget of 200 KiB of gzipped JavaScript.

## Decision

**Use TanStack Charts, pinned to 1.0.0, for the dashboard's chart.** It brings ~30 packages into
`node_modules` (25 of them d3 modules); a bar chart bundles three (`d3-array`, `d3-scale`,
`d3-shape`). `npm audit` finds nothing in them.

**Load it lazily.** The chart is its own chunk (about 40 KiB gzipped), loaded after the rest of
the dashboard, behind an error boundary: the main chunk stays at about 128 KiB, and a chunk that
cannot load (say, replaced by an upgrade) leaves a sentence instead of a broken page. All
JavaScript together is 180 KiB of the 200 KiB budget.

**Keep the CSP as it is.** The SVG renderer writes one inline style on its root element
(`display:block;overflow:visible`) into markup the browser parses, which the policy refuses.
goethite passes its own `renderSvg`, the default renderer with that attribute removed, and sets
the same two properties in its stylesheet. Everything else the library styles goes through DOM
style properties, which the policy allows. The end-to-end test fails on any console error on the
dashboard, so a release that adds another inline style shows up there.

**Theme it through CSS.** Bar colors come from the stylesheet's tokens; the tooltip reads
`--ts-chart-tooltip-*` variables set on its class: square, a 3 px ink border, a hard shadow.

## Consequences

- The dashboard can grow more charts (per upstream, per client) at little extra cost.
- A young 1.0 can change quickly; the version is pinned and the tests cover the chart's
  rendering, tooltip, selection and the policy.
- A renderer option that leaves out the root style would remove the workaround; worth asking
  TanStack for.
