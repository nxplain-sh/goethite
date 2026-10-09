# ADR 0022: Recommended lists by category, with presets

- **Status:** Accepted, extends ADR 0018
- **Date:** 2026-10-08

## Context

ADR 0018 gave goethite ten recommended lists for ads and trackers and one default. Research
provided by the user groups the lists that matter for DNS filtering differently: one base list
(they overlap), security lists that stack on it, optional lists by topic, and legacy lists the
base lists already include, with presets for common setups. It also asks for sizes read at
runtime rather than hardcoded (HaGeZi's Threat Intelligence Feeds in particular change a lot),
for skipped rules to be counted where users see them, and for lists that do the same job to be
switched rather than stacked.

## Decision

**A catalog with categories** (`goethite_api::recommended`): 36 lists, each with a category, a
topic for optional ones, a ★ for the most recommended per category, a short badge (Minimal,
Aggressive, Strict, Compatibility, Max security) and a note. Every list was downloaded and read
by goethite on 8 October 2026: all parse cleanly except the AdGuard DNS filter (554 lines a DNS
server cannot apply) and Dandelion Sprout's list (its IP address rules), whose plain-domains
version is used because it is cleaner than the AdGuard Home one and has no exceptions that
could unblock other lists' names. Perflyst's Smart-TV list is the plain version, for the same
reason. Licenses are each project's own; URLhaus's are abuse.ch's fair use terms.

**Exclusions instead of stacking.** `excludes` names lists that do the same job, symmetrically:
TIF and TIF Mini, Perflyst's list and HaGeZi's Samsung, LG and Roku lists. The web UI offers to
switch: the new list takes the old one's place in every group that uses it, with the same
schedules, and the old one is turned off. Two base lists on at once only get a warning, since
someone may want them.

**Presets** (Balanced, Strict, Family, Don't break anything), each with exactly one base list and
no excluded pairs (checked by a test). Applying one to a group, which the web UI previews
first: its lists join the group, created or turned on as needed; recommended lists it does not
have leave the group and are turned off if no other group uses them; other lists stay. The web
UI applies a preset with the existing API, lists first, groups next and lists turned off last,
so no group goes unprotected in between; an API call doing it in one transaction is backlog.

**New nodes start with Balanced**: HaGeZi Multi Normal, TIF Mini and Fake, in the default
group. Existing nodes do not change.

**Sizes at runtime.** `GET /api/v1/lists/recommended/sizes` reads the first 8 KiB of each
recommended list, a range request cut off there whether or not the server honors it (oisd.nl
answers ranges with 416, so the request is repeated without), six at a time, only when asked,
kept a day, one refresh at a time. A bounded parser (fuzzed in `parse_filterlists`) takes the
number from the header's comment lines: HaGeZi's "Number of entries", OISD's "Entries", Steven
Black's "Number of unique domains"; 29 of the 36 lists state one. Once a list is added, the
Lists page shows what goethite read instead: rules and skipped lines. `[filter] directory`,
which already governs looking lists up for the web UI, turns it off.

Checking the lists also found that a byte order mark at the start of a list file was read as
part of the first line; the filter now drops it.

## Consequences

- The catalog needs a look at each release: lists move, and licenses and formats change.
- Opening the Lists page contacts the recommended lists' hosts once a day, for 8 KiB each.
- Applying a preset is several API calls; a failure in between leaves a partial change, which
  the page shows as an error and which applying the preset again completes.
