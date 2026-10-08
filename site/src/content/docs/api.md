---
title: REST API
description: Configure and observe goethite over HTTP with /api/v1.
---

goethite has a REST API at `/api/v1` for everything the config file does not cover: filter lists,
custom rules, clients, groups, schedules, the filtering settings, pausing, the query log,
statistics and the audit log. The TUI, the web UI and the Terraform provider all use it. The
[API reference](../api-reference/) lists every endpoint.

## Access

By default the API listens on `127.0.0.1:8053` and answers without authentication, which only
local programs can reach:

```sh
curl http://127.0.0.1:8053/api/v1/status
```

To use it from other machines, create an admin token:

```sh
goethite token
```

It prints a token (`gth_` followed by 64 hex digits) and a line for the config file. Only that
hash goes into the config, so the config file gives nothing away:

```toml
[api]
listen = ["0.0.0.0:8053", "[::]:8053"]
token_sha256 = "…"
tls_cert = "/etc/goethite/api.crt"   # recommended beyond loopback
tls_key = "/etc/goethite/api.key"
```

Restart goethite. From then on every request, from anywhere, needs the token:

```sh
curl -H "Authorization: Bearer $GOETHITE_TOKEN" https://dns.example.lan:8053/api/v1/status
```

goethite refuses to listen beyond loopback without a token. Without TLS, the token crosses the
network in clear text, and goethite logs a warning. Keep the API off the internet either way.

## Resources

Lists, rules, groups, clients and schedules all work the same way. `POST` a spec to the
collection to create one, then `GET`, `PUT` or `DELETE` it by ID:

```sh
api() { curl -s -H "Authorization: Bearer $GOETHITE_TOKEN" -H 'content-type: application/json' "$@"; }

api -X POST http://127.0.0.1:8053/api/v1/rules -d '{"rule": "||ads.example^"}'
```

```json
{
  "id": "ru_6e687cfb77741ac2",
  "revision": 1,
  "created_at": "2026-10-08T07:20:40.011282Z",
  "updated_at": "2026-10-08T07:20:40.011282Z",
  "spec": { "rule": "||ads.example^", "enabled": true, "comment": "", "managed_by": "api" }
}
```

A `PUT` replaces the whole spec. Every resource has a `revision`, also sent as its `ETag`. Send it
back in `If-Match` and the update or delete fails with `412` if someone changed the resource in
the meantime. Changes apply at once: a new rule blocks from the next query on.

Specs reject unknown fields. Errors are JSON with a stable code:

```json
{ "error": { "code": "conflict", "message": "conflict: groups[default].lists[0]: there is no list \"li_x\"" } }
```

| Status | Code | When |
| --- | --- | --- |
| 400 | `bad_request` | The request is malformed (bad JSON, bad query string, bad `If-Match`). |
| 401 | `unauthorized` | The token is missing or wrong. |
| 404 | `not_found` | No such resource or endpoint. |
| 409 | `conflict` | It refers to something missing, or something still refers to it. |
| 412 | `revision_mismatch` | It changed since the revision in `If-Match`. |
| 413 | | The body is larger than 1 MiB. |
| 422 | `invalid` | A value is not valid, or a field is unknown. |

Resources with `"managed_by": "terraform"` are read-only in the web UI and the TUI, so they do not
drift from their Terraform definition. The API itself accepts changes to them.

## Pausing filtering

```sh
api -X PUT http://127.0.0.1:8053/api/v1/pause -d '{"seconds": 600}'   # for 10 minutes
api -X DELETE http://127.0.0.1:8053/api/v1/pause                      # resume now
```

A pause ends by itself, and on a restart. The settings' `protection` switch turns filtering off
for good.

## Query log and statistics

```sh
api 'http://127.0.0.1:8053/api/v1/querylog?limit=50&outcome=blocked'
api 'http://127.0.0.1:8053/api/v1/querylog?client=192.168.1.23&name=example'
api 'http://127.0.0.1:8053/api/v1/stats?hours=24'
```

The query log is newest first. To page, pass the response's `next` as `before`. The statistics
cover the last 1 to 720 hours: counts per hour by outcome, and the names, blocked names and clients
asked most.

## Audit log

Every change, and every pause, resume and list refresh, is in the audit log with the time, who
made it (`token`, `unauthenticated`, `cli` or `system`), their address, and the resource before and
after:

```sh
api 'http://127.0.0.1:8053/api/v1/audit?limit=20'
```

## Metrics

`/metrics` serves Prometheus metrics: queries by outcome and protocol, a latency histogram,
rate-limited and refused queries, the cache, upstream health, the filter and the query log. It
needs the token once one is configured:

```yaml
scrape_configs:
  - job_name: goethite
    authorization:
      credentials_file: /etc/prometheus/goethite-token
    static_configs:
      - targets: ["dns.example.lan:8053"]
```

## The OpenAPI document

`goethite openapi` prints the OpenAPI 3.1 document, which `/api/v1/openapi.json` also serves.
Generate a client from it, or browse it in the [API reference](../api-reference/).
