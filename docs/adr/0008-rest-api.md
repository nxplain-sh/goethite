# ADR 0008: REST API design and access

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

Phase 2 adds `/api/v1`, used by the TUI, the web UI and later Terraform. AGENTS.md requires an
OpenAPI document generated from the code, an admin token, loopback-only access until a token is
configured, and an audit entry for every change. The user chose to keep only a token hash in the
config, with optional HTTPS and a warning for plain HTTP beyond loopback.

## Decision

- **axum + utoipa.** Each handler carries a `#[utoipa::path]`; schemas come from the store's
  model types. The generated document is committed as `crates/goethite-api/openapi.json`, and a
  test fails when it is out of date (`GOETHITE_UPDATE_OPENAPI=1` rewrites it). `goethite openapi`
  prints it.
- **Uniform resources.** A collection supports `GET` and `POST`; an item supports `GET`, `PUT`
  (the whole spec) and `DELETE`. One macro writes the handlers for every kind. Responses nest the
  client-written spec under `spec`, next to `id`, `revision` and timestamps, so request bodies can
  reject unknown fields. The revision is the `ETag`. `If-Match` turns lost updates into `412`.
- **Errors** are JSON `{"error": {"code", "message"}}` with a stable code per status. Even body and
  query-string parse errors use this shape.
- **The data plane behind a trait.** Handlers write through the store (validation, audit), then
  call `Control::apply(Filter | Policy)`, which the binary implements. The response is sent once
  queries use the change.
- **Access.** `Authorization: Bearer <token>`. The token is 32 random bytes in hex, prefixed `gth_`
  so it can be found if it leaks. The config holds its SHA-256 only; a hash compare is enough,
  since the token's entropy makes the hash irreversible and unguessable. Without a token: loopback
  only, and goethite refuses to listen elsewhere. `/api/v1/health` is open. There is a single
  admin role for now.
- **Transport.** HTTP/1.1 and HTTP/2 via hyper-util, with optional rustls TLS from PEM files read
  before privileges are dropped. Limits: 64 connections, 10 s for the TLS handshake and headers,
  1 MiB bodies, 30 s per request. Every response carries a strict CSP, `X-Frame-Options: DENY`,
  `nosniff`, `no-referrer` and `no-store`. There is no CORS.
- **Port** 8053 by default, on loopback.

## Consequences

- Anyone with the token has full control. Scoped tokens (read-only, Terraform) are in the
  backlog.
- Plain HTTP beyond loopback is allowed, so home setups without certificates work. The warning
  and the docs push towards TLS.
- The OpenAPI document is a reviewed artifact. Changes to the API show up in diffs, and CI can
  check them for breaking changes.
