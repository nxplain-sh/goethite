# ADR 0039: Users, roles and sessions for the API and the web UI

- **Status:** Accepted
- **Date:** 2026-10-10

## Context

The API had one credential: an admin token (`gth_…`), with only its SHA-256 in the config file.
It is right for scripts, the TUI, Prometheus and `goethite migrate`, but it is one secret with
full power, cannot be attributed to a person, and the web UI asked people to paste it. The
product needs human authentication — a sign-in page, passwords, a second factor, password reset
— and authorization (who may change what), while staying self-hosted and working offline.

Clerk was considered and rejected: it is a hosted service (its Frontend API runs on Clerk's
infrastructure, production requires DNS records and certificates at Clerk), so it cannot run
offline or air-gapped, and it would put a third-party script in a UI whose CSP forbids
third-party scripts. A self-hosted OIDC provider (Authelia, authentik, Keycloak) as an identity
source stays possible as a later ADR; it is an integration, not a replacement.

## Decision

- **Users are a stored resource**, replicated like lists and clients, in the same store file and
  the same Raft log: `UserSpec` carries the name, `role`, `disabled`, the Argon2id hash of the
  password in PHC form, an optional TOTP secret (`enabled` once a code confirmed it), SHA-256
  hashes of unused recovery codes, and the hash plus expiry of a pending reset. Secret material
  is stored, and replicated, but audited redacted: the audit entry of a user change shows name,
  role, disabled state and whether a second factor exists, never a hash.
- **Roles are two**, for 1.0: `admin` (everything) and `viewer` (`GET`s and the endpoints that
  act on the reader's own account). The role gate runs after authentication; the token and
  bootstrap-loopback actors count as admin. The store refuses to disable, demote or delete the
  last enabled admin.
- **Sessions are in memory on each node**, one opaque token (`gths_`, 32 random bytes) whose
  SHA-256 is all the process keeps. The browser gets it in an `HttpOnly; SameSite=Strict` cookie
  for `Path=/api`, `Secure` when the API serves TLS, twelve hours absolute. Every request
  compares the revision the session was made at with the user's current one: changing a
  password, role, second factor or disabled state ends every session of that user on every node,
  with one config write. Sessions are not replicated: after a failover the user signs in again.
- **Sign-in is one endpoint**: password first (Argon2id, default parameters, on a blocking
  thread), then the second factor when enabled — a TOTP code (RFC 6238, HMAC-SHA1, one 30-second
  step either side, implemented on `ring`) or one of ten one-time recovery codes. An unknown
  name pays the same hashing cost as a known one. Failed sign-ins are limited per client address
  and per name, in memory, bounded.
- **Password reset is admin-issued**: `goethite user reset <name>` or
  `POST /api/v1/users/{id}/reset` produce a one-time token (stored hashed, valid one hour); the
  user opens `/reset?token=…` and sets a new password, which ends every session of that account.
  No email: it would need SMTP configuration and a mail dependency on a resolver that often has
  neither. An admin whose authenticator is lost has it cleared with
  `POST /api/v1/users/{id}/otp/disable`.
- **The command line bootstraps**: `goethite user add|list|passwd|reset|remove|disable|enable`,
  against the store file directly, so the first admin exists before the node serves anything.
  These commands need goethite stopped (the store file is locked) and refuse to run on a cluster
  member — like `goethite import` today.
- **The admin token stays.** It keeps working on every node, next to sessions, for automation.
  The API listens beyond loopback only with a token configured (unchanged config validation);
  once users exist, loopback is trusted no more: without a token, nothing is.
- **CSRF** rests on `SameSite=Strict` plus the existing `Origin` check: a cross-site request
  carries no session cookie, and a same-origin `POST` carries an `Origin` that must match
  `Host`. No separate CSRF token is issued.
- **Schema version 3**: the users table. A cluster runs one goethite version per the existing
  rule; nodes on schema 2 refuse a schema 3 seed, as before.

## Alternatives considered

- **Clerk.** Rejected above: cloud-only, breaks offline and the CSP.
- **Self-hosted OIDC.** Attractive for labs that already run an IdP; deferred, not excluded. It
  would be an additional sign-in method, with the built-in users as the bootstrap fallback.
- **Replicated sessions.** Sessions in the store would survive failover at the price of a Raft
  write per sign-in and per expiry sweep. Signing in again after a failover costs one password
  entry; the data plane is unaffected either way.
- **Signed (stateless) session tokens.** A signed token needs a cluster-wide key in the store
  and a denylist for revocation on password change; the revision check against the replicated
  user record gives revocation with no key and no list.
- **Email reset and email codes.** Useful for larger deployments; needs SMTP. Nothing here
  blocks adding it later behind the same `/auth` endpoints.
- **Argon2 parameters.** The crate's defaults (19 MiB, 2 rounds, one lane) are the OWASP
  recommendation; sign-in is rare and runs on the blocking pool.

## Consequences

- The web UI no longer asks for the token; the TUI, scripts and Prometheus keep using it. The
  `web/` login, account, users and reset pages and the `goethite user` command are the new
  surfaces; all are covered by tests, and the API reference is regenerated.
- A node with users but no token answers loopback clients with 401 until they sign in. Nodes
  seeded from an older store have no users and keep answering loopback, as before.
- Restarting a node ends its sessions; failing over to another node ends the ones it held.
- Every user change is a config write: it goes through the leader, is audited, and bumps the
  config version, which on this branch also rebuilds the policy (harmless, no filter rebuild).
