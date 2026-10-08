---
title: Encrypted DNS
description: Serve DNS over TLS and DNS over HTTPS, and tell devices apart by client ID wherever they are.
---

goethite answers DNS over TLS (DoT, RFC 7858) and DNS over HTTPS (DoH, RFC 8484) beside plain DNS.
Encrypted DNS keeps queries private on networks you do not control, and with a **client ID** a
phone keeps its own filtering when it is away from home.

## Set it up

You need a certificate for the name devices will use, such as `dns.example`, and, for client IDs
in the server name, for `*.dns.example` too. A Let's Encrypt certificate with both names works.
Then add a `[server.tls]` table:

```toml
[server.tls]
cert = "/etc/goethite/tls/fullchain.pem"
key = "/etc/goethite/tls/privkey.pem"
server_name = "dns.example"
dot = ["0.0.0.0:853", "[::]:853"]
doh = ["0.0.0.0:443", "[::]:443"]
```

Restart goethite. It logs `DNS over TLS listening` and `DNS over HTTPS listening` for each
address. DoH answers at `https://dns.example/dns-query`. Check both with
[kdig](https://www.knot-dns.cz/docs/latest/html/man_kdig.html):

```sh
kdig @dns.example +tls goethite.test
kdig @dns.example +https goethite.test
```

Both should answer `127.0.0.53`. See the [configuration reference](../configuration/#servertls)
for every key.

### Certificates

goethite reads the certificate and key at startup, and `systemctl reload goethite` (`SIGHUP`)
reads them again and serves the renewed certificate to new connections without dropping any. A
file that cannot be read, or a key that does not fit, leaves the certificate in use and is logged.
`goethite check-config` checks that the certificate and key fit together.

The shipped systemd unit runs goethite as a dynamic user, which cannot read a key that only root
may read. Create a group for it, let goethite join it in a drop-in (`systemctl edit goethite`),
and keep a copy of the certificate and key that the group may read:

```sh
groupadd --system goethite-tls
install -d -m 750 -g goethite-tls /etc/goethite/tls
```

```ini
[Service]
SupplementaryGroups=goethite-tls
```

A certbot deploy hook copies renewed files there and has goethite reload them:

```sh
#!/bin/sh
# /etc/letsencrypt/renewal-hooks/deploy/goethite
install -m 640 -g goethite-tls "$RENEWED_LINEAGE/fullchain.pem" /etc/goethite/tls/fullchain.pem
install -m 640 -g goethite-tls "$RENEWED_LINEAGE/privkey.pem" /etc/goethite/tls/privkey.pem
systemctl reload goethite
```

Started as root without systemd, goethite reads the files before it drops its privileges, so
they may be readable by root only; to reload them it must still be able to read them as
`server.user`.

## Client IDs

A client is usually known by its address, which works on your network. Away from it, a phone has
an address you do not know. A client ID names the device instead:

1. Give the client an ID, such as `anna-phone`, in the [web UI](../web-ui/) (Clients) or
   through the [API](../groups/#clients) (`"ids": ["anna-phone"]`); the [TUI](../tui/) lists it.
   IDs are 1 to 63 lowercase letters, digits and hyphens, not at either end; a client has up to
   16. Addresses are optional for a client with an ID.
2. Set up the device with its ID. The client editor shows the exact values:
   - **DNS over HTTPS:** `https://dns.example/dns-query/anna-phone`
   - **DNS over TLS:** `anna-phone.dns.example` as the hostname. On Android this is
     *Private DNS*; it needs `server_name` and a certificate for `*.dns.example`.

A query that carries a known ID belongs to that client, wherever it comes from; the ID wins over
the address. An unknown ID, or none, falls back to the address. When both the DoH path and the
server name carry an ID, the path wins. The query log shows the client and `DoT` or `DoH` next to
its address.

## Reaching goethite from the internet

Serving DoT or DoH beyond your network makes goethite a resolver anyone can use who reaches it.
Turn on `require_client_id`, so encrypted queries without a known client ID get `REFUSED`:

```toml
[server.tls]
require_client_id = true
```

Plain DNS on port 53 is not affected; keep it on your network. A client ID is a name, not a
password: over DoT it travels unencrypted in the TLS server name, so anyone on the path can see
it. Over DoH the ID in the path is encrypted. Treat `require_client_id` as keeping casual users
out, and use a firewall or VPN where that is not enough.

## Limits

Encrypted connections count against the same limits as TCP: `max_tcp_connections` (256) in total
and `max_tcp_connections_per_client` (16) from one address. A TLS handshake must finish within 10
seconds, and a connection without a query for 30 seconds is closed. DoH accepts request heads of
up to 64 KiB, bodies of up to 65,535 bytes (one DNS message), and 64 concurrent requests on an
HTTP/2 connection. Answers carry `Cache-Control: max-age` set to their shortest time to live.

The metrics count failed handshakes (`goethite_tls_handshake_failures_total`) and DoH requests
answered with an HTTP error (`goethite_https_rejected_total`), and queries by protocol (`dot`,
`doh`) in `goethite_queries_total`.

DNS over QUIC is coming in a later release, and so is DoH behind a reverse proxy.
