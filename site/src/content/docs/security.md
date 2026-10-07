---
title: Security settings
description: DNS rebinding protection and the other protections goethite turns on by default.
---

goethite is built to be safe by default: the settings on this page are on unless you turn them
off. The [threat model](https://github.com/nxplain-sh/goethite/blob/main/docs/THREAT_MODEL.md)
lists every threat and what defends against it.

## DNS rebinding protection

In a DNS rebinding attack, a web page from a name the attacker controls makes that name resolve to
an address inside your network, such as your router's `192.168.1.1`. The browser still thinks it is
talking to the attacker's site, so the page can reach devices that were never meant to be exposed
to the internet.

goethite removes such answers: when a forwarded answer for a public name contains an A or AAAA
record with a private address, that record is dropped before the answer is cached or sent. These
addresses count as private:

| Range | What it is |
| --- | --- |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | private IPv4 networks (RFC 1918) |
| `100.64.0.0/10` | carrier-grade NAT (RFC 6598) |
| `127.0.0.0/8`, `::1` | loopback |
| `169.254.0.0/16`, `fe80::/10` | link-local |
| `0.0.0.0/8`, `::` | "this host" and unspecified |
| `fc00::/7` | unique local IPv6 (RFC 4193) |

IPv4 addresses mapped into IPv6 (`::ffff:192.168.1.1`) are checked as IPv4. The question name
decides, not the names in the answer: a public name that is a CNAME for `printer.lan` still loses
its private addresses.

Names below the private domains may resolve to private addresses, so a local DNS server behind
goethite keeps working for them:

```toml
[security]
rebinding_protection = true
private_domains = ["lan", "home.arpa", "internal", "local"]   # the defaults
```

Add your own domains to `private_domains` if a public domain you own resolves to internal addresses
(split-horizon DNS), for example `private_domains = ["lan", "home.arpa", "corp.example"]`. Setting
`private_domains` replaces the defaults, so list them again if you still want them. Answers
goethite gives itself, such as blocked names answered with `0.0.0.0`, are never touched.
