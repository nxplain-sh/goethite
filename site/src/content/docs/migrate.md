---
title: Moving from Pi-hole or AdGuard Home
description: Bring a Pi-hole v6 or AdGuard Home configuration over to goethite with goethite migrate.
---

`goethite migrate` reads a running Pi-hole (version 6) or AdGuard Home through its web API, shows
what goethite would get, and with `--apply` makes those changes through goethite's own
[API](../api/). Every change is checked, written to the audit log and, in a [cluster](../ha/),
replicated like any other.

Install goethite first and start it (see [Install on Linux](../install/)); the old server keeps
running while you migrate. Then, on the goethite host:

```sh
# Pi-hole: its web password, or an app password, in a file.
goethite migrate pihole --from http://pi.hole --password-file pihole-password

# AdGuard Home: its user name and password.
goethite migrate adguard-home --from http://192.168.1.2:3000 --user admin \
  --password-file adguard-password
```

Without `--apply` nothing changes: you see what comes over, what behaves differently in goethite,
and what is left out and why. Read it, then run the same command with `--apply`. If goethite's API
needs a token (from another machine, or once you set one), add `--token-file`, as for the
[terminal UI](../tui/); `--api` names another node.

Applying only adds: a list with the same URL, a group or client with the same name, the same rule
or record already in goethite is kept as it is. Running the command again changes nothing the
second time, so you can migrate, look, adjust the old server and migrate again.

## What comes over

| | Pi-hole | AdGuard Home |
| --- | --- | --- |
| Filter lists | Block lists, in the default group if Pi-hole's Default group uses them, and in the groups below | Filter subscriptions, in the default group |
| Custom rules | Exact allowed and denied domains, as `@@\|name^` and `\|name^` | Custom filtering rules |
| Groups | Every group but Default, with its lists | One for each client with settings of its own: filtering, safe search, blocked services |
| Clients | Those known by address or network, in their first group | Those known by address, network or client ID |
| [Local records](../local-records/) | Local DNS records and CNAME records | DNS rewrites |
| Default group | | Safe search and blocked services |
| [Settings](../security/#access-control) | Blocking mode (null IP or NXDOMAIN), blocked answers' TTL | Blocking mode, blocked answers' TTL, list update interval, allowed and disallowed clients |

## What does not

The plan lists each item it leaves out, with the reason. The usual ones:

- **Lists over plain HTTP or from local files.** goethite downloads lists over HTTPS only. Most
  hosts offer HTTPS: add the list again with `https://`.
- **Allowlist subscriptions.** goethite has none; add the domains you need as `@@` rules.
- **Regular expressions** and rules with options goethite does not support yet.
- **Clients known by MAC address, host name or network interface.** goethite matches clients by
  address, network and client ID.
- **Upstream servers and conditional forwarding.** goethite's upstreams are in its config file
  (`[[upstream]]`); the plan names the ones the old server used.
- **AdGuard Home's parental control and safe browsing**, which are AdGuard services, the pauses
  in a blocked-services schedule, rewrites that keep a type upstream (`A` or `AAAA` as the answer),
  and per-client upstreams.

Some things come over but behave a little differently; the plan says so. Pi-hole's domains for
some groups become rules for every group, since goethite's custom rules apply to all clients. A
client in several Pi-hole groups goes into the first, since a goethite client is in one group.

## After migrating

Check the [web UI](../web-ui/), point a device at goethite and run the
[DNS leak test](../leak-test/), then hand out goethite's address in your router's DHCP settings.
Keep the old server until you are happy; the migration never changes it.
