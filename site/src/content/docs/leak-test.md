---
title: DNS leak test
description: Check that a device's lookups actually reach goethite, and how.
---

Filtering only works for lookups that reach goethite. A device or browser that asks another
resolver bypasses it, without anything looking wrong: a browser with secure DNS (DNS over HTTPS)
turned on, a VPN, DNS servers typed into the device, or a router that hands out a second DNS
server besides goethite. The **DNS leak test** checks a device for that.

## Running it

Open the web UI's **Leak test** page on the device you want to check, in the browser you use
there, and press **Run the test**. The browser looks up eight names that only goethite answers,
such as `3f9c…e1-1.leak.goethite.test`, by loading images from them (they never load). goethite
records each lookup that reaches it. The result says:

- **NO LEAK**: all eight lookups reached goethite. The page shows over which protocol (UDP, TCP,
  DoT, DoH, DoQ), from which address, as which [client and group](../groups/), and whether
  filtering applies to them.
- **PARTIAL LEAK**: some reached goethite, the rest went elsewhere. Usually the device or the
  router has a second DNS server, and the device asks both. Remove the other server, or make it
  another goethite node ([high availability](../ha/)).
- **LEAK**: none reached goethite. The browser or device asks another resolver: turn off the
  browser's secure DNS (or point it at goethite's own [DNS over HTTPS](../encrypted-dns/)), check
  the VPN, or set the device's DNS server to goethite.

When the lookups come from another address than the browser's own (as goethite's API sees it),
the page says so. That may be the device's other address (IPv4 against IPv6), but often it is the
router: it forwards its devices' lookups, so goethite sees them all as one client and cannot
give them different groups. Point the devices at goethite directly to tell them apart.

The **Recent tests** list shows every test of the last hour, from any device, so you can run the
test on a phone and read the result on your computer.

## From the terminal

The [terminal UI](../tui/)'s **Leak tests** screen lists the same tests. Its <kbd>t</kbd> key
tests the machine the TUI runs on: it looks the names up through the system's resolver, as any
program there would, rather than through a browser.

With the [REST API](../api/#dns-leak-tests), any device with a shell can be tested:

```sh
test=$(api -X POST http://127.0.0.1:8053/api/v1/leak-tests)
for name in $(echo "$test" | jq -r '.names[]'); do host "$name" >/dev/null; done
api "http://127.0.0.1:8053/api/v1/leak-tests/$(echo "$test" | jq -r .id)" | jq '{reached, lookups}'
```

## How it works

The names are under `leak.goethite.test`. `.test` is reserved for testing and exists on no
public DNS server (RFC 6761), so a lookup that reaches another resolver fails there, and
goethite answers everything under `goethite.test` itself (`NXDOMAIN`), without forwarding or
filtering it. Each test gets 128 random bits in its names, so a lookup is only counted for the
test that made it, and the names tell no one anything but that a test ran.

Tests live in memory, on the node that made them, for an hour; a node keeps the 32 newest and
records at most 64 lookups for each. In a [pair](../ha/), run the test against the node your
devices use (the one holding the floating IP): the other node does not see those lookups.

The web UI's [Content Security Policy](../web-ui/#security) allows images from
`*.leak.goethite.test` for this, and nothing else new.

## Limits

- The test checks lookups made the way the browser makes them. Apps with their own DNS (some
  video, game and messaging apps hardcode a resolver) are not covered; the
  [query log](../web-ui/#screens) shows which devices ask goethite at all.
- A browser that asks another resolver first and only falls back to the system's resolver for
  names that one cannot find would pass, since the test names exist nowhere else.
- The browser may cache a lookup for a moment; every test uses new names, so run it again rather
  than reloading.
