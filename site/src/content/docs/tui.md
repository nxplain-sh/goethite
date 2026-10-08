---
title: Terminal UI
description: Watch and steer a goethite node from a terminal with goethite tui.
---

`goethite tui` is a terminal UI for a goethite node. It talks to the node's
[REST API](../api/), so it works the same on the machine running goethite or over SSH from
anywhere that can reach the API. It refreshes every two seconds.

```sh
goethite tui
```

## Connecting

By default it connects to `http://127.0.0.1:8053`, the API's default address, which needs no
token. For another node, give the API's address and an admin token:

```sh
export GOETHITE_TOKEN=gth_…
goethite tui --api https://dns.example.lan:8053
```

| Option                | Environment      | Meaning                                                   |
| --------------------- | ---------------- | --------------------------------------------------------- |
| `--api <URL>`         | `GOETHITE_API`   | The API's address, `http://` or `https://`                |
| `--token-file <PATH>` | `GOETHITE_TOKEN` | The admin token, from a file or the environment           |
| `--ca-file <PATH>`    |                  | A PEM CA certificate, for an API with its own certificate |

The token is never taken on the command line, where other users of the machine could see it in
the process list. Without `--ca-file`, HTTPS certificates are checked against the bundled Mozilla
roots.

## Screens

Switch screens with <kbd>Tab</kbd>, the arrow keys, or <kbd>1</kbd>–<kbd>5</kbd>.

1. **Dashboard**: the last 24 hours (queries, blocked, cached, forwarded, failed, average answer
   time), the top names, blocked names and clients, the filter's rule count, and whether each
   upstream is up.
2. **Query log**: the newest queries, with their client, type, answer and the rule that decided.
3. **Lists**: the filter lists, whether each is on, its rule count, its last update, who manages it
   and any download or parse problem.
4. **Clients**: the clients, their addresses and their groups.
5. **Groups**: each group's filtering, safe search, lists and clients.

Every answer carries a text label (`BLOCKED`, `ALLOWED`, `CACHED` and so on), so nothing depends on
color alone.

## Keys

| Key                                                        | Where      | Does                                                             |
| ---------------------------------------------------------- | ---------- | ---------------------------------------------------------------- |
| <kbd>Tab</kbd>, <kbd>1</kbd>–<kbd>5</kbd>                  | everywhere | Switch screens                                                   |
| <kbd>↑</kbd> <kbd>↓</kbd>, <kbd>k</kbd> <kbd>j</kbd>       | tables     | Move the selection                                               |
| <kbd>p</kbd>                                               | everywhere | Pause filtering for 10 minutes                                   |
| <kbd>P</kbd>                                               | everywhere | Resume filtering                                                 |
| <kbd>R</kbd>, <kbd>F5</kbd>                                | everywhere | Refresh now                                                      |
| <kbd>/</kbd>                                               | query log  | Filter by name; <kbd>Enter</kbd> applies, <kbd>Esc</kbd> cancels |
| <kbd>b</kbd>                                               | query log  | Show blocked queries only, or everything                         |
| <kbd>Space</kbd>                                           | lists      | Turn the selected list on or off                                 |
| <kbd>r</kbd>                                               | lists      | Download the lists now                                           |
| <kbd>q</kbd>, <kbd>Esc</kbd>, <kbd>Ctrl</kbd>+<kbd>C</kbd> | everywhere | Quit                                                             |

Lists managed by Terraform cannot be changed from the TUI; change them in Terraform instead. Every
change the TUI makes goes through the API, so it lands in the audit log like any other.
