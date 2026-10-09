---
title: Terraform
description: Manage goethite's filtering configuration with Terraform or OpenTofu.
---

The goethite provider for Terraform and OpenTofu manages the filtering configuration through the
[REST API](../api/): filter lists, custom rules, client groups, clients, schedules and settings.
It lives in its own repository,
[nxplain-sh/terraform-provider-goethite](https://github.com/nxplain-sh/terraform-provider-goethite),
where its [documentation](https://github.com/nxplain-sh/terraform-provider-goethite/tree/main/docs)
describes every resource.

```hcl
resource "goethite_list" "ads" {
  name = "Ads and trackers"
  url  = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
}

resource "goethite_schedule" "school" {
  name      = "School hours"
  time_zone = "Europe/Berlin"
  windows   = [{ days = ["mon", "tue", "wed", "thu", "fri"], start = "08:00", end = "15:00" }]
}

resource "goethite_list" "social" {
  name = "Social media"
  url  = "https://lists.example/social.txt"
}

resource "goethite_group" "kids" {
  name        = "Kids"
  safe_search = true
  lists = [
    { list = goethite_list.ads.id },
    { list = goethite_list.social.id, schedule = goethite_schedule.school.id },
  ]
}

resource "goethite_client" "tablet" {
  name      = "Tablet"
  addresses = ["192.168.1.23"]
  group     = goethite_group.kids.id
}
```

## Install

The provider is not on the Terraform Registry yet. Build it with Go and point Terraform (or
OpenTofu) at it:

```sh
go install github.com/nxplain-sh/terraform-provider-goethite@latest
```

```hcl
# ~/.terraformrc, or ~/.tofurc for OpenTofu
provider_installation {
  dev_overrides {
    "nxplain-sh/goethite" = "/home/you/go/bin"
  }
  direct {}
}
```

```hcl
terraform {
  required_providers {
    goethite = {
      source = "nxplain-sh/goethite"
    }
  }
}

provider "goethite" {
  endpoint = "https://dns1.example:8053"
}
```

Give it an admin token from `goethite token` in the `GOETHITE_TOKEN` environment variable. From
another machine, serve the API over HTTPS (`tls_cert` and `tls_key` in [`[api]`](../configuration/#api));
`ca_file` names the CA of a certificate you made yourself. The provider warns if the token would
travel over plain HTTP.

## What Terraform manages

- **Read-only elsewhere.** Everything the provider creates gets `managed_by = "terraform"`; the
  web UI and the TUI show it read-only. A change made through the API anyway shows up as drift
  in the next plan, and the next apply puts it back.
- **Nothing overwritten by surprise.** Every change carries the revision Terraform last read, so
  a change made between Terraform's refresh and its apply fails with a clear error instead of
  being lost.
- **Existing resources.** Import anything by its ID, as shown in the API (`li_…`, `ru_…`,
  `gr_…`, `cl_…`, `sc_…`); the next apply takes it over. The default group, which always exists,
  is imported as `default`; destroying it resets it to how goethite creates it.
- **Settings.** `goethite_settings` manages only the attributes you set, and destroying it leaves
  the settings as they are.
- **The config file.** Lists and rules in the config file's [`[filter]`](../configuration/#filter)
  table belong to it: `goethite import` puts them back as the file says. Manage each list or rule
  in one place. To move one to Terraform, import it and apply first, then remove it from
  `[filter]`: goethite's imports leave what Terraform manages alone.

## In a cluster

Point the provider at any node of a [cluster](../ha/). A member that does not lead hands changes
to the leader and answers once it has applied them, so Terraform reads back what it wrote. While
the cluster has no leader, plans still work, and applies fail with goethite's explanation
(`503 unavailable`) until it elects one or a member takes it over.
