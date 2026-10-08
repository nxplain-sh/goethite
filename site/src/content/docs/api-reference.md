---
title: API reference
description: Every /api/v1 endpoint, generated from the Rust code.
---

The full reference for goethite's REST API is generated from the OpenAPI document that the Rust
code produces. CI checks that the committed document matches the code, and that pull requests do
not break `/api/v1` unless they are marked as intentionally breaking.

- [Browse the API reference](../reference/), with every endpoint, parameter and schema.
- [Download the OpenAPI 3.1 document](https://github.com/nxplain-sh/goethite/blob/main/crates/goethite-api/openapi.json),
  for example to generate a client. `goethite openapi` prints the document for the version you run.

[REST API](../api/) explains access, revisions, errors and common tasks.
