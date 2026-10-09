# `xtask/`

Repository automation, in Rust instead of shell or Make: the
[cargo-xtask](https://github.com/matklad/cargo-xtask) pattern. The alias in
[`../.cargo/config.toml`](../.cargo/config.toml) turns `cargo xtask ci` into
`cargo run --package xtask -- ci`.

```sh
cargo xtask ci     # what CI runs: fmt, toolchain pin, shellcheck, clippy, rustdoc, tests, deny + audit
cargo xtask fmt    # format in place
cargo xtask help   # every task
```

The crate has **no dependencies** and should keep none: it is compiled before a contributor's
first check. Optional tools (shellcheck, cargo-deny, cargo-audit) are skipped with a note when
they are not installed; CI always runs them.

CI calls cargo directly, one job per check, so a failure names itself in the pull request. When
you change a check, change it in both places.
