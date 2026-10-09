//! Repository automation: `cargo xtask <task>` runs the checks CI runs, the
//! same way, from any directory in the repository.
//!
//! The alias is in `.cargo/config.toml`. This crate has no dependencies, so
//! the first `cargo xtask` in a fresh checkout compiles in seconds; keep it
//! that way. shellcheck, cargo-deny and cargo-audit run when they are on
//! `PATH` and are skipped with a note when they are not: `rustup` stays the
//! only requirement, and CI always runs them.

#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

type Result<T = (), E = Box<dyn Error>> = std::result::Result<T, E>;

const HELP: &str = "\
cargo xtask <task>

Tasks:
    ci            every check below, cheapest first: what CI runs
    fmt           format the Rust code in place
    lint          clippy on every target, warnings denied
    test          the test suite, doctests included
    doc           rustdoc, warnings denied
    toolchain     rust-toolchain.toml pins the MSRV from Cargo.toml
    shellcheck    lint the shell scripts (needs shellcheck)
    supply-chain  cargo deny and cargo audit on both workspaces (needs both)
    help          this message
";

/// The cargo-deny checks CI runs.
const DENY_CHECKS: [&str; 4] = ["advisories", "bans", "licenses", "sources"];

fn main() -> ExitCode {
    let result = match env::args().nth(1).as_deref() {
        Some("ci") => ci(),
        Some("fmt") => cargo(&["fmt", "--all"]),
        Some("lint") => lint(),
        Some("test") => test(),
        Some("doc") => doc(),
        Some("toolchain") => toolchain(),
        Some("shellcheck") => shellcheck(),
        Some("supply-chain") => supply_chain(),
        Some("help" | "--help" | "-h") | None => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Some(unknown) => Err(format!("unknown task `{unknown}`\n\n{HELP}").into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            say(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

/// Cheap checks first, so a formatting slip does not cost a test run. The
/// web UI has its own checks: `npm run build` and `npm test` in `web/`.
fn ci() -> Result {
    cargo(&["fmt", "--all", "--check"])?;
    toolchain()?;
    shellcheck()?;
    lint()?;
    doc()?;
    test()?;
    supply_chain()
}

fn lint() -> Result {
    cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--locked",
        "--",
        "-D",
        "warnings",
    ])
}

/// Without `--all-targets`, `cargo test` also runs the doctests.
fn test() -> Result {
    cargo(&["test", "--workspace", "--all-features", "--locked"])
}

fn doc() -> Result {
    cargo_with_env(
        &[
            "doc",
            "--workspace",
            "--no-deps",
            "--all-features",
            "--locked",
        ],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )
}

/// The pinned toolchain is the MSRV: `channel` in rust-toolchain.toml is
/// `rust-version` from Cargo.toml, or a patch release of it.
fn toolchain() -> Result {
    let root = root()?;
    let msrv = toml_string(&root.join("Cargo.toml"), "rust-version")?;
    let channel = toml_string(&root.join("rust-toolchain.toml"), "channel")?;
    let pins_msrv = channel
        .strip_prefix(msrv.as_str())
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'));
    if pins_msrv {
        say(&format!("toolchain {channel} pins rust-version {msrv}"));
        Ok(())
    } else {
        Err(format!("rust-toolchain.toml pins {channel}, but rust-version is {msrv}").into())
    }
}

fn shellcheck() -> Result {
    let Some(shellcheck) = which("shellcheck") else {
        skip("shellcheck");
        return Ok(());
    };
    let root = root()?;
    let listing = Command::new("git")
        .current_dir(&root)
        .args(["ls-files", "-z", "*.sh"])
        .output()?;
    if !listing.status.success() {
        return Err(format!("`git ls-files` failed: {}", listing.status).into());
    }
    let listing = String::from_utf8(listing.stdout)?;
    let scripts: Vec<&str> = listing
        .split('\0')
        .filter(|path| !path.is_empty())
        .collect();
    run(Command::new(shellcheck).current_dir(&root).args(scripts))
}

/// The fuzz targets are a workspace of their own, with their own lockfile.
fn supply_chain() -> Result {
    if which("cargo-deny").is_some() {
        cargo(&[&["deny", "check"][..], &DENY_CHECKS].concat())?;
        cargo(
            &[
                &["deny", "--manifest-path", "fuzz/Cargo.toml", "check"][..],
                &DENY_CHECKS,
            ]
            .concat(),
        )?;
    } else {
        skip("cargo-deny");
    }
    if which("cargo-audit").is_some() {
        cargo(&["audit", "--deny", "warnings"])?;
        cargo(&["audit", "--deny", "warnings", "--file", "fuzz/Cargo.lock"])?;
    } else {
        skip("cargo-audit");
    }
    Ok(())
}

fn skip(tool: &str) {
    say(&format!(
        "note: {tool} is not on PATH, skipping it (CI runs it)"
    ));
}

/// Runs `cargo` from the repository root. `$CARGO` is the cargo that started
/// this task, so `cargo +nightly xtask ...` stays on nightly throughout.
fn cargo(args: &[&str]) -> Result {
    cargo_with_env(args, &[])
}

fn cargo_with_env(args: &[&str], vars: &[(&str, &str)]) -> Result {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    run(Command::new(cargo)
        .current_dir(root()?)
        .args(args)
        .envs(vars.iter().copied()))
}

fn run(command: &mut Command) -> Result {
    let shown = show(command);
    say(&format!("$ {shown}"));
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{shown}` failed: {status}").into())
    }
}

/// A command as a shell line: variables, program name, arguments.
fn show(command: &Command) -> String {
    let vars = command.get_envs().filter_map(|(key, value)| {
        value.map(|value| format!("{}={}", key.to_string_lossy(), value.to_string_lossy()))
    });
    let program = Path::new(command.get_program())
        .file_name()
        .unwrap_or_else(|| command.get_program())
        .to_string_lossy()
        .into_owned();
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned());
    vars.chain([program])
        .chain(args)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The first `key = "value"` line of a TOML file. Enough for the two
/// top-level keys read here; a TOML parser would be this crate's first
/// dependency.
fn toml_string(path: &Path, key: &str) -> Result<String> {
    fs::read_to_string(path)?
        .lines()
        .find_map(|line| {
            let value = line
                .strip_prefix(key)?
                .trim_start()
                .strip_prefix('=')?
                .trim();
            value
                .strip_prefix('"')?
                .strip_suffix('"')
                .map(str::to_owned)
        })
        .ok_or_else(|| format!("no `{key} = \"...\"` line in {}", path.display()).into())
}

/// The first file called `program` in a `PATH` directory.
fn which(program: &str) -> Option<PathBuf> {
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// The repository root: this crate's parent directory, wherever the task
/// was started from.
fn root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask/ has no parent directory".into())
}

#[allow(
    clippy::print_stderr,
    reason = "progress and errors for the person running the task; there is no subscriber"
)]
fn say(line: &str) {
    eprintln!("{line}");
}

#[allow(clippy::print_stdout, reason = "the help text is the task's output")]
fn print_help() {
    print!("{HELP}");
}
