//! Repository automation: `cargo xtask <task>` runs the checks CI runs, the
//! same way, from any directory in the repository.
//!
//! The alias is in `.cargo/config.toml`. This crate has no dependencies, so
//! the first `cargo xtask` in a fresh checkout compiles in seconds; keep it
//! that way. shellcheck, cargo-deny and cargo-audit run when they are on
//! `PATH` and are skipped with a note when they are not: `rustup` stays the
//! only requirement, and CI always runs them. `dist`, the release build, needs
//! docker or podman and nothing else: everything it builds with is pinned in
//! `xtask/dist/Containerfile`.

#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Command, ExitCode, Stdio};

type Result<T = (), E = Box<dyn Error>> = std::result::Result<T, E>;

const HELP: &str = "\
cargo xtask <task>

Tasks:
    ci            every check from fmt to supply-chain, cheapest first: what CI
                  runs
    fmt           format the Rust code in place
    lint          clippy on every target, warnings denied
    test          the test suite, doctests included
    doc           rustdoc, warnings denied
    toolchain     rust-toolchain.toml pins the MSRV from Cargo.toml
    versions      the internal crates and the web UI carry the workspace version
    shellcheck    lint the shell scripts (needs shellcheck)
    supply-chain  cargo deny and cargo audit on both workspaces (needs both)
    dist          the release tarball, packages and SBOMs for this machine's
                  architecture, built from the last commit in the pinned build
                  image (needs docker or podman), into target/dist
    dist-inside   what `dist` runs inside the build image
    image         the container image from the release tarballs in target/dist,
                  as an OCI archive there (needs docker with buildx); with
                  `--push <name:tag>...`, pushed to a registry instead
    help          this message
";

/// The cargo-deny checks CI runs.
const DENY_CHECKS: [&str; 4] = ["advisories", "bans", "licenses", "sources"];

/// The local tag of the image `dist` builds in.
const DIST_IMAGE: &str = "goethite-dist";

/// Where the source sits inside the build image. Paths under it, and under
/// `CARGO_HOME`, are remapped in the binary anyway; a fixed one keeps the
/// rest of the build identical too.
const DIST_SOURCE: &str = "/goethite";

/// The newest glibc a release binary may need: 2.34 runs it on RHEL 9,
/// Ubuntu 22.04, Debian 12 and everything newer. The image has glibc 2.36;
/// `dist` fails if the binary starts to need a symbol from after 2.34.
const DIST_GLIBC: (u32, u32) = (2, 34);

/// What a release tarball holds, from the repository root to its place in
/// the tarball's top directory. The binary comes from the target directory.
const DIST_FILES: [(&str, &str); 8] = [
    ("LICENSE-APACHE", "LICENSE-APACHE"),
    ("LICENSE-MIT", "LICENSE-MIT"),
    ("README.md", "README.md"),
    ("CHANGELOG.md", "CHANGELOG.md"),
    ("deploy/goethite.toml", "goethite.toml"),
    ("config/goethite.example.toml", "goethite.example.toml"),
    (
        "deploy/systemd/goethite.service",
        "systemd/goethite.service",
    ),
    (
        "deploy/systemd/goethite-vrrp.service",
        "systemd/goethite-vrrp.service",
    ),
];

fn main() -> ExitCode {
    let result = match env::args().nth(1).as_deref() {
        Some("ci") => ci(),
        Some("fmt") => cargo(&["fmt", "--all"]),
        Some("lint") => lint(),
        Some("test") => test(),
        Some("doc") => doc(),
        Some("toolchain") => toolchain(),
        Some("versions") => versions(),
        Some("shellcheck") => shellcheck(),
        Some("supply-chain") => supply_chain(),
        Some("dist") => dist(),
        Some("dist-inside") => match env::args_os().nth(2) {
            Some(out) => dist_inside(Path::new(&out)),
            None => Err("usage: cargo xtask dist-inside <output directory>".into()),
        },
        Some("image") => image(&env::args().skip(2).collect::<Vec<_>>()),
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
    versions()?;
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

/// A release bumps one version in several places: the internal crates'
/// `version` in `[workspace.dependencies]`, and the web UI's package.json and
/// its lockfile, whose version names the web UI in its SBOM.
fn versions() -> Result {
    let root = root()?;
    let manifest = root.join("Cargo.toml");
    let version = toml_string(&manifest, "version")?;
    let mut found = Vec::new();
    for line in fs::read_to_string(&manifest)?.lines() {
        if let Some((name, rest)) = line.split_once(" = { path = ")
            && name.starts_with("goethite")
        {
            found.push((name.to_owned(), quoted_after(rest, "version = ")));
        }
    }
    for file in ["web/package.json", "web/package-lock.json"] {
        let text = fs::read_to_string(root.join(file))?;
        let first = text
            .lines()
            .find_map(|line| quoted_after(line, "\"version\": "));
        found.push((file.to_owned(), first));
    }
    let wrong: Vec<String> = found
        .into_iter()
        .filter(|(_, found)| found.as_deref() != Some(version.as_str()))
        .map(|(name, found)| format!("{name} has {}", found.as_deref().unwrap_or("no version")))
        .collect();
    if wrong.is_empty() {
        say(&format!("everything carries version {version}"));
        Ok(())
    } else {
        Err(format!(
            "the workspace version is {version}, but {}",
            wrong.join(", ")
        )
        .into())
    }
}

/// The double-quoted string after `prefix` in `text`.
fn quoted_after(text: &str, prefix: &str) -> Option<String> {
    let (_, rest) = text.split_once(prefix)?;
    let (value, _) = rest.strip_prefix('"')?.split_once('"')?;
    Some(value.to_owned())
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

/// Builds the release files for this machine's architecture in the pinned
/// image, from the last commit, and unpacks them into `target/dist`. Nothing
/// is mounted: the source goes in as a `git archive` on stdin and the results
/// come out as a tar stream on stdout, so neither file ownership nor SELinux
/// labels get in the way, with docker or podman alike.
fn dist() -> Result {
    let root = root()?;
    let engine = ["docker", "podman"]
        .into_iter()
        .find(|engine| which(engine).is_some())
        .ok_or("dist needs docker or podman on PATH")?;
    if !capture(git(&root).args(["status", "--porcelain"]))?.is_empty() {
        say("note: uncommitted changes are not built: dist builds the last commit");
    }
    let commit = capture(git(&root).args(["rev-parse", "HEAD"]))?;
    // The commit time stands in for the build time wherever one is recorded.
    let epoch = capture(git(&root).args(["log", "-1", "--format=%ct", &commit]))?;
    let context = root.join("xtask").join("dist");
    let mut build = Command::new(engine);
    build.args(["build", "--tag", DIST_IMAGE]);
    // docker's buildx keeps the image in its builder unless told to load it.
    if engine == "docker" {
        build.arg("--load");
    }
    run(build
        .arg("--file")
        .arg(context.join("Containerfile"))
        .arg(&context))?;
    let out = root.join("target").join("dist");
    fs::create_dir_all(&out)?;
    // Build output goes to stderr, so stdout carries the results alone.
    let script = format!(
        "set -eu; mkdir {DIST_SOURCE} /out; tar -x -C {DIST_SOURCE}; cd {DIST_SOURCE}; \
         cargo xtask dist-inside /out >&2; tar -c -C /out ."
    );
    let mut container = Command::new(engine);
    // A fixed host name, which the .rpm records as its build host.
    container
        .args([
            "run",
            "--rm",
            "--interactive",
            "--hostname",
            DIST_IMAGE,
            "--env",
        ])
        .arg(format!("SOURCE_DATE_EPOCH={epoch}"));
    // Fewer parallel jobs for a small VM; the output does not depend on it.
    if let Some(jobs) = env::var_os("CARGO_BUILD_JOBS") {
        let mut jobs_var = OsString::from("CARGO_BUILD_JOBS=");
        jobs_var.push(jobs);
        container.arg("--env").arg(jobs_var);
    }
    pipe(&mut [
        git(&root).args(["archive", "--format=tar", &commit]),
        container.args([DIST_IMAGE, "sh", "-c", &script]),
        Command::new("tar").arg("-x").arg("-C").arg(&out),
    ])?;
    say(&format!(
        "release files for {commit} are in {}",
        out.display()
    ));
    Ok(())
}

/// What `dist` runs inside the image: the web UI, the binary (with its
/// dependency list embedded by cargo-auditable), the SBOMs, then the
/// tarball and the packages, all into `out`. Given the image and `SOURCE_DATE_EPOCH`, the
/// output is the same bytes every time: paths are remapped, and the tarball
/// has fixed times, owners, modes and order.
fn dist_inside(out: &Path) -> Result {
    let root = root()?;
    let out = env::current_dir()?.join(out);
    fs::create_dir_all(&out)?;
    let epoch = env::var("SOURCE_DATE_EPOCH")
        .map_err(|_| "SOURCE_DATE_EPOCH is not set: run `cargo xtask dist`, which sets it")?;
    let host = dist_host(&root)?;
    let version = toml_string(&root.join("Cargo.toml"), "version")?;
    let name = format!("goethite-{version}-{host}");
    dist_web(&root)?;
    dist_binary(&root)?;
    dist_glibc(&root)?;
    dist_sboms(&root, &out, &host, &version, &name)?;
    dist_tarball(&root, &out, &name, &epoch)?;
    dist_packages(&root, &out, &host, &version)?;
    let mut files: Vec<OsString> = fs::read_dir(&out)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<_>>()?;
    files.sort();
    run(Command::new("sha256sum").current_dir(&out).args(files))
}

/// The target triple to build for, once the image is known to hold the
/// pinned Rust and Node.js: a release built with anything else would not be
/// the one its commit describes.
fn dist_host(root: &Path) -> Result<String> {
    let rustc = capture(Command::new("rustc").arg("-vV"))?;
    let field = |name: &str| {
        rustc
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
            .ok_or_else(|| format!("`rustc -vV` printed no `{name}` line"))
    };
    let (release, host) = (field("release:")?, field("host:")?);
    let channel = toml_string(&root.join("rust-toolchain.toml"), "channel")?;
    if release != channel {
        return Err(format!(
            "the build image has Rust {release}, but rust-toolchain.toml pins {channel}: \
             update xtask/dist/Containerfile"
        )
        .into());
    }
    let node = capture(Command::new("node").arg("--version"))?;
    let pinned = fs::read_to_string(root.join("web").join(".node-version"))?;
    if node.strip_prefix('v') != Some(pinned.trim()) {
        return Err(format!(
            "the build image has Node.js {node}, but web/.node-version pins {}: \
             update xtask/dist/Containerfile",
            pinned.trim()
        )
        .into());
    }
    if !host.ends_with("-unknown-linux-gnu") {
        return Err(format!("release builds are for Linux with glibc, not {host}").into());
    }
    Ok(host.to_owned())
}

/// The web UI, which a release build embeds from web/dist and web/dist-docs.
/// Both are removed first, so no stale file is embedded.
fn dist_web(root: &Path) -> Result {
    let web = root.join("web");
    remove_dir_if_exists(&web.join("dist"))?;
    remove_dir_if_exists(&web.join("dist-docs"))?;
    run(Command::new("npm")
        .current_dir(&web)
        .args(["ci", "--ignore-scripts"]))?;
    run(Command::new("npm").current_dir(&web).args(["run", "build"]))
}

/// The binary. Rust and C code alike record source paths (panic locations,
/// `__FILE__`), so the source and the registry get fixed names.
fn dist_binary(root: &Path) -> Result {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .ok_or("neither CARGO_HOME nor HOME is set")?;
    let (source, cargo_home) = (root.display(), cargo_home.display());
    let rustflags = format!(
        "--remap-path-prefix={source}={DIST_SOURCE}\x1f--remap-path-prefix={cargo_home}=/cargo"
    );
    let cflags =
        format!("-ffile-prefix-map={source}={DIST_SOURCE} -ffile-prefix-map={cargo_home}=/cargo");
    cargo_with_env(
        &[
            "auditable",
            "build",
            "--release",
            "--locked",
            "--package",
            "goethite",
        ],
        &[("CARGO_ENCODED_RUSTFLAGS", &rustflags), ("CFLAGS", &cflags)],
    )
}

/// Fails if the binary needs a glibc newer than [`DIST_GLIBC`].
fn dist_glibc(root: &Path) -> Result {
    let versions = capture(
        Command::new("readelf")
            .args(["--version-info", "--wide"])
            .arg(dist_binary_path(root)),
    )?;
    let newest = versions
        .split("GLIBC_")
        .skip(1)
        .filter_map(|rest| {
            let version: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            let mut parts = version.split('.').map(str::parse::<u32>);
            Some((parts.next()?.ok()?, parts.next()?.ok()?))
        })
        .max()
        .ok_or("readelf shows no glibc symbol versions")?;
    let (major, minor) = DIST_GLIBC;
    if newest > DIST_GLIBC {
        return Err(format!(
            "the binary needs glibc {}.{}, newer than the {major}.{minor} releases promise",
            newest.0, newest.1
        )
        .into());
    }
    say(&format!(
        "the binary needs glibc {}.{} at most ({major}.{minor} allowed)",
        newest.0, newest.1
    ));
    Ok(())
}

/// Where cargo puts the release binary.
fn dist_binary_path(root: &Path) -> PathBuf {
    env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| root.join("target"), PathBuf::from)
        .join("release")
        .join("goethite")
}

/// `<name>.tar.gz` in `out`: the binary and [`DIST_FILES`] under a `<name>/`
/// directory, every entry owned by root, dated `epoch` and in name order.
fn dist_tarball(root: &Path, out: &Path, name: &str, epoch: &str) -> Result {
    let stage = out.join(name);
    remove_dir_if_exists(&stage)?;
    fs::create_dir_all(stage.join("systemd"))?;
    let binary = dist_binary_path(root);
    let files = DIST_FILES
        .iter()
        .map(|&(from, to)| (root.join(from), stage.join(to)));
    for (from, to) in [(binary, stage.join("goethite"))].into_iter().chain(files) {
        fs::copy(&from, &to).map_err(|error| format!("copying {}: {error}", from.display()))?;
    }
    let tarball = fs::File::create(out.join(format!("{name}.tar.gz")))?;
    pipe(&mut [
        Command::new("tar")
            .args(["--create", "--file=-", "--directory"])
            .arg(out)
            .args([
                "--sort=name",
                "--format=gnu",
                "--owner=0",
                "--group=0",
                "--numeric-owner",
                "--mode=u=rwX,go=rX",
            ])
            .arg(format!("--mtime=@{epoch}"))
            .arg(name),
        Command::new("gzip")
            .args(["-9", "--no-name"])
            .stdout(tarball),
    ])?;
    Ok(fs::remove_dir_all(&stage)?)
}

/// The .deb and .rpm packages, from deploy/package/nfpm.yaml. nfpm dates
/// every file with `SOURCE_DATE_EPOCH`, which `dist` sets.
fn dist_packages(root: &Path, out: &Path, host: &str, version: &str) -> Result {
    let arch = if host.starts_with("x86_64-") {
        "amd64"
    } else if host.starts_with("aarch64-") {
        "arm64"
    } else {
        return Err(format!("no package architecture for {host}").into());
    };
    let binary = dist_binary_path(root);
    for packager in ["deb", "rpm"] {
        run(Command::new("nfpm")
            .current_dir(root)
            .args(["package", "--config", "deploy/package/nfpm.yaml"])
            .args(["--packager", packager, "--target"])
            .arg(out)
            .env("GOETHITE_VERSION", version)
            .env("GOETHITE_ARCH", arch)
            .env("GOETHITE_BINARY", &binary))?;
    }
    Ok(())
}

/// Two CycloneDX SBOMs: the crates built into the binary on this target, and
/// the npm packages bundled into the web UI.
fn dist_sboms(root: &Path, out: &Path, host: &str, version: &str, name: &str) -> Result {
    // cargo-cyclonedx writes one SBOM beside every workspace member's
    // Cargo.toml; goethite's is the one that describes the binary.
    const SBOM: &str = "dist-sbom";
    // npm stamps its SBOM with a random serial number and the current time;
    // the serial number is optional in CycloneDX, and the time becomes the
    // commit's, as cargo-cyclonedx makes it.
    const STABLE: &str = "let json = ''; \
        process.stdin.on('data', (chunk) => (json += chunk)).on('end', () => { \
            const bom = JSON.parse(json); \
            delete bom.serialNumber; \
            const epoch = Number(process.env.SOURCE_DATE_EPOCH); \
            bom.metadata.timestamp = new Date(epoch * 1000).toISOString(); \
            process.stdout.write(JSON.stringify(bom, null, 2) + '\\n'); \
        });";
    cargo(&[
        "cyclonedx",
        "--manifest-path",
        "crates/goethite/Cargo.toml",
        "--format",
        "json",
        "--spec-version",
        "1.5",
        "--target",
        host,
        "--override-filename",
        SBOM,
        "--quiet",
    ])?;
    let sbom = format!("{SBOM}.json");
    fs::rename(
        root.join("crates").join("goethite").join(&sbom),
        out.join(format!("{name}.cdx.json")),
    )?;
    let mut members = vec![root.join("xtask")];
    for entry in fs::read_dir(root.join("crates"))? {
        members.push(entry?.path());
    }
    for member in members {
        match fs::remove_file(member.join(&sbom)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    let web = fs::File::create(out.join(format!("goethite-{version}-web.cdx.json")))?;
    pipe(&mut [
        Command::new("npm").current_dir(root.join("web")).args([
            "sbom",
            "--sbom-format=cyclonedx",
            "--sbom-type=application",
            "--omit=dev",
            "--package-lock-only",
        ]),
        Command::new("node").args(["--eval", STABLE]).stdout(web),
    ])
}

/// The container image (deploy/container/Containerfile) for every
/// architecture with a release tarball in target/dist: the binaries come out
/// of the tarballs, so the image holds exactly what was released. Without
/// arguments it is written to target/dist as an OCI archive; with
/// `--push <name:tag>...` it goes to a registry under each name, and the
/// digest is printed. Timestamps are the last commit's, so the same tarballs
/// give the same image.
fn image(args: &[String]) -> Result {
    let push: Vec<&str> = match args.split_first() {
        None => Vec::new(),
        Some((flag, names)) if flag == "--push" && !names.is_empty() => {
            names.iter().map(String::as_str).collect()
        }
        Some(_) => return Err("usage: cargo xtask image [--push <name:tag>...]".into()),
    };
    let root = root()?;
    let dist = root.join("target").join("dist");
    let version = toml_string(&root.join("Cargo.toml"), "version")?;
    let context = dist.join("image");
    remove_dir_if_exists(&context)?;
    fs::create_dir_all(context.join("empty"))?;
    let mut platforms = Vec::new();
    for (arch, triple) in [
        ("amd64", "x86_64-unknown-linux-gnu"),
        ("arm64", "aarch64-unknown-linux-gnu"),
    ] {
        let name = format!("goethite-{version}-{triple}");
        let tarball = dist.join(format!("{name}.tar.gz"));
        if !tarball.is_file() {
            continue;
        }
        let binary = fs::File::create(context.join(format!("goethite-{arch}")))?;
        run(Command::new("tar")
            .arg("--extract")
            .arg("--to-stdout")
            .arg("--file")
            .arg(&tarball)
            .arg(format!("{name}/goethite"))
            .stdout(binary))?;
        platforms.push(format!("linux/{arch}"));
    }
    if platforms.is_empty() {
        return Err(format!(
            "no release tarball for {version} in {}: run `cargo xtask dist` first",
            dist.display()
        )
        .into());
    }
    fs::copy(
        root.join("deploy").join("container").join("goethite.toml"),
        context.join("goethite.toml"),
    )?;
    let epoch = capture(git(&root).args(["log", "-1", "--format=%ct", "HEAD"]))?;
    let mut build = Command::new("docker");
    build
        .args(["buildx", "build", "--platform", &platforms.join(",")])
        .arg("--file")
        .arg(root.join("deploy").join("container").join("Containerfile"))
        // buildx's own provenance carries build times; the release workflow
        // attests the image instead.
        .args(["--provenance=false", "--sbom=false"])
        .arg("--build-arg")
        .arg(format!("SOURCE_DATE_EPOCH={epoch}"))
        .env("SOURCE_DATE_EPOCH", &epoch);
    if push.is_empty() {
        let archive = dist.join(format!("goethite-{version}-image.oci.tar"));
        build.arg("--output").arg(format!(
            "type=oci,dest={},rewrite-timestamp=true",
            archive.display()
        ));
    } else {
        build
            .arg("--output")
            .arg(format!(
                "type=image,\"name={}\",push=true,rewrite-timestamp=true",
                push.join(",")
            ))
            .arg("--metadata-file")
            .arg(dist.join("image-metadata.json"));
    }
    run(build.arg(&context))?;
    fs::remove_dir_all(&context)?;
    Ok(())
}

fn remove_dir_if_exists(dir: &Path) -> Result {
    match fs::remove_dir_all(dir) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

fn git(root: &Path) -> Command {
    let mut git = Command::new("git");
    git.current_dir(root);
    git
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

/// Runs a command and returns its standard output, trimmed.
fn capture(command: &mut Command) -> Result<String> {
    let output = command.stderr(Stdio::inherit()).output()?;
    if output.status.success() {
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    } else {
        Err(format!("`{}` failed: {}", show(command), output.status).into())
    }
}

/// Runs `first | second | ...`, each command's stdout feeding the next one's
/// stdin, and fails naming every command that failed.
fn pipe(commands: &mut [&mut Command]) -> Result {
    let shown: Vec<String> = commands.iter().map(|command| show(command)).collect();
    say(&format!("$ {}", shown.join(" | ")));
    let last = commands.len().saturating_sub(1);
    let mut children = Vec::with_capacity(commands.len());
    let mut input: Option<ChildStdout> = None;
    for (index, command) in commands.iter_mut().enumerate() {
        if let Some(stdout) = input.take() {
            command.stdin(stdout);
        }
        if index < last {
            command.stdout(Stdio::piped());
        }
        let mut child = command.spawn()?;
        input = child.stdout.take();
        children.push(child);
    }
    let mut failed = Vec::new();
    for (shown, mut child) in shown.into_iter().zip(children) {
        let status = child.wait()?;
        if !status.success() {
            failed.push(format!("`{shown}` failed: {status}"));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; ").into())
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
