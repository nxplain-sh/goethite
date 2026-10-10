//! `goethite user`: managing the users with access to the API, from the
//! command line.
//!
//! Every command needs goethite to be stopped: the store file is locked by
//! the running process. In a cluster, change users through the API of any
//! member instead, so every member stays alike.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use goethite_api::hash_recovery_code;
use goethite_store::{Actor, ResetSpec, Role, User, UserSpec};
use jiff::{SignedDuration, Timestamp};

use crate::config::Config;
use crate::{open_store, print};

/// How long an issued reset works, in seconds: one hour.
const RESET_TTL_SECONDS: i64 = 60 * 60;

/// What `goethite user` was asked to do.
#[derive(Debug, clap::Subcommand)]
pub(crate) enum UserCommand {
    /// Add a user. Without `--password-file`, a random password is
    /// generated and printed once.
    Add {
        /// The sign-in name.
        name: String,
        /// What the user may do.
        #[arg(long, value_enum, default_value_t = UserRole::Admin)]
        role: UserRole,
        /// A file with the first password, to script the command. The file
        /// is read as it is, without its last newline.
        #[arg(long, value_name = "PATH")]
        password_file: Option<std::path::PathBuf>,
    },
    /// List the users.
    List,
    /// Set a user's password. Without `--password-file`, a random password
    /// is generated and printed once. The user's sessions stop working.
    Passwd {
        /// The sign-in name.
        name: String,
        /// A file with the new password.
        #[arg(long, value_name = "PATH")]
        password_file: Option<std::path::PathBuf>,
    },
    /// Issue a one-time password reset link for a user, valid for an hour.
    Reset {
        /// The sign-in name.
        name: String,
    },
    /// Remove a user.
    Remove {
        /// The sign-in name.
        name: String,
    },
    /// Disable a user: no sign-in, and their sessions stop working.
    Disable {
        /// The sign-in name.
        name: String,
    },
    /// Enable a disabled user.
    Enable {
        /// The sign-in name.
        name: String,
    },
}

/// What `--role` accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum UserRole {
    /// Everything.
    Admin,
    /// Read-only pages and their own account.
    Viewer,
}

impl From<UserRole> for Role {
    fn from(role: UserRole) -> Self {
        match role {
            UserRole::Admin => Self::Admin,
            UserRole::Viewer => Self::Viewer,
        }
    }
}

/// Runs one `goethite user` command.
pub(crate) fn run(config_path: &Path, command: UserCommand) -> Result<()> {
    let config = Config::load(config_path)?;
    let store = open_store(&config)?;
    if store.cluster_value("id")?.is_some() {
        bail!(
            "this node is in a cluster, whose users every member keeps alike: change them \
             through the API of any member, not on the command line"
        );
    }
    let actor = Actor::cli();
    match command {
        UserCommand::Add {
            name,
            role,
            password_file,
        } => {
            let password = password_from(password_file)?;
            let hash = hash_password(&password)?;
            let spec = UserSpec {
                name: name.clone(),
                role: role.into(),
                disabled: false,
                password_hash: hash,
                totp: None,
                recovery: Vec::new(),
                reset: None,
            };
            store
                .create::<User>(spec, &actor)
                .map_err(|err| anyhow::anyhow!("cannot add the user: {err}"))?;
            print(&format!("Added {name} ({}):\n", role_name(role.into())))?;
            print_password(&password)?;
            Ok(())
        }
        UserCommand::List => list(&store),
        UserCommand::Passwd {
            name,
            password_file,
        } => {
            let user = find(&store, &name)?;
            let password = password_from(password_file)?;
            let hash = hash_password(&password)?;
            edit(&store, &actor, &user, move |spec| {
                spec.password_hash = hash;
            })?;
            print(&format!("Set the password of {name}.\n"))?;
            print_password(&password)
        }
        UserCommand::Reset { name } => {
            let user = find(&store, &name)?;
            let token = new_token();
            let hash = hash_recovery_code(&token);
            let expires_at = Timestamp::now()
                .checked_add(SignedDuration::from_secs(RESET_TTL_SECONDS))
                .unwrap_or_else(|_| Timestamp::now());
            edit(&store, &actor, &user, move |spec| {
                spec.reset = Some(ResetSpec { hash, expires_at });
            })?;
            print(&format!(
                "Reset link for {name}, valid for one hour (use it once):\n\n    \
                 /reset?token={token}\n\n\
                 Open it on the web UI of a node that serves one, and set a new password.\n"
            ))
        }
        UserCommand::Remove { name } => {
            let user = find(&store, &name)?;
            store
                .delete::<User>(&user.id, Some(user.revision), &actor)
                .map_err(|err| anyhow::anyhow!("cannot remove {name}: {err}"))?;
            print(&format!("Removed {name}.\n"))
        }
        UserCommand::Disable { name } => set_disabled(&store, &actor, &name, true),
        UserCommand::Enable { name } => set_disabled(&store, &actor, &name, false),
    }
}

fn set_disabled(
    store: &goethite_store::Store,
    actor: &Actor,
    name: &str,
    disabled: bool,
) -> Result<()> {
    let user = find(store, name)?;
    edit(store, actor, &user, move |spec| spec.disabled = disabled)?;
    print(&format!(
        "{} {name}.\n",
        if disabled { "Disabled" } else { "Enabled" }
    ))
}

/// Prints the users as a small table.
fn list(store: &goethite_store::Store) -> Result<()> {
    let config = store.config();
    if config.users.is_empty() {
        return print("No users. Add one with `goethite user add <name>`.\n");
    }
    let mut text = String::from("NAME                 ROLE    STATE    2FA\n");
    for user in &config.users {
        let state = if user.spec.disabled {
            "disabled"
        } else {
            "enabled"
        };
        let totp = if user.spec.totp.as_ref().is_some_and(|totp| totp.enabled) {
            "yes"
        } else {
            "no"
        };
        let _ = writeln!(
            text,
            "{:<20} {:<7} {:<8} {totp}",
            user.spec.name,
            role_name(user.spec.role),
            state
        );
    }
    print(&text)
}

fn find(store: &goethite_store::Store, name: &str) -> Result<User> {
    store
        .user_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("there is no user {name:?}"))
}

/// Reads a user, applies `edit` to the spec, and writes it back.
fn edit(
    store: &goethite_store::Store,
    actor: &Actor,
    user: &User,
    edit: impl FnOnce(&mut UserSpec),
) -> Result<User> {
    let mut spec = user.spec.clone();
    edit(&mut spec);
    store
        .update::<User>(&user.id, spec, Some(user.revision), actor)
        .map_err(|err| anyhow::anyhow!("cannot update {}: {err}", user.spec.name))
}

/// The password from `path`, or a fresh random one.
fn password_from(path: Option<std::path::PathBuf>) -> Result<String> {
    match path {
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            Ok(text.trim_end_matches(['\n', '\r']).to_owned())
        }
        None => goethite_api::new_password().context("cannot gather randomness for a password"),
    }
}

fn hash_password(password: &str) -> Result<String> {
    goethite_api::check_new(password).map_err(|err| anyhow::anyhow!("{err}"))?;
    goethite_api::hash_password(password).context("cannot hash the password")
}

fn print_password(password: &str) -> Result<()> {
    print(&format!(
        "Password (shown once; keep it secret):\n\n    {password}\n"
    ))
}

/// A new one-time reset token.
fn new_token() -> String {
    let mut token = String::from("gtr_");
    let random: [u8; 32] = rand::random();
    for byte in random {
        let _ = write!(token, "{byte:02x}");
    }
    token
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Admin => "admin",
        Role::Viewer => "viewer",
    }
}
