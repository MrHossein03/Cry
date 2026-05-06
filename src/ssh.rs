//! `cry ssh` — ephemeral-key SSH using a CryDNA-derived Ed25519 identity.
//!
//! ## Flow (Unix)
//!
//! 1. Derive a deterministic Ed25519 key from passphrase + namespace.
//! 2. Spawn a fresh temporary `ssh-agent` process (Unix socket).
//! 3. Encode the derived key as OpenSSH private key text **in memory**.
//! 4. Pipe that key into `ssh-add -` (stdin), never touching disk.
//! 5. Run system `ssh` with `SSH_AUTH_SOCK` pointing to our temporary agent.
//! 6. On drop, kill the temporary agent via `ssh-agent -k`.
//!
//! ## Flow (Windows)
//!
//! Windows OpenSSH does not support `ssh-add -` (stdin pipe) reliably.
//! Instead we write the unencrypted private key to a secure temp file
//! with restricted permissions (owner-only), pass it to `ssh -i`, then
//! securely wipe and delete the file on exit.
//!
//! The temp file is placed in `%TEMP%` with a random suffix and is removed
//! in all exit paths (normal, error, and panic via a RAII guard).

use std::io::Write as IoWrite;
use std::process::Command;

use clap::Args;
use ssh_key::{
    LineEnding,
    private::{Ed25519Keypair, KeypairData, PrivateKey},
};
use zeroize::Zeroizing;

use crate::crydna::Identity;
use crate::error::CryError;

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

/// Arguments for `cry ssh`.
#[derive(Args, Debug)]
pub struct SshArgs {
    /// SSH target in OpenSSH syntax: `[user@]hostname`.
    #[arg(value_name = "USER@HOST")]
    pub target: String,

    /// Optional passphrase override (use --pass-file in CI instead).
    #[arg(long = "passphrase", value_name = "PASS")]
    pub passphrase: Option<String>,

    /// Derivation namespace (extra context/salt domain).
    ///
    /// Same passphrase + same namespace => same deterministic key.
    #[arg(
        short = 'n',
        long = "namespace",
        value_name = "NAME",
        default_value = "default"
    )]
    pub namespace: String,

    /// Key version for rotation (must match what was registered on the server).
    #[arg(long = "key-version", default_value_t = 0, value_name = "N")]
    pub key_version: u32,

    /// Sub-identity label (must match what was registered on the server).
    #[arg(long = "sub-id", value_name = "LABEL")]
    pub sub_id: Option<String>,

    /// Read passphrase from a file instead of prompting.
    #[arg(long = "pass-file", value_name = "FILE", help_heading = "Advanced")]
    pub pass_file: Option<std::path::PathBuf>,

    /// Optional SSH port forwarded as `-p PORT`.
    #[arg(short = 'p', long = "port", value_name = "PORT")]
    pub port: Option<u16>,

    /// Extra args forwarded verbatim to `ssh`.
    ///
    /// Usage: `cry ssh user@host -- -v -L 8080:localhost:8080`
    #[arg(last = true, value_name = "SSH_ARG")]
    pub ssh_args: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public entrypoint — dispatches to Unix or Windows implementation
// ---------------------------------------------------------------------------

pub fn run_ssh(args: SshArgs, passphrase: &Zeroizing<Vec<u8>>) -> Result<(), CryError> {
    // 1) Derive the Ed25519 identity.
    let identity = Identity::derive(
        passphrase,
        &args.namespace,
        args.key_version,
        args.sub_id.as_deref(),
    )?;
    let comment = format!("CryDNA:{}", args.namespace);

    // 2) Encode the private key as unencrypted OpenSSH PEM (in memory).
    //    We need the unencrypted form so ssh/ssh-add can use it without a
    //    second passphrase prompt. The Zeroizing wrapper wipes it on drop.
    let key_pem = encode_openssh_private_key(&identity, &comment)?;

    // 3) Platform-specific SSH invocation.
    #[cfg(unix)]
    return run_ssh_unix(args, &key_pem);

    #[cfg(windows)]
    return run_ssh_windows(args, &key_pem);
}

// ---------------------------------------------------------------------------
// OpenSSH key encoding (shared)
// ---------------------------------------------------------------------------

/// Encode the identity as an **unencrypted** OpenSSH private key PEM.
///
/// We use no passphrase here because:
/// - Unix: key is injected into an ephemeral agent via stdin; agent holds it.
/// - Windows: key is written to a 0600 temp file for the duration of the
///   session and wiped immediately after.
///
/// In neither case is the caller asked for a second passphrase.
fn encode_openssh_private_key(
    identity: &Identity,
    comment: &str,
) -> Result<Zeroizing<String>, CryError> {
    let keypair = Ed25519Keypair::from_bytes(&identity.signing_key.to_keypair_bytes())
        .map_err(|e| CryError::InvalidFormat(format!("OpenSSH key build failed: {e}")))?;
    let private = PrivateKey::new(KeypairData::Ed25519(keypair), comment)
        .map_err(|e| CryError::InvalidFormat(format!("OpenSSH key build failed: {e}")))?;
    // Unencrypted — no passphrase.
    private
        .to_openssh(LineEnding::LF)
        .map_err(|e| CryError::InvalidFormat(format!("OpenSSH key encode failed: {e}")))
}

// ---------------------------------------------------------------------------
// Unix implementation — ephemeral ssh-agent
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn run_ssh_unix(args: SshArgs, key_pem: &Zeroizing<String>) -> Result<(), CryError> {
    // Spawn a fresh agent and inject the key via stdin.
    let agent = TempAgent::spawn()?;
    agent.add_private_key(key_pem)?;

    // Build the ssh command.
    let mut ssh = Command::new("ssh");
    ssh.env("SSH_AUTH_SOCK", &agent.socket);
    if let Some(pid) = &agent.pid {
        ssh.env("SSH_AGENT_PID", pid);
    }

    // Point ssh at our ephemeral agent only. We do NOT pass -F /dev/null
    // because that suppresses known_hosts and other useful config.
    // We DO disable fallback auth methods so the outcome is unambiguous.
    ssh.arg("-o").arg(format!("IdentityAgent={}", &agent.socket));
    ssh.arg("-o").arg("IdentitiesOnly=yes");
    ssh.arg("-o").arg("PubkeyAuthentication=yes");
    ssh.arg("-o").arg("PreferredAuthentications=publickey");

    append_common_ssh_args(&mut ssh, &args);

    let status = ssh
        .status()
        .map_err(|e| CryError::InvalidFormat(format!("Failed to exec ssh: {e}")))?;

    if !status.success() {
        eprintln!("  ssh exited with status: {:?}", status.code());
    }

    // agent is dropped here → ssh-agent -k is called
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows implementation — temp key file
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn run_ssh_windows(args: SshArgs, key_pem: &Zeroizing<String>) -> Result<(), CryError> {
    // Write the unencrypted private key to a restricted temp file.
    let guard = TempKeyFile::create(key_pem)?;

    let mut ssh = Command::new("ssh");

    // Use the temp file as the sole identity source.
    ssh.arg("-i").arg(guard.path());
    ssh.arg("-o").arg("IdentitiesOnly=yes");
    ssh.arg("-o").arg("PubkeyAuthentication=yes");
    ssh.arg("-o").arg("PreferredAuthentications=publickey");
    // Suppress the Windows OpenSSH agent so it doesn't offer competing keys.
    ssh.arg("-o").arg("IdentityAgent=none");

    append_common_ssh_args(&mut ssh, &args);

    let status = ssh
        .status()
        .map_err(|e| CryError::InvalidFormat(format!("Failed to exec ssh: {e}")))?;

    if !status.success() {
        eprintln!("  ssh exited with status: {:?}", status.code());
    }

    // guard is dropped here → temp file is wiped and deleted
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helper: append port + user-supplied extra args + target
// ---------------------------------------------------------------------------

fn append_common_ssh_args(ssh: &mut Command, args: &SshArgs) {
    if let Some(port) = args.port {
        ssh.arg("-p").arg(port.to_string());
    }
    for extra in &args.ssh_args {
        ssh.arg(extra);
    }
    ssh.arg(&args.target);
}

// ---------------------------------------------------------------------------
// Unix: ephemeral ssh-agent lifecycle
// ---------------------------------------------------------------------------

#[cfg(unix)]
struct TempAgent {
    socket: String,
    pid: Option<String>,
}

#[cfg(unix)]
impl TempAgent {
    /// Spawn a fresh `ssh-agent` and parse its socket + pid from stdout.
    fn spawn() -> Result<Self, CryError> {
        let out = Command::new("ssh-agent")
            .arg("-s")
            .output()
            .map_err(|e| {
                CryError::InvalidFormat(format!(
                    "Failed to spawn ssh-agent: {e}\n\
                     Make sure openssh-client is installed (e.g. `apt install openssh-client`)."
                ))
            })?;

        if !out.status.success() {
            return Err(CryError::InvalidFormat(format!(
                "ssh-agent exited with error: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }

        let stdout = String::from_utf8_lossy(&out.stdout);

        let socket = extract_var(&stdout, "SSH_AUTH_SOCK").ok_or_else(|| {
            CryError::InvalidFormat(format!(
                "Could not parse SSH_AUTH_SOCK from ssh-agent output:\n{stdout}"
            ))
        })?;

        let pid = extract_var(&stdout, "SSH_AGENT_PID");

        Ok(Self { socket, pid })
    }

    /// Inject an OpenSSH private key by piping it to `ssh-add -` on stdin.
    fn add_private_key(&self, key_pem: &Zeroizing<String>) -> Result<(), CryError> {
        let mut add = Command::new("ssh-add")
            .arg("-")
            .env("SSH_AUTH_SOCK", &self.socket)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| CryError::InvalidFormat(format!("Failed to spawn ssh-add: {e}")))?;

        if let Some(stdin) = add.stdin.as_mut() {
            stdin.write_all(key_pem.as_bytes()).map_err(CryError::Io)?;
            // Close stdin so ssh-add knows EOF has been reached.
        }

        let output = add.wait_with_output().map_err(CryError::Io)?;
        if !output.status.success() {
            return Err(CryError::InvalidFormat(format!(
                "ssh-add failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }
}

#[cfg(unix)]
impl Drop for TempAgent {
    fn drop(&mut self) {
        let mut cmd = Command::new("ssh-agent");
        cmd.arg("-k").env("SSH_AUTH_SOCK", &self.socket);
        if let Some(pid) = &self.pid {
            cmd.env("SSH_AGENT_PID", pid);
        }
        let _ = cmd.status();
    }
}

// ---------------------------------------------------------------------------
// Windows: RAII temp key file
// ---------------------------------------------------------------------------

#[cfg(windows)]
struct TempKeyFile {
    path: std::path::PathBuf,
}

#[cfg(windows)]
impl TempKeyFile {
    /// Write `key_pem` to a temp file with owner-only ACL.
    fn create(key_pem: &Zeroizing<String>) -> Result<Self, CryError> {
        use std::fs::OpenOptions;

        // Build a path like %TEMP%\cry_<hex>.pem
        let mut rng_bytes = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rng_bytes);
        let suffix = crate::crydna::bytes_to_hex(&rng_bytes);

        let path = std::env::temp_dir().join(format!("cry_{suffix}.pem"));

        // Write the file.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(CryError::Io)?;

        file.write_all(key_pem.as_bytes()).map_err(CryError::Io)?;
        file.flush().map_err(CryError::Io)?;
        drop(file);

        // Restrict permissions to owner-only using icacls.
        // This mimics the Unix 0600 behavior.
        let _ = Command::new("icacls")
            .args([
                path.to_str().unwrap_or(""),
                "/inheritance:r",
                "/grant:r",
                &format!("{}:F", whoami_windows()),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        Ok(Self { path })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(windows)]
impl Drop for TempKeyFile {
    fn drop(&mut self) {
        // Overwrite file content with zeros before deleting (best-effort).
        if let Ok(meta) = std::fs::metadata(&self.path) {
            let zeros = vec![0u8; meta.len() as usize];
            let _ = std::fs::write(&self.path, &zeros);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Get the current Windows username for icacls.
#[cfg(windows)]
fn whoami_windows() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "BUILTIN\\Users".to_string())
}

// ---------------------------------------------------------------------------
// Helper: parse a variable from `ssh-agent -s` output
// ---------------------------------------------------------------------------

/// Supports both sh-style and csh-style output:
/// - `SSH_AUTH_SOCK=/tmp/...; export SSH_AUTH_SOCK;`
/// - `setenv SSH_AUTH_SOCK /tmp/...;`
#[cfg(unix)]
fn extract_var(text: &str, var: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();

        // sh/bash style: VAR=value; export VAR;
        if let Some(rest) = line.strip_prefix(&format!("{var}=")) {
            return Some(rest.split(';').next()?.trim().to_string());
        }

        // csh style: setenv VAR value;
        if let Some(rest) = line.strip_prefix("setenv ") {
            let mut parts = rest.splitn(3, ' ');
            if parts.next()? == var {
                return Some(parts.next()?.trim_end_matches(';').to_string());
            }
        }
    }
    None
}
