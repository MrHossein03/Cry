//! `cry ssh` — ephemeral-key SSH using a CryDNA-derived Ed25519 identity.
//!
//! ## Flow
//!
//! 1. Derive a deterministic Ed25519 key from passphrase + namespace.
//! 2. Spawn a fresh temporary `ssh-agent` process.
//! 3. Encode the derived key as OpenSSH private key text **in memory**.
//! 4. Pipe that key into `ssh-add -` (stdin), never touching disk.
//! 5. Run system `ssh` with `SSH_AUTH_SOCK` / `SSH_AGENT_PID` pointing to
//!    our temporary agent.
//! 6. On drop, kill the temporary agent via `ssh-agent -k`.

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

#[cfg(windows)]
fn try_start_windows_ssh_agent_service() {
    let _ = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Service -Name ssh-agent -ErrorAction SilentlyContinue",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(windows)]
fn windows_ssh_auth_sock() -> String {
    match std::env::var("SSH_AUTH_SOCK") {
        Ok(sock) if sock.starts_with(r"\\.\pipe\") => sock,
        _ => r"\\.\pipe\openssh-ssh-agent".to_string(),
    }
}

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

/// Arguments for `cry ssh`.
#[derive(Args, Debug)]
pub struct SshArgs {
    /// SSH target in OpenSSH syntax: `[user@]hostname`.
    #[arg(value_name = "USER@HOST")]
    pub target: String,

    /// Optional passphrase override.
    ///
    /// If omitted, `main.rs` prompts securely with input echo disabled.
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
// Temporary agent lifecycle
// ---------------------------------------------------------------------------

/// Handle for an ephemeral `ssh-agent` session.
///
/// The agent is spawned per `cry ssh` invocation and is terminated in `Drop`.
struct TempAgent {
    /// Agent socket path / endpoint used by OpenSSH tooling.
    socket: String,
    /// Agent PID reported by `ssh-agent` when a per-session agent is spawned.
    pid: Option<String>,
    /// Whether this process owns agent lifecycle and should kill it on drop.
    owned: bool,
}

impl TempAgent {
    /// Spawn a temporary agent, with Windows fallback to the built-in named-pipe agent.
    fn spawn() -> Result<Self, CryError> {
        let out = Command::new("ssh-agent").arg("-s").output();

        if let Ok(out) = out {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                #[cfg(windows)]
                let socket =
                    extract_var(&stdout, "SSH_AUTH_SOCK").unwrap_or_else(windows_ssh_auth_sock);
                #[cfg(not(windows))]
                let socket = extract_var(&stdout, "SSH_AUTH_SOCK").ok_or_else(|| {
                    CryError::InvalidFormat("Could not parse SSH_AUTH_SOCK".into())
                })?;

                #[cfg(windows)]
                let pid = extract_var(&stdout, "SSH_AGENT_PID");
                #[cfg(not(windows))]
                let pid = Some(extract_var(&stdout, "SSH_AGENT_PID").ok_or_else(|| {
                    CryError::InvalidFormat("Could not parse SSH_AGENT_PID".into())
                })?);
                let owned = pid.is_some();
                return Ok(Self { socket, pid, owned });
            }

            #[cfg(windows)]
            {
                try_start_windows_ssh_agent_service();
                // Windows OpenSSH default agent endpoint (named pipe).
                // This path is used by the built-in `ssh-agent` service.
                let socket = windows_ssh_auth_sock();
                return Ok(Self {
                    socket,
                    pid: None,
                    owned: false,
                });
            }

            #[cfg(not(windows))]
            {
                return Err(CryError::InvalidFormat(format!(
                    "ssh-agent failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                )));
            }
        }

        #[cfg(windows)]
        {
            try_start_windows_ssh_agent_service();
            let socket = windows_ssh_auth_sock();
            return Ok(Self {
                socket,
                pid: None,
                owned: false,
            });
        }

        #[cfg(not(windows))]
        {
            Err(CryError::InvalidFormat("Failed to spawn ssh-agent".into()))
        }
    }

    /// Add an OpenSSH private key via stdin (`ssh-add -`).
    ///
    /// This keeps key material entirely in memory; no temporary files are used.
    fn add_private_key(&self, key_pem: &Zeroizing<String>) -> Result<(), CryError> {
        let mut add_cmd = Command::new("ssh-add");
        add_cmd.arg("-").env("SSH_AUTH_SOCK", &self.socket);
        if let Some(pid) = &self.pid {
            add_cmd.env("SSH_AGENT_PID", pid);
        }

        let mut add = add_cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| CryError::InvalidFormat(format!("Failed to spawn ssh-add: {e}")))?;

        if let Some(stdin) = add.stdin.as_mut() {
            stdin.write_all(key_pem.as_bytes()).map_err(CryError::Io)?;
            stdin.flush().map_err(CryError::Io)?;
        }

        let output = add.wait_with_output().map_err(CryError::Io)?;
        if !output.status.success() {
            return Err(CryError::InvalidFormat(format!(
                "ssh-add failed: {}\nOn Windows, run PowerShell as Administrator and execute: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }
}

impl Drop for TempAgent {
    /// Best-effort cleanup: terminate the temporary agent.
    fn drop(&mut self) {
        if !self.owned {
            return;
        }

        let mut cmd = Command::new("ssh-agent");
        cmd.arg("-k").env("SSH_AUTH_SOCK", &self.socket);
        if let Some(pid) = &self.pid {
            cmd.env("SSH_AGENT_PID", pid);
        }

        let _ = cmd.status();
    }
}

// ---------------------------------------------------------------------------
// Public entrypoint
// ---------------------------------------------------------------------------

/// Execute `cry ssh` end-to-end.
///
/// Key security properties:
/// - private key is derived deterministically in memory,
/// - encoded in OpenSSH format in memory,
/// - piped to `ssh-add` via stdin,
/// - never written to disk.
pub fn run_ssh(args: SshArgs, passphrase: &Zeroizing<Vec<u8>>) -> Result<(), CryError> {
    // 1) Deterministic identity derivation (Argon2id params defined in CryDNA).
    let identity = Identity::derive(passphrase, &args.namespace, 0, None)?;
    let comment = format!("CryDNA:{}", args.namespace);

    // 2) Convert derived key to OpenSSH private key text (PEM) in-memory only.
    let keypair = Ed25519Keypair::from_bytes(&identity.signing_key.to_keypair_bytes())
        .map_err(|e| CryError::InvalidFormat(format!("OpenSSH key build failed: {e}")))?;
    let private = PrivateKey::new(KeypairData::Ed25519(keypair), &comment)
        .map_err(|e| CryError::InvalidFormat(format!("OpenSSH key build failed: {e}")))?;
    let key_pem = private
        .to_openssh(LineEnding::LF)
        .map_err(|e| CryError::InvalidFormat(format!("OpenSSH key encode failed: {e}")))?;

    // 3) Spawn temporary agent and inject key through stdin.
    let agent = TempAgent::spawn()?;
    agent.add_private_key(&key_pem)?;

    // 4) Execute system ssh pinned to this ephemeral agent.
    let mut ssh = Command::new("ssh");
    ssh.env("SSH_AUTH_SOCK", &agent.socket);
    if let Some(pid) = &agent.pid {
        ssh.env("SSH_AGENT_PID", pid);
    }
    ssh.arg("-o")
        .arg(format!("IdentityAgent={}", &agent.socket));
    ssh.arg("-o").arg("IdentitiesOnly=yes");

    if let Some(port) = args.port {
        ssh.arg("-p").arg(port.to_string());
    }
    for extra in &args.ssh_args {
        ssh.arg(extra);
    }
    ssh.arg(&args.target);

    let status = ssh
        .status()
        .map_err(|e| CryError::InvalidFormat(format!("Failed to exec ssh: {e}")))?;

    if !status.success() {
        eprintln!("  ssh exited with status: {:?}", status.code());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Parse a variable from `ssh-agent` output.
///
/// Supports both sh-style and csh-style lines:
/// - `SSH_AUTH_SOCK=/tmp/...; export SSH_AUTH_SOCK;`
/// - `setenv SSH_AUTH_SOCK /tmp/...;`
fn extract_var(text: &str, var: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();

        if let Some(rest) = line.strip_prefix(&format!("{var}=")) {
            return Some(rest.split(';').next()?.trim().to_string());
        }

        if let Some(rest) = line.strip_prefix("setenv ") {
            let mut parts = rest.splitn(3, ' ');
            if parts.next()? == var {
                return Some(parts.next()?.trim_end_matches(';').to_string());
            }
        }
    }

    None
}
