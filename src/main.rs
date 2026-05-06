//! `cry` — a fast, minimal CLI cryptography tool.
//!
//! Supported algorithms: AES-256-GCM, ChaCha20-Poly1305
//! Key derivation: Argon2id (64 MiB, 3 iterations)
//! Identity: CryDNA — deterministic Ed25519 keypairs from a passphrase
//! SSH: ephemeral key injection via a temporary ssh-agent (Unix only)

mod bench;
mod cipher;
mod crydna;
mod error;
mod header;
mod kdf;
mod ssh;

use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser};
use zeroize::Zeroizing;

use cipher::{decrypt_file, encrypt_file};
use crydna::{Identity, IdentityArgs, PubKeyFormat, SignArgs, VerifyArgs};
use error::CryError;
use header::Algorithm;

// ---------------------------------------------------------------------------
// Banner / formatting helpers
// ---------------------------------------------------------------------------

fn banner() {
    let ver = env!("CARGO_PKG_VERSION");
    eprintln!("\n  cry 🔐  \x1b[2mv{ver}\x1b[0m\n");
}

fn section(icon: &str, label: &str, value: &str) {
    eprintln!("  {}  \x1b[2m{:<14}\x1b[0m  {}", icon, label, value);
}

fn divider() {
    eprintln!("  \x1b[2m{}\x1b[0m", "─".repeat(56));
}

fn kv(label: &str, value: &str) {
    eprintln!("  \x1b[2m{:<18}\x1b[0m  {}", label, value);
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// cry — encrypt files, decrypt files, or build a deterministic cryptographic identity
#[derive(Parser, Debug)]
#[command(
    name = "cry",
    version = env!("CARGO_PKG_VERSION"),
    about = "Encrypt · Decrypt · Identity · SSH — passphrase-protected, authenticated",
    after_help = concat!(
        "\x1b[2mExamples:\x1b[0m\n",
        "  cry encrypt  -p secret.txt -c secret.cry\n",
        "  cry encrypt  -p secret.txt -c secret.cry -a chacha20poly1305\n",
        "  cry decrypt  -c secret.cry -p recovered.txt\n",
        "  cry identity                                # show default identity\n",
        "  cry identity -n work --openssh              # work key, OpenSSH format\n",
        "  cry identity -n work --key-version 2        # rotated key\n",
        "  cry identity -n work --sub-id deploy        # sub-identity\n",
        "  cry sign     -f report.pdf -n work          # sign a file\n",
        "  cry verify   -f report.pdf -s <SIG> -k <PUB>  # verify a signature\n",
        "  cry ssh      user@host                      # SSH with ephemeral derived key\n",
        "  cry ssh      user@host -n work              # SSH using 'work' namespace key\n",
        "  cry ssh      user@host -- -v -L 8080:localhost:8080  # extra ssh flags\n",
    )
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Encrypt a plaintext file
    #[command(name = "encrypt", alias = "-en", alias = "en")]
    Encrypt(EncryptArgs),

    /// Decrypt an encrypted file (algorithm detected from header)
    #[command(name = "decrypt", alias = "-de", alias = "de")]
    Decrypt(DecryptArgs),

    /// Derive and display a deterministic cryptographic identity (CryDNA)
    ///
    /// The same passphrase + namespace + version always produces the same
    /// Ed25519 keypair, on any machine, without storing anything to disk.
    #[command(name = "identity", alias = "-id", alias = "id")]
    Identity(IdentityArgs),

    /// Sign a file using a derived CryDNA identity
    #[command(name = "sign")]
    Sign(SignArgs),

    /// Verify a file signature against a public key
    #[command(name = "verify")]
    Verify(VerifyArgs),

    /// Run quick crypto benchmarks
    #[command(name = "bench")]
    Bench(bench::BenchArgs),

    /// Connect to an SSH host using a passphrase-derived Ed25519 key
    ///
    /// Derives a CryDNA Ed25519 keypair, injects it into a short-lived
    /// ssh-agent subprocess, then opens an SSH session. The private key
    /// never touches disk at any point. The agent is killed when the
    /// session ends.
    ///
    /// Prerequisites: `ssh` and `ssh-agent` must be on PATH.
    ///
    /// The public key to add to the server's authorized_keys is printed
    /// by `cry identity [--namespace NAME] --ssh`.
    #[command(name = "ssh")]
    Ssh(ssh::SshArgs),
}

// ── Encrypt ───────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
struct EncryptArgs {
    /// Plaintext input file
    #[arg(short = 'p', long = "plain", value_name = "FILE")]
    plain: PathBuf,

    /// Encrypted output file
    #[arg(short = 'c', long = "cipher", value_name = "FILE")]
    cipher: PathBuf,

    /// Encryption algorithm
    #[arg(
        short = 'a',
        long = "algorithm",
        value_name = "ALGO",
        default_value = "aes256gcm"
    )]
    algorithm: Algorithm,

    /// Overwrite the output file if it already exists
    #[arg(long = "force", default_value_t = false)]
    force: bool,

    /// Read passphrase from a file (first line used; useful in containers/CI)
    #[arg(long = "pass-file", value_name = "FILE", help_heading = "Advanced")]
    pass_file: Option<PathBuf>,
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
struct DecryptArgs {
    /// Encrypted input file
    #[arg(short = 'c', long = "cipher", value_name = "FILE")]
    cipher: PathBuf,

    /// Plaintext output file
    #[arg(short = 'p', long = "plain", value_name = "FILE")]
    plain: PathBuf,

    /// Overwrite the output file if it already exists
    #[arg(long = "force", default_value_t = false)]
    force: bool,

    /// Read passphrase from a file (first line used; useful in containers/CI)
    #[arg(long = "pass-file", value_name = "FILE", help_heading = "Advanced")]
    pass_file: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    let Some(command) = cli.command else {
        Cli::command().print_help().unwrap();
        eprintln!();
        return;
    };

    banner();

    let result: Result<(), CryError> = match command {
        // ── Encrypt ──────────────────────────────────────────────────────────
        Command::Encrypt(args) => {
            eprintln!(
                "  🔒  \x1b[1mEncrypting\x1b[0m  {} \x1b[2m→\x1b[0m {}",
                args.plain.display(),
                args.cipher.display()
            );
            section("⚙", "Algorithm", &args.algorithm.to_string());
            section("🔑", "KDF", "Argon2id  (64 MiB · 3 iter · 1 thread)");
            divider();

            read_passphrase(args.pass_file.as_deref(), true).and_then(|p| {
                encrypt_file(&args.plain, &args.cipher, &p, args.algorithm, args.force)
            })
        }

        // ── Decrypt ──────────────────────────────────────────────────────────
        Command::Decrypt(args) => {
            eprintln!(
                "  🔓  \x1b[1mDecrypting\x1b[0m  {} \x1b[2m→\x1b[0m {}",
                args.cipher.display(),
                args.plain.display()
            );
            section("🔑", "KDF", "Argon2id  (64 MiB · 3 iter · 1 thread)");
            divider();

            read_passphrase(args.pass_file.as_deref(), false)
                .and_then(|p| decrypt_file(&args.plain, &args.cipher, &p, args.force))
        }

        // ── Identity (CryDNA) ─────────────────────────────────────────────────
        Command::Identity(args) => {
            let p = &args.params;

            // Build display header
            let mut label = format!("namespace={:?}", p.namespace);
            if p.key_version > 0 {
                label.push_str(&format!("  version={}", p.key_version));
            }
            if let Some(ref sub) = p.sub_id {
                label.push_str(&format!("  sub={sub:?}"));
            }
            eprintln!("  🪪  \x1b[1mCryDNA Identity\x1b[0m  \x1b[2m{label}\x1b[0m");
            section("⚙", "Algorithm", "Ed25519");
            section("🔑", "KDF", "Argon2id  (64 MiB · 3 iter · 1 thread)");
            divider();

            read_passphrase(p.pass_file.as_deref(), false).and_then(|pass| {
                let id = Identity::derive(
                    &pass,
                    &p.namespace,
                    p.key_version,
                    p.sub_id.as_deref(),
                )?;
                divider();

                // Public key output
                match args.format {
                    PubKeyFormat::Hex => {
                        kv("Public key (hex)", &id.public_key_hex());
                    }
                    PubKeyFormat::Base64 => {
                        kv("Public key (b64)", &id.public_key_base64());
                    }
                    PubKeyFormat::All => {
                        kv("Public key (hex)", &id.public_key_hex());
                        kv("Public key (b64)", &id.public_key_base64());
                    }
                }

                kv("Fingerprint", &id.fingerprint());
                if args.show_private_key {
                    kv("Private key (hex)", &id.private_key_hex());
                } else {
                    kv("Private key", "\x1b[2m[in memory only — use --show-private-key to print]\x1b[0m");
                }

                if args.openssh {
                    let key_pass = read_openssh_passphrase()?;
                    let key_pass_str = std::str::from_utf8(&key_pass).map_err(|_| {
                        CryError::InvalidFormat(
                            "OpenSSH key passphrase must be valid UTF-8".to_string(),
                        )
                    })?;
                    let openssh_key = id.openssh_private_key(key_pass_str, &args.comment)?;
                    if let Some(path) = args.private_key_out.as_deref() {
                        let openssh_path = PathBuf::from(format!("{}.openssh_id", path.display()));
                        if openssh_path.exists() && !args.force {
                            return Err(CryError::FileExists(openssh_path.display().to_string()));
                        }
                        std::fs::write(&openssh_path, &openssh_key)?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            std::fs::set_permissions(
                                &openssh_path,
                                std::fs::Permissions::from_mode(0o600),
                            )?;
                        }
                        kv("OpenSSH key file", &openssh_path.display().to_string());
                    } else {
                        divider();
                        eprintln!("  \x1b[2mOpenSSH private key (encrypted):\x1b[0m");
                        eprintln!();
                        eprintln!("{openssh_key}");
                        eprintln!("  \x1b[2mOpenSSH public key line:\x1b[0m");
                        eprintln!("  {}", id.ssh_authorized_keys_line(&args.comment));
                        eprintln!();
                        eprintln!(
                            "  \x1b[2mAppend the line above to ~/.ssh/authorized_keys on your server.\x1b[0m"
                        );
                    }
                }

                if let Some(path) = args.private_key_out.as_deref() {
                    id.write_private_key_hex_file(path, args.force)?;
                    kv("Private key file", &path.display().to_string());
                }

                Ok(())
            })
        }

        // ── Sign ─────────────────────────────────────────────────────────────
        Command::Sign(args) => {
            let p = &args.params;
            eprintln!("  ✍️   \x1b[1mSigning\x1b[0m  {}", args.file.display());
            section(
                "🪪",
                "Namespace",
                &format!("{:?}  v{}", p.namespace, p.key_version),
            );
            section("⚙", "Algorithm", "Ed25519");
            divider();

            let content = std::fs::read(&args.file).map_err(CryError::Io);

            content.and_then(|bytes| {
                read_passphrase(p.pass_file.as_deref(), false).and_then(|pass| {
                    let id =
                        Identity::derive(&pass, &p.namespace, p.key_version, p.sub_id.as_deref())?;
                    let sig = id.sign_content(&bytes);
                    let sig_hex = Identity::signature_hex(&sig);

                    divider();
                    kv("Public key", &id.public_key_hex());
                    kv("File", &args.file.display().to_string());
                    kv("Signature", &sig_hex);
                    eprintln!();
                    eprintln!("  \x1b[2mVerify with:\x1b[0m");
                    eprintln!(
                        "  cry verify -f {} -s {} -k {}",
                        args.file.display(),
                        sig_hex,
                        id.public_key_hex()
                    );

                    Ok(())
                })
            })
        }

        // ── Verify ───────────────────────────────────────────────────────────
        Command::Verify(args) => {
            eprintln!("  🔍  \x1b[1mVerifying\x1b[0m  {}", args.file.display());
            divider();

            let result: Result<(), CryError> = (|| {
                let content = std::fs::read(&args.file).map_err(CryError::Io)?;
                let valid =
                    crydna::verify_content_signature(&args.public_key, &content, &args.signature)?;

                kv("File", &args.file.display().to_string());
                kv("Public key", &args.public_key);
                kv(
                    "Signature",
                    &format!(
                        "{}…{}",
                        &args.signature[..8],
                        &args.signature[args.signature.len().saturating_sub(8)..]
                    ),
                );
                divider();

                if valid {
                    eprintln!(
                        "  \x1b[32m✔\x1b[0m  Signature is \x1b[1mVALID\x1b[0m — file is authentic and untampered."
                    );
                    Ok(())
                } else {
                    Err(CryError::VerificationFailed(
                        "Signature does not match — file may have been tampered with, \
                         or the wrong public key was supplied."
                            .into(),
                    ))
                }
            })();

            result
        }

        // ── Bench ─────────────────────────────────────────────────────────────
        Command::Bench(args) => bench::run_bench(args),

        // ── SSH ───────────────────────────────────────────────────────────────────
        Command::Ssh(args) => {
            // Build namespace label for the banner.
            let ns_label = {
                let s = format!("namespace={:?}", args.namespace);
                s
            };

            eprintln!(
                "  🔑  \x1b[1mSSH\x1b[0m  {}  \x1b[2m({})\x1b[0m",
                args.target, ns_label
            );
            section("⚙", "Key type", "Ed25519 (CryDNA — ephemeral, no disk write)");
            section("🔑", "KDF", "Argon2id  (64 MiB · 3 iter · 1 thread)");
            eprintln!(
                "  \x1b[2mℹ  To add the public key to the server, run:\x1b[0m"
            );
            eprintln!(
                "  \x1b[2m   cry identity -n {} --ssh\x1b[0m",
                args.namespace
            );
            divider();

            if let Some(raw) = &args.passphrase {
                let pass = Zeroizing::new(raw.as_bytes().to_vec());
                ssh::run_ssh(args, &pass)
            } else {
                read_passphrase(None, false).and_then(|pass| ssh::run_ssh(args, &pass))
            }
        }
    };

    eprintln!();
    match result {
        Ok(()) => eprintln!("  \x1b[32m✔\x1b[0m  Done."),
        Err(e) => {
            eprintln!("  \x1b[31m✘\x1b[0m  {e}");
            std::process::exit(1);
        }
    }
    eprintln!();
}

// ---------------------------------------------------------------------------
// Passphrase helpers
// ---------------------------------------------------------------------------

/// Read a passphrase from (in priority order):
///   1. a file (`--pass-file PATH`, first line)
///   2. an interactive terminal prompt (with optional confirmation)
///
/// Status output goes to stderr; stdout stays clean for piping.
/// Returns `Zeroizing<Vec<u8>>` so the bytes are wiped on drop.
fn read_passphrase(
    pass_file: Option<&Path>,
    confirm: bool,
) -> Result<Zeroizing<Vec<u8>>, CryError> {
    if let Some(path) = pass_file {
        let contents = Zeroizing::new(std::fs::read(path)?);
        let first_line = contents
            .split(|b| *b == b'\n' || *b == b'\r')
            .next()
            .unwrap_or(&[]);
        if first_line.is_empty() {
            return Err(CryError::EmptyPassphrase);
        }
        return Ok(Zeroizing::new(first_line.to_vec()));
    }

    let pass = Zeroizing::new(rpassword::prompt_password("  Passphrase : ").map_err(CryError::Io)?);

    if pass.is_empty() {
        return Err(CryError::EmptyPassphrase);
    }

    if confirm {
        let confirm_pass =
            Zeroizing::new(rpassword::prompt_password("  Confirm    : ").map_err(CryError::Io)?);
        if *pass != *confirm_pass {
            return Err(CryError::PassphraseMismatch);
        }
    }

    Ok(Zeroizing::new(pass.as_bytes().to_vec()))
}

fn read_openssh_passphrase() -> Result<Zeroizing<Vec<u8>>, CryError> {
    let pass = Zeroizing::new(
        rpassword::prompt_password("  OpenSSH key passphrase : ").map_err(CryError::Io)?,
    );
    if pass.is_empty() {
        return Err(CryError::EmptyPassphrase);
    }
    let confirm = Zeroizing::new(
        rpassword::prompt_password("  Confirm OpenSSH passphrase : ").map_err(CryError::Io)?,
    );
    if *pass != *confirm {
        return Err(CryError::PassphraseMismatch);
    }
    Ok(Zeroizing::new(pass.as_bytes().to_vec()))
}

// ---------------------------------------------------------------------------
// Integration tests (file-based, cover atomic rename / --force paths)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod integration {
    use super::*;
    use tempfile::TempDir;

    fn passphrase(s: &str) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(s.as_bytes().to_vec())
    }

    fn write_file(dir: &TempDir, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn encrypt_decrypt_roundtrip_aes() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "plain.txt", b"Hello from integration test!");
        let cipher = dir.path().join("out.cry");
        let recovered = dir.path().join("recovered.txt");

        let pass = passphrase("hunter2");
        encrypt_file(&plain, &cipher, &pass, Algorithm::Aes256Gcm, false).unwrap();
        decrypt_file(&recovered, &cipher, &pass, false).unwrap();

        assert_eq!(
            std::fs::read(&plain).unwrap(),
            std::fs::read(&recovered).unwrap()
        );
    }

    #[test]
    fn encrypt_decrypt_roundtrip_chacha() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "plain.txt", b"ChaCha integration test data.");
        let cipher = dir.path().join("out.cry");
        let recovered = dir.path().join("recovered.txt");

        let pass = passphrase("passphrase123");
        encrypt_file(&plain, &cipher, &pass, Algorithm::ChaCha20Poly1305, false).unwrap();
        decrypt_file(&recovered, &cipher, &pass, false).unwrap();

        assert_eq!(
            std::fs::read(&plain).unwrap(),
            std::fs::read(&recovered).unwrap()
        );
    }

    #[test]
    fn encrypt_decrypt_empty_file() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "empty.txt", b"");
        let cipher = dir.path().join("out.cry");
        let recovered = dir.path().join("recovered.txt");

        let pass = passphrase("emptytest");
        encrypt_file(&plain, &cipher, &pass, Algorithm::Aes256Gcm, false).unwrap();
        decrypt_file(&recovered, &cipher, &pass, false).unwrap();

        assert_eq!(std::fs::read(&recovered).unwrap(), b"");
    }

    #[test]
    fn refuses_to_overwrite_without_force() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "plain.txt", b"data");
        let cipher = dir.path().join("out.cry");
        std::fs::write(&cipher, b"existing").unwrap();

        let pass = passphrase("test");
        let err = encrypt_file(&plain, &cipher, &pass, Algorithm::Aes256Gcm, false).unwrap_err();
        assert!(
            matches!(err, CryError::FileExists(_)),
            "expected FileExists, got {err:?}"
        );
        assert_eq!(std::fs::read(&cipher).unwrap(), b"existing");
    }

    #[test]
    fn force_flag_allows_overwrite() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "plain.txt", b"new data");
        let cipher = dir.path().join("out.cry");
        std::fs::write(&cipher, b"old").unwrap();

        let pass = passphrase("test");
        encrypt_file(&plain, &cipher, &pass, Algorithm::Aes256Gcm, true).unwrap();
        assert_ne!(std::fs::read(&cipher).unwrap(), b"old");
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "plain.txt", b"secret");
        let cipher = dir.path().join("out.cry");
        let recovered = dir.path().join("recovered.txt");

        encrypt_file(
            &plain,
            &cipher,
            &passphrase("correct"),
            Algorithm::Aes256Gcm,
            false,
        )
        .unwrap();
        let err = decrypt_file(&recovered, &cipher, &passphrase("wrong"), false).unwrap_err();
        assert!(
            matches!(err, CryError::HeaderTampered | CryError::DecryptionFailed),
            "expected auth failure, got {err:?}"
        );
        assert!(
            !recovered.exists(),
            "tmp file should be cleaned up on failure"
        );
    }

    #[test]
    fn no_tmp_file_left_on_failure() {
        let dir = TempDir::new().unwrap();
        let plain = write_file(&dir, "plain.txt", b"test");
        let cipher = dir.path().join("out.cry");
        let recovered = dir.path().join("recovered.txt");

        encrypt_file(
            &plain,
            &cipher,
            &passphrase("pw"),
            Algorithm::Aes256Gcm,
            false,
        )
        .unwrap();
        let _ = decrypt_file(&recovered, &cipher, &passphrase("bad"), false);

        let tmp = recovered.with_extension("plain.tmp");
        assert!(!tmp.exists(), ".plain.tmp should be cleaned up on failure");
    }

    // ── CryDNA integration ─────────────────────────────────────────────────

    #[test]
    fn identity_sign_verify_full_roundtrip() {
        use crate::crydna;

        let pass = b"integration-test-passphrase";
        let id = Identity::derive(pass, "test-ns", 0, None).unwrap();
        let content = b"document content for signing";
        let sig = id.sign_content(content);
        let pub_hex = id.public_key_hex();
        let sig_hex = Identity::signature_hex(&sig);

        assert!(
            crydna::verify_content_signature(&pub_hex, content, &sig_hex).unwrap(),
            "full sign-verify roundtrip must succeed"
        );
    }

    #[test]
    fn identity_is_reproducible_across_derives() {
        let pass = b"same-passphrase";
        let id1 = Identity::derive(pass, "ns", 3, Some("child")).unwrap();
        let id2 = Identity::derive(pass, "ns", 3, Some("child")).unwrap();
        assert_eq!(
            id1.public_key_hex(),
            id2.public_key_hex(),
            "identical parameters must produce identical public key"
        );
    }
}