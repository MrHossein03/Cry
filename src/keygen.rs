use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crydna::Identity;
use crate::error::CryError;

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum KeyAlgorithm {
    Ed25519,
    Rsa,
    Aes256Gcm,
}
#[derive(clap::Args, Debug)]
pub struct KeygenArgs {
    #[arg(long = "algo", value_enum, default_value_t = KeyAlgorithm::Ed25519)]
    pub algo: KeyAlgorithm,
    #[arg(long = "bits", default_value_t = 3072)]
    pub bits: usize,
    #[arg(short = 'o', long = "output", default_value = "k")]
    pub output: PathBuf,
    #[arg(long = "sub-id")]
    pub sub_id: Option<String>,
    #[arg(long = "force", default_value_t = false)]
    pub force: bool,
    /// Print encrypted OpenSSH private key + OpenSSH public key line
    #[arg(long = "openssh")]
    pub openssh: bool,
    /// Comment embedded in the SSH key line (used with --ssh)
    #[arg(long = "comment", default_value = "CryDNA", value_name = "TEXT")]
    pub comment: String,
}

#[derive(clap::Args, Debug)]
pub struct DeriveArgs {
    #[arg(long = "algo", value_enum, default_value_t = KeyAlgorithm::Ed25519)]
    pub algo: KeyAlgorithm,
    #[arg(long = "bits", default_value_t = 3072)]
    pub bits: usize,
    #[arg(long = "passphrase", value_name = "PASS")]
    pub passphrase: Option<String>,
    #[arg(short = 'n', long = "namespace", default_value = "default")]
    pub namespace: String,
    #[arg(short = 'o', long = "output", default_value = "k")]
    pub output: PathBuf,
    #[arg(long = "sub-id")]
    pub sub_id: Option<String>,
    #[arg(long = "force", default_value_t = false)]
    pub force: bool,
    /// Print encrypted OpenSSH private key + OpenSSH public key line
    #[arg(long = "openssh")]
    pub openssh: bool,
    /// Comment embedded in the SSH key line (used with --ssh)
    #[arg(long = "comment", default_value = "CryDNA", value_name = "TEXT")]
    pub comment: String,
}

pub fn keygen(args: &KeygenArgs, openssh_passphrase: Option<&[u8]>) -> Result<(), CryError> {
    let output = names(&args.output, &args.algo);
    match args.algo {
        KeyAlgorithm::Ed25519 => {
            ensure_writable(&output.0, args.force)?;
            ensure_writable(output.1.as_ref().unwrap(), args.force)?;
            if args.openssh {
                ensure_writable(&openssh_path(&output.0), args.force)?;
                ensure_writable(&openssh_pub_path(&output.0), args.force)?;
            }
            let sk = SigningKey::generate(&mut OsRng);
            let id = Identity { signing_key: sk };
            id.write_private_key_hex_file(&output.0, args.force)?;
            write_public_key(
                &output.1.unwrap(),
                &id.verifying_key().to_bytes(),
                args.force,
            )?;
            if args.openssh {
                let passphrase = openssh_passphrase
                    .ok_or_else(|| CryError::InvalidFormat("missing OpenSSH passphrase".into()))?;
                let ssh_priv_path = openssh_path(&output.0);
                write_openssh_private_key(
                    &ssh_priv_path,
                    &id,
                    passphrase,
                    &args.comment,
                    args.force,
                )?;
                let auth_line = id.ssh_authorized_keys_line(&args.comment);
                let ssh_pub_path = openssh_pub_path(&output.0);
                std::fs::write(&ssh_pub_path, format!("{auth_line}\n"))?;
                eprintln!("  algorithm: ed25519");
                eprintln!("  ssh public: {}", ssh_pub_path.display());
                eprintln!("  ssh private: {}", ssh_priv_path.display());
                eprintln!("  authorized_keys: {auth_line}");
                eprintln!("  pubkey(base64): {}", id.public_key_base64());
                eprintln!("  fingerprint: {}", id.fingerprint());
            }
        }
        KeyAlgorithm::Aes256Gcm => {
            ensure_writable(&output.0, args.force)?;
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            write_private_key(&output.0, &key, args.force)?;
        }
        KeyAlgorithm::Rsa => {
            ensure_writable(&output.0, args.force)?;
            ensure_writable(output.1.as_ref().unwrap(), args.force)?;
            let mut rng = OsRng;
            let private = RsaPrivateKey::new(&mut rng, args.bits)
                .map_err(|e| CryError::InvalidFormat(format!("RSA generation failed: {e}")))?;
            let public = RsaPublicKey::from(&private);
            std::fs::write(
                &output.0,
                private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
            )?;
            std::fs::write(
                output.1.as_ref().unwrap(),
                public.to_public_key_pem(LineEnding::LF).unwrap().as_bytes(),
            )?;
        }
    }
    Ok(())
}

pub fn derive(
    args: &DeriveArgs,
    passphrase: &Zeroizing<Vec<u8>>,
    openssh_passphrase: Option<&[u8]>,
) -> Result<(), CryError> {
    let output = names(&args.output, &args.algo);

    match args.algo {
        KeyAlgorithm::Ed25519 => {
            ensure_writable(&output.0, args.force)?;
            ensure_writable(output.1.as_ref().unwrap(), args.force)?;
            if args.openssh {
                ensure_writable(&openssh_path(&output.0), args.force)?;
                ensure_writable(&openssh_pub_path(&output.0), args.force)?;
            }
            let id = Identity::derive(passphrase, &args.namespace, 0, args.sub_id.as_deref())?;
            id.write_private_key_hex_file(&output.0, args.force)?;
            let vk: VerifyingKey = id.verifying_key();
            write_public_key(&output.1.unwrap(), &vk.to_bytes(), args.force)?;
            if args.openssh {
                let ssh_pass = openssh_passphrase
                    .ok_or_else(|| CryError::InvalidFormat("missing OpenSSH passphrase".into()))?;
                let ssh_priv_path = openssh_path(&output.0);
                write_openssh_private_key(
                    &ssh_priv_path,
                    &id,
                    ssh_pass,
                    &args.comment,
                    args.force,
                )?;
                let auth_line = id.ssh_authorized_keys_line(&args.comment);
                let ssh_pub_path = openssh_pub_path(&output.0);
                std::fs::write(&ssh_pub_path, format!("{auth_line}\n"))?;
                eprintln!("  algorithm: ed25519");
                eprintln!("  ssh public: {}", ssh_pub_path.display());
                eprintln!("  ssh private: {}", ssh_priv_path.display());
                eprintln!("  authorized_keys: {auth_line}");
                eprintln!("  pubkey(base64): {}", id.public_key_base64());
                eprintln!("  fingerprint: {}", id.fingerprint());
            }
        }
        KeyAlgorithm::Aes256Gcm => {
            ensure_writable(&output.0, args.force)?;
            let salt =
                Sha256::digest(format!("{}|{:?}|cry:derive", args.namespace, args.algo).as_bytes());
            let mut okm = [0u8; 32];
            Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(65536, 3, 1, Some(32)).unwrap(),
            )
            .hash_password_into(passphrase.as_ref(), &salt, &mut okm)
            .map_err(|e| CryError::Kdf(e.to_string()))?;
            write_private_key(&output.0, &okm, args.force)?;
        }
        KeyAlgorithm::Rsa => {
            eprintln!(
                "⚠ Deterministic RSA is risky: weak/reused passphrases can reproduce private keys."
            );
            return Err(CryError::InvalidFormat(
                "Deterministic RSA derivation is intentionally disabled".into(),
            ));
        }
    }
    Ok(())
}

fn ensure_writable(path: &Path, force: bool) -> Result<(), CryError> {
    if path.exists() && !force {
        return Err(CryError::FileExists(path.display().to_string()));
    }
    Ok(())
}

fn names(base: &Path, algo: &KeyAlgorithm) -> (PathBuf, Option<PathBuf>) {
    let priv_path = PathBuf::from(format!("{}.cry_id", base.display()));
    match algo {
        KeyAlgorithm::Aes256Gcm => (priv_path, None),
        _ => (
            priv_path,
            Some(PathBuf::from(format!("{}.cry_pub_id", base.display()))),
        ),
    }
}

fn write_private_key(path: &Path, bytes: &[u8], force: bool) -> Result<(), CryError> {
    ensure_writable(path, force)?;
    std::fs::write(path, hex::encode(bytes))?;
    Ok(())
}
fn write_public_key(path: &Path, bytes: &[u8], force: bool) -> Result<(), CryError> {
    ensure_writable(path, force)?;
    std::fs::write(path, hex::encode(bytes))?;
    Ok(())
}

fn openssh_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.openssh_id", path.display()))
}
fn openssh_pub_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.openssh_pub", path.display()))
}

fn write_openssh_private_key(
    path: &Path,
    identity: &Identity,
    passphrase: &[u8],
    comment: &str,
    force: bool,
) -> Result<(), CryError> {
    ensure_writable(path, force)?;
    let passphrase_str = std::str::from_utf8(passphrase)
        .map_err(|_| CryError::InvalidFormat("OpenSSH passphrase must be valid UTF-8".into()))?;
    let pem = identity.openssh_private_key(passphrase_str, comment)?;
    std::fs::write(path, pem)?;
    Ok(())
}
