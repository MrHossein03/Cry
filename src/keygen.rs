use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

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
    #[arg(long = "passphrase", default_value_t = false)]
    pub passphrase: bool,
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

pub fn keygen(args: &KeygenArgs) -> Result<(), CryError> {
    let output = names(&args.output, &args.algo);
    match args.algo {
        KeyAlgorithm::Ed25519 => {
            ensure_writable(&output.0, args.force)?;
            ensure_writable(output.1.as_ref().unwrap(), args.force)?;
            let sk = SigningKey::generate(&mut OsRng);
            write_private_key(&output.0, &sk.to_bytes(), args.force)?;
            write_public_key(
                &output.1.unwrap(),
                &sk.verifying_key().to_bytes(),
                args.force,
            )?;
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

pub fn derive(args: &DeriveArgs, passphrase: &Zeroizing<Vec<u8>>) -> Result<(), CryError> {
    let output = names(&args.output, &args.algo);
    let mut salt_input = format!("{}|{:?}|cry:derive", args.namespace, args.algo).into_bytes();
    if let Some(sub) = &args.sub_id {
        salt_input.extend_from_slice(sub.as_bytes());
    }
    let salt = Sha256::digest(&salt_input);

    let mut okm = [0u8; 64];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 1, Some(64)).unwrap(),
    )
    .hash_password_into(passphrase.as_ref(), &salt, &mut okm)
    .map_err(|e| CryError::Kdf(e.to_string()))?;

    match args.algo {
        KeyAlgorithm::Ed25519 => {
            ensure_writable(&output.0, args.force)?;
            ensure_writable(output.1.as_ref().unwrap(), args.force)?;
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&okm[..32]);
            let sk = SigningKey::from_bytes(&seed);
            write_private_key(&output.0, &sk.to_bytes(), args.force)?;
            let vk: VerifyingKey = sk.verifying_key();
            write_public_key(&output.1.unwrap(), &vk.to_bytes(), args.force)?;
        }
        KeyAlgorithm::Aes256Gcm => {
            ensure_writable(&output.0, args.force)?;
            write_private_key(&output.0, &okm[..32], args.force)?;
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
