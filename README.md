# cry 🔐 v0.6.0

A fast, minimal CLI cryptography tool written in Rust.

`cry` now combines:
- authenticated file encryption/decryption,
- deterministic key derivation from passphrases,
- secure random key generation,
- and ephemeral SSH key usage with no-disk private key flow.

---

## Project description

`cry` is designed for security-focused CLI workflows where reproducibility and low key exposure matter:

- **Deterministic key derivation**: derive the same key material from the same passphrase + context tuple (namespace, key version, sub-id).
- **Ephemeral SSH keys**: `cry ssh` derives an Ed25519 identity, injects it into a short-lived SSH auth path, and uses it for the session.
- **No-disk key usage**: private key material for SSH sessions is handled in memory and lifecycle-managed to minimize persistence risk.

---

## What's new in v0.6

| # | Change |
|---|--------|
| 1 | Added `cry ssh` with ephemeral in-memory SSH keys |
| 2 | Introduced `keygen` for secure random key generation |
| 3 | Introduced `derive` for deterministic keys from passphrases |
| 4 | Removed legacy `identity` command |
| 5 | Standardized key file extensions (`.cry_id`, `.cry_pub_id`) |
| 6 | Improved cross-platform SSH support (Linux + Windows) |

---

## Documentation

- [Deterministic identity, derive, and SSH guide](docs/identity-and-ssh.md)
- [Architecture & security deep dive](docs/architecture-and-security.md)
- [Developer guide](docs/developer-guide.md)

---

## Build

```sh
cargo build --release
```

---

## Usage examples

### Encrypt / decrypt files

```sh
cry encrypt -p secret.txt -c secret.cry
cry decrypt -c secret.cry -p recovered.txt
```

### SSH usage (ephemeral derived key)

```sh
# Basic
cry ssh user@host

# Namespace isolation
cry ssh user@host -n work

# Key rotation context
cry ssh user@host -n work --key-version 2

# Non-interactive passphrase file
cry ssh user@host --pass-file /run/secrets/cry_pass

# Forward native ssh flags
cry ssh user@host -- -v -L 8080:localhost:8080
```

### keygen examples (secure random keys)

```sh
# Random Ed25519 keypair -> k.cry_id + k.cry_pub_id
cry keygen --algo ed25519 -o k

# Random AES-256 key -> aes.cry_id
cry keygen --algo aes256gcm -o aes

# Random RSA keypair
cry keygen --algo rsa --bits 4096 -o server
```

### derive examples (deterministic keys)

```sh
# Deterministic Ed25519 from prompted passphrase
cry derive --algo ed25519 -n work -o work

# Deterministic AES key from explicit passphrase
cry derive --algo aes256gcm --passphrase 'correct horse battery staple' -n backup -o backup

# Namespace + sub-id scoping
cry derive --algo ed25519 -n prod --sub-id deploy -o deploy
```

---

## Security notes

### Deterministic vs random keys

- Use **`derive`** when you need reproducibility across systems without copying private keys.
- Use **`keygen`** when you want fresh independent random keys each time.
- Deterministic keys are only as strong as passphrase entropy and context hygiene.

### Passphrase strength is critical

For deterministic derivation, weak passphrases reduce effective security regardless of algorithm choice. Prefer long, unique, high-entropy passphrases and avoid reuse across environments.

### In-memory key advantages

For SSH sessions, `cry` minimizes key persistence by using ephemeral key handling and short-lived auth context instead of long-term private key files. This reduces accidental leakage through backups, sync tools, or filesystem artifacts.

---

## Command aliases

```sh
cry encrypt / en / -en
cry decrypt / de / -de
cry keygen
cry derive
cry sign
cry verify
cry ssh
```

---

## File format (encrypted payloads)

```
┌──────────────────────────────────────────────────────────────┐
│ Header  73 bytes                                             │
│   Magic        4 bytes  "CRY\x02"                            │
│   AlgoID       1 byte   0x01=AES-256-GCM                     │
│                         0x02=ChaCha20-Poly1305               │
│   Salt        16 bytes  Argon2 salt (random per file)        │
│   Nonce       12 bytes  AEAD base nonce (random per file)    │
│   ChunkCount   8 bytes  u64 big-endian (0 for empty files)   │
│   HeaderHMAC  32 bytes  HMAC-SHA256(header fields, sub-key)  │
├──────────────────────────────────────────────────────────────┤
│ Chunks  (repeated ChunkCount times)                          │
│   Length       4 bytes  u32 big-endian                       │
│   Data         N bytes  AEAD ciphertext + 16-byte tag        │
└──────────────────────────────────────────────────────────────┘
```
