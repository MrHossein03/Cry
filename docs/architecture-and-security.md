# cry Architecture & Security Deep Dive (v0.6)

## High-level module map

- `src/main.rs` — CLI surface (`encrypt`, `decrypt`, `keygen`, `derive`, `sign`, `verify`, `bench`, `ssh`) and passphrase input.
- `src/cipher.rs` — streaming file encryption/decryption and authenticated chunk framing.
- `src/header.rs` — `.cry` header format and algorithm enum.
- `src/kdf.rs` — Argon2id key derivation and sub-key derivation.
- `src/keygen.rs` — random key generation + deterministic derive workflow outputs.
- `src/crydna.rs` — deterministic Ed25519 identity and signing/verification.
- `src/ssh.rs` — ephemeral SSH key flow and platform-specific execution.
- `src/error.rs` — typed error model.

## v0.6 security focus

- deterministic key workflows via `derive`
- random key workflows via `keygen`
- ephemeral SSH private key handling in `ssh`
- standardized key filename extensions: `.cry_id`, `.cry_pub_id`

## Operational security notes

- Deterministic keys depend on passphrase strength and context consistency.
- Random keys are preferred when reproducibility is not required.
- Private key material is zeroized where possible and should not be logged.
- SSH flow is designed to minimize disk persistence and avoid stale key artifacts.
