# cry v0.6: Derive, Keygen, and SSH Guide

This guide explains deterministic derivation, random key generation, and ephemeral SSH authentication in `cry` v0.6.

## 1) Deterministic derivation model (`cry derive`)

Deterministic derivation depends on this tuple:

1. passphrase
2. namespace (`--namespace`)
3. key version (used in SSH/signing flows)
4. sub-identity (`--sub-id`, optional)

Same tuple => same key. Any change => different key.

## 2) Random key generation (`cry keygen`)

`cry keygen` generates fresh random keys each run:

- `ed25519` => `<base>.cry_id` + `<base>.cry_pub_id`
- `rsa` => `<base>.cry_id` + `<base>.cry_pub_id`
- `aes256gcm` => `<base>.cry_id`

Use `--force` to overwrite.

## 3) SSH with ephemeral keys (`cry ssh`)

`cry ssh` derives an Ed25519 key from your passphrase context and uses it for SSH without long-term key file management.

Examples:

```bash
cry ssh user@host
cry ssh user@host -n work --key-version 2
cry ssh user@host --pass-file /run/secrets/cry_pass
cry ssh user@host -- -v -L 8080:localhost:8080
```

## 4) Security reminders

- Deterministic derivation is reproducible, not magically stronger than passphrase quality.
- Random keys avoid passphrase-derived reproducibility risks.
- Prefer high-entropy passphrases and environment-specific namespaces.
- Ephemeral SSH auth reduces disk persistence of private key material.
