# Developer Guide (v0.6)

## Build

```bash
cargo build
cargo build --release
```

## Primary commands to validate

```bash
cargo run -- encrypt -p ./plain.txt -c ./plain.cry
cargo run -- decrypt -c ./plain.cry -p ./recovered.txt
cargo run -- keygen --algo ed25519 -o demo
cargo run -- derive --algo ed25519 -n work -o work
cargo run -- ssh user@host -- -V
```

## Checks before PR

1. `cargo fmt`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test`
4. verify README and docs match `--help` output
5. confirm release/version references are updated to `v0.6.0`

## Conventions

- Use explicit `Result<_, CryError>` flows.
- Keep cryptographic logic auditable and comments close to critical code.
- Avoid silent overwrite behavior unless gated by `--force`.
