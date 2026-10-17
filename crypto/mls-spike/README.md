# Squadtime MLS spike

Disposable Rust integration proof for MLS group creation, Welcome joins,
authenticated encrypted events, member removal, tamper/replay rejection and
pinned device-key validation. **Not wired into the apps or backend.**

```sh
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

See [evaluation, findings and open security work](../../docs/crypto-spike.md).
In particular, failed ciphertext authentication consumes the received generation
in this configuration; retry/recovery behavior needs resolution before adoption.
No production keys or accounts are used.

Interactive relay check: `cargo build --locked --example relay_roundtrip`, then
run `target/debug/examples/relay_roundtrip`. Read its first stdout hex line, relay
the corresponding bytes, and send the fetched hex bytes on stdin. It prints
`verified` only after Bob verifies the original encrypted synthetic event.
