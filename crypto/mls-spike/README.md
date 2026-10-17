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
The raw library call consumes a generation after failed authentication. The
application receiver now stages a supported group clone and commits only an
accepted message; see [transaction boundaries and regression evidence](../../docs/mls-state-transactions.md).
Durable inbox atomicity and rollback protection remain open.
No production keys or accounts are used.

Interactive relay check: `cargo build --locked --example relay_roundtrip`, then
run `target/debug/examples/relay_roundtrip`. Read its first stdout hex line, relay
the corresponding bytes, and send the fetched hex bytes on stdin. It prints
`verified` only after Bob verifies the original encrypted synthetic event.

`src/lib.rs` contains the reusable application-only `ApplicationReceiver`.
`tests/transactions.rs` preserves authentic retry after rejection and replay
rejection across supported reloads. The raw failure test remains in
`tests/lifecycle.rs` as evidence.

The real MLS [native snapshot bridge](../../docs/native-mls-bridge.md) exports a
bounded C ABI and complete secret receiver snapshots for native encrypted
state/inbox transaction experiments. It performs no durable publication itself.
