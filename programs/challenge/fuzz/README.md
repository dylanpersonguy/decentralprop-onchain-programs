# Settlement / Merkle coverage-guided fuzzing (cargo-fuzz / libFuzzer)

Coverage-guided fuzzing of the security-critical settlement engine + Merkle + fault verifiers in
[`../src/settlement.rs`](../src/settlement.rs). Complements the `cargo test`-native randomized harness
(`settlement.rs::mod fuzz`, 5 invariants × ~17k seeds) with **coverage-guided** exploration (libFuzzer
mutates toward new code paths instead of pure random).

Both share the SAME logic via `settlement::fuzz_support` (the Merkle builder + the `check_no_false_slash`
invariant), gated behind the `fuzzing` feature so it is never compiled into the deployed program.

## What it checks

`fuzz_targets/settlement_soundness.rs` drives `check_no_false_slash(rules, steps)`: it builds an **honest**
transcript from the arbitrary input, commits the real Merkle trees, and asserts that **no** fault verifier
(transition / input / provenance) flags it. Any fault on an honest transcript is a permissionless
**false-slash** of an honest operator — the worst class of bug here. The engine's **no-panic** property is
exercised implicitly (the honest run calls `apply_step` on the fuzzed steps), so an integer-overflow panic
(the class the cargo-test harness already caught + fixed) is also a fuzzer-reportable crash.

## Run

```sh
# from onchain/programs/challenge/
ASAN_OPTIONS=detect_leaks=0 cargo +nightly fuzz run settlement_soundness -- -max_total_time=120 -max_len=4096
```

- Use the **default sanitizer** (ASan). `--sanitizer none` fails to link on macOS arm64 (cargo-fuzz still
  emits sancov coverage instrumentation but doesn't link a runtime that provides the `__sanitizer_cov_trace_*`
  symbols); ASan's runtime provides them. `ASAN_OPTIONS=detect_leaks=0` silences anchor/solana-program noise.
- A crash saves the minimal input to `artifacts/settlement_soundness/`; re-run that file to reproduce.
- First run: clean across **99,229 execs** (no crash / panic / soundness violation).

## CI

Run a time-boxed pass on changes to `settlement.rs` (e.g. `-max_total_time=300`), committing/restoring the
`corpus/` to carry coverage forward. Standalone workspace — the onchain SBF build never touches it.

## Next

- A `settlement_completeness` target (fraud is ALWAYS caught) to complement no-false-slash.
- Longer scheduled runs (hours) + a persisted corpus.
