# hash-bench

Hybrid ("Strategy C") benchmark for choosing a hash function — SHA-256,
SHA3-256, BLAKE3, Poseidon (v1) — by **expected cost over a
probability-weighted use-case set**, measured in two dimensions: native
execution and proving cost inside a SNARK/STARK prover. The prover backend
is a parameter: any system whose circuits are largely repetitive (fixed
rows per permutation, trace padded to a power of two) fits the model —
examples include Flock and the FRI-STARK zkVMs submitted to
[ethereum/soundcalc](https://github.com/ethereum/soundcalc) (OpenVM ships
as a sample workload in `workloads/openvm.toml`).

## Model

Instead of end-to-end benchmarking every (hash, use case) pair, we measure
**atoms** and derive use-case costs analytically:

- **Call counts** (`src/callcount.rs`) — permutation/compression invocations
  per message, from each hash's padding/mode rules. Pure math, unit-tested.
- **Native atoms** (`calibration.json`, fitted by `measure`) — per hash:
  `time_ns(msg) = c0 + c1 · perms(msg)` (c0 = per-call overhead, c1 =
  cost per permutation), least-squares fitted from real implementations
  at several message lengths.
- **Circuit atoms** — trace rows per permutation, plus a two-constant prover
  model `prove_ns = setup_ns + ns_per_row · padded_height`. For a
  repetitive circuit, a use case's trace height is
  `num_calls · perms · rows_per_perm`, padded to the next power of two —
  which is why **`num_calls` is a first-class use-case parameter**
  (typical values: 1, 8, 64, 1024, 2^15). Per-call prover cost falls in
  power-of-two steps as repetition fills the padded trace; the report
  includes a sweep table over exactly these values.

Expected cost per hash: `C(H) = Σᵢ pᵢ · costₕ(use caseᵢ)`, computed
separately for native and prover dimensions. Since both are wall-clock
time, the combined score is simply their sum — one occurrence of a use
case pays its native cost (witness generation hashes natively anyway)
and its proving cost once. If some hashing runs natively far more often
than it is proven, encode that as a separate `role = "native"` use case
with its own probability: frequency asymmetries live in the workload,
not in a global exchange-rate knob.

## Usage

```bash
cargo run --release -- measure     # fit native atoms on this machine -> calibration.json
cargo run --release -- report      # use-case workload -> markdown report + results.json
cargo run --release -- report --workload workloads/openvm.toml   # OpenVM sample workload
```

Flags: `--workload workloads/default.toml`, `--calibration calibration.json`,
`--out results.json`.

`report` dispatches on the workload file's contents: a file with a
top-level `[zkvm]` section is treated as a zkVM spec, anything else as a
probability-weighted use-case set.

## zkVM workloads

`workloads/openvm.toml` encodes the OpenVM v1.5.0 parameters submitted to
[ethereum/soundcalc](https://github.com/ethereum/soundcalc) and the model in
its math companion (fri.tex "FRI proof size", `pcs/fri.py`,
`common/utils.py`): per proof, the prover natively hashes one Merkle tree
over the LDE domain `D = trace_length/ρ` (leaf = all committed columns at
that index) plus one sibling-pair tree per FRI fold round plus grinding;
per proof *verified* inside an aggregation circuit (leaf verifies app,
internal verifies leaf/internal per the continuations topology), the
verifier's hashing — t query openings with expected Merkle multi-proof
deduplication (the eMP formula) plus transcript absorption — must be
*proven*, and is mapped to trace rows via rows/perm. Prover per-row speed
is sampled deterministically (seeded) from a configured range to produce
concrete illustrative times. To benchmark a different zkVM, add a sibling
workload TOML with its soundcalc parameters and pass it via `--workload`.

## Workflow / what is real vs. placeholder

1. **Edit `workloads/default.toml`** — the current use cases are placeholders;
   put in your real lengths, probabilities, `num_calls`, and roles
   (`native` / `circuit` / `both`).
2. **Run `measure`** on each target hardware profile (with/without SHA-NI
   makes a large difference for SHA-256) — this makes the native side real.
3. **Calibrate the circuit side against your prover**: the
   `circuit_rows_per_perm` values and the prover constants (`setup_ns`,
   `ns_per_row`, `min_height`) in `calibration.json` are placeholders with
   literature-prior ratios. Replace them with numbers from real traces of
   your target prover (a few end-to-end runs suffice to fit two constants),
   then set `"measured": true` and name the backend in `prover.name`.
4. **Read the sensitivity section** of the report: it perturbs every use-case
   probability ×0.5/×2 and reports whether the winner flips — if it does, the
   benchmark's real output is which probability you must pin down.

## TODO

- [ ] Poseidon (v1) native backend (blocked on the target prover's field
      choice; then wire e.g. the `zkhash` crate or a hand-rolled permutation
      and delete the placeholder atom).
- [ ] Poseidon `bytes_per_elem`/rate in `[poseidon]` must match the target
      prover's field and chosen instance (width, rate, R_F/R_P round numbers).
- [ ] Prover adapters: extract rows/perm and (setup, per-row) constants from
      real traces of each backend of interest; validate the analytic model
      within ~10% on 2–3 end-to-end runs.
- [ ] Optional second hardware profile (ARM / no-SHA-NI x86 / WASM).
- [ ] BLAKE3's linear (c0, c1) fit is poor: SIMD batching makes long-message
      per-permutation cost ~5x cheaper than single-block calls, so the fit
      overestimates short-message native cost (~3x at 32 B). Replace the
      linear atom with a per-length measured table + interpolation, or fit
      separate short/long regimes.
