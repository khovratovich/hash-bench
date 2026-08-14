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

A zkVM spec is **expanded into an ordinary use-case workload** at report
time: its message lengths, call counts, and probabilities are derived from
the zkVM's architecture, then scored by the exact same pipeline as a
hand-written workload. `workloads/openvm.toml` encodes the OpenVM v1.5.0
parameters submitted to
[ethereum/soundcalc](https://github.com/ethereum/soundcalc); following the
model in its math companion (fri.tex "FRI proof size", `pcs/fri.py`,
`common/utils.py`), each circuit (app/leaf/internal) yields:

- **native use cases** — the prover's Merkle commitment hashing: one tree
  over the LDE domain `D = trace_length/ρ` (leaf = all committed columns
  at that index), one sibling-pair tree per FRI fold round, plus grinding;
- **circuit (proven) use cases** — the verifier hashing re-executed inside
  the aggregation circuits: t query openings with expected Merkle
  multi-proof deduplication (the eMP formula) plus transcript absorption;

weighted by how often each proof is produced/verified in one continuation
run (leaf verifies app; internal levels verify leaf/internal at the
configured arity until a single root). Prover speed comes from
`calibration.json`, same as for any workload. To benchmark a different
zkVM, add a sibling workload TOML with its soundcalc parameters and pass
it via `--workload`.

## Filling calibration.json

`calibration.json` is the one JSON the report **reads** (all atom costs live
there); `results.json` is **written** by the report. If `calibration.json`
is absent or unparseable, built-in placeholders are used and the report
prints a warning. Start from the tracked example:

```bash
cp calibration.example.json calibration.json
```

All times are **nanoseconds**. All four hash keys — exactly `"sha256"`,
`"sha3-256"`, `"blake3"`, `"poseidon"` — are **required** in both `native`
and `circuit_rows_per_perm` (a missing key aborts the report).

### `native` — per-hash native cost model

`time_ns(msg) = c0_ns + c1_ns · perms(msg)`, where `perms(msg)` is the
call-count model in `src/callcount.rs`.

| field | meaning | how to obtain |
|---|---|---|
| `c0_ns` | fixed per-call overhead (setup, padding, finalization) | `cargo run --release -- measure` fits it (least squares over 5 message lengths) |
| `c1_ns` | marginal cost of one permutation / compression call | same `measure` run |
| `measured` | `true` once fitted on the target machine; `false` = placeholder (report warns) | set by `measure` automatically |

`measure` fills SHA-256, SHA3-256, BLAKE3. Poseidon has no backend yet, so
fill it by hand: time `N` calls of your implementation at two message
lengths `L1` (1 permutation) and `L2` (k permutations), then
`c1 = (t(L2) − t(L1)) / (k − 1)` and `c0 = t(L1) − c1`. Re-run `measure`
on every hardware profile you care about — SHA-NI vs. no SHA-NI changes
SHA-256 by an order of magnitude.

### `circuit_rows_per_perm` — per-hash in-circuit footprint

Integer: how many trace rows one permutation of that hash occupies in your
prover's arithmetization. Obtain from the AIR definition (a wide
one-row-per-permutation Poseidon AIR is 1–2; bitwise hashes are 10²–10³),
or empirically: build a test circuit with `n` permutations and divide its
trace height by `n`. The shipped values are literature-prior *ratios*, not
measurements — replace them.

### `prover` — the prover backend (a parameter, key `"flock"` also accepted)

`prove_ns = setup_ns + ns_per_row · padded_height`, where `padded_height`
is the use case's hash rows rounded up to a power of two, floored at
`min_height`.

| field | meaning | how to obtain |
|---|---|---|
| `name` | backend label shown in warnings (`"flock"`, `"openvm"`, ...) | free text |
| `setup_ns` | fixed per-proof overhead (commit setup, transcript init) | intercept of a linear fit (below) |
| `ns_per_row` | marginal proving cost per padded trace row | slope of the same fit |
| `min_height` | smallest trace height the prover pads to (power of two) | from the prover's config |
| `measured` | `true` once fitted against real runs | set by hand |

Fit procedure: run 2–3 end-to-end proofs at well-separated trace heights
(e.g. 2^12, 2^16, 2^20), record wall time, linear-fit time against padded
height. Validate on a held-out height: the model should land within ~10%,
otherwise the linear-in-rows assumption is off for your prover (FFT
n·log n terms, column count) and needs a refinement.

### `results.json` (output, for downstream tooling)

Written by `report`: the normalized workload (`workload.usecases`), the
calibration used (`calibration`), every (use case × hash) cost row
(`per_usecase`: perms, native_ns, trace rows, padded height, prove_ns),
and the final ranking (`scores`: expected native / prove / combined ns).

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
