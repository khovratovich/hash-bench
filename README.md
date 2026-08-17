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

# also fit Poseidon from the reference implementation (heavier build, see below)
cargo run --release --features poseidon-native -- measure
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

`measure` fills SHA-256, SHA3-256 and BLAKE3 from their production crates,
and Poseidon too when built with `--features poseidon-native` (below).
Re-run it on every hardware profile you care about — SHA-NI vs. no SHA-NI
changes SHA-256 by an order of magnitude.

To fill an atom by hand instead, time `N` calls at two message lengths
`L1` (1 permutation) and `L2` (k permutations), then
`c1 = (t(L2) − t(L1)) / (k − 1)` and `c0 = t(L1) − c1`. Set `source` on any
atom you fill by hand or take from the literature — `report` prints it, so
a cited value is never mistaken for a bare guess, and a *measured* value
that carries a caveat keeps the caveat attached.

`measure` reports the **minimum** of 15 timed batches, not the median:
interference (background load, preemption, frequency dips) only ever adds
time, so the fastest batch is the best estimate of uncontended cost. It
also prints a `spread` factor per length — near 1.0 means a quiet machine,
and anything above 2 triggers a "re-run when idle" warning. This matters:
on a loaded machine the median put SHA-256 anywhere between 98 and
350 ns/perm across runs, while the minimum reproduced its quiet-machine
value (~78–80 ns/perm) every time.

#### Poseidon: measuring it, and the maturity caveat

`--features poseidon-native` wires the Poseidon2 paper's own reference code
([HorizenLabs/poseidon2](https://github.com/HorizenLabs/poseidon2), crate
`zkhash`) at `POSEIDON_BABYBEAR_16_PARAMS` — width 16, α=7, R_F=8, R_P=13,
via its optimized `permutation()` — so `measure` fits the atom instead of
inheriting a literature value:

```bash
cargo run --release --features poseidon-native -- measure
```

It is optional because it pulls a large dependency tree (halo2/pasta/jubjub,
for the crate's other primitives) that slows every build. Three data points,
which now agree:

| route | value | source |
|---|---|---|
| **measured here** (reference impl) | 8.5–8.7 µs/perm | this machine, `--features poseidon-native`, min-of-batches |
| same code, published | 7.06 µs/perm on a 2015 i7-6700K | [Poseidon2 paper](https://eprint.iacr.org/2023/323.pdf) Table 2 (BabyBear t=16: Poseidon 7.06, Poseidon2 2.09 µs; t=24: 15.01 vs 3.53), optimized partial-round representation |
| production impl, derived | ~3.4 µs/perm | Plonky3 Poseidon2 BabyBear width 16 = 1.0 µs (AVX-2, i9 Raptor Lake) × the paper's 3.38× Poseidon/Poseidon2 ratio — [Small Fields in Plonky3](https://hackmd.io/@Syxton/small_fields_in_plonky3) |

**The caveat that matters for a fair comparison:** the reference
implementation uses ark-ff's *generic* Montgomery backend (64-bit limbs) for
a 31-bit field, while the other three candidates are production crates with
SHA-NI/SIMD. Comparing them head-to-head measures engineering effort as much
as primitive cost — the implementation-maturity bias. A specialized Poseidon
(Plonky3-style BabyBear + AVX-2) is ~2.5× faster than what `measure` reports
here. To compare production-quality implementations of all four hashes, set
Poseidon's `c1_ns = 3400` by hand; the shipped placeholder in
`calibration.rs` uses that figure for exactly this reason. Either choice
leaves the ranking intact — Poseidon loses the native dimension by 2–3
orders of magnitude regardless — but the absolute gap changes by 2.5×.

Beware that widely-quoted "N million Poseidon2 hashes/second" figures are
usually *proving* throughput, not native permutation speed — e.g. the same
Plonky3 note proves 2^19 Poseidon2 permutations in 480 ms (~1.1M/s proven),
a different quantity from the 1 µs native permutation above.

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

- [x] Poseidon (v1) native backend — `--features poseidon-native` wires the
      `zkhash` BabyBear t=16 reference implementation; `measure` fits it at
      8.5–8.7 µs/perm here.
- [ ] A *production-quality* Poseidon backend (specialized BabyBear field +
      AVX-2, Plonky3-style) so the measured atom is free of the
      implementation-maturity bias and the hand-set `c1_ns = 3400` can go.
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
