//! zkVM benchmark mode: translate a soundcalc-style FRI-STARK submission
//! (see provers/openvm.toml) into hashing amounts, then into running times.
//!
//! Model (soundcalc math companion, fri.tex "FRI proof size" + pcs/fri.py):
//!
//! Prover-side NATIVE hashing per proof (Merkle commitments):
//!   - initial tree over D = 2^(log_trace + log_inv_rate) leaves; leaf i holds
//!     all committed column values at index i (cols = batch_size /
//!     opening_points base-field elements) -> D leaf hashes of
//!     cols*base_elem_bytes + (D-1) digest compressions
//!   - FRI fold round i (factor 2, siblings grouped): tree over D >> (i+1)
//!     leaves of two extension elements -> leaf hashes + compressions
//!   - grinding: 2^grind_batch + 2^grind_query + 2^grind_deep expected
//!     transcript hash attempts
//!
//! PROVEN hashing (verifier re-execution inside leaf/internal circuits), per
//! child proof verified:
//!   - transcript absorption of roots/challenges: ~(rounds + 16) compressions
//!   - initial tree: t leaf hashes + expected deduplicated path compressions
//!     eMP(D, t) = sum_d ceil(2^d ((1-2^-d)^t - (1-2^(1-d))^t))
//!     (fri.tex eq. for expected Merkle multi-proof size, hash count part)
//!   - fold round i: t sibling-pair leaf hashes + eMP(D >> (i+1), t)
//!
//! Aggregation topology (OpenVM continuations): num_app_segments app proofs
//! -> leaf proofs (leaf_arity children each) -> internal levels
//! (internal_arity children) until a single root proof.
//!
//! Prover speed is SAMPLED from configured ranges (seeded, deterministic) to
//! produce concrete illustrative running times; native hash atoms come from
//! this machine's calibration.

use crate::calibration::Calibration;
use crate::callcount::{perms_per_msg, HashId, ALL_HASHES};
use crate::workload::PoseidonParams;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Spec parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ZkvmSpec {
    pub zkvm: ZkvmMeta,
    pub aggregation: Aggregation,
    pub sampling: Sampling,
    #[serde(default = "default_poseidon")]
    pub poseidon: PoseidonParams,
    pub circuits: Vec<CircuitSpec>,
}

fn default_poseidon() -> PoseidonParams {
    PoseidonParams { width: 16, rate: 8, bytes_per_elem: 4 }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZkvmMeta {
    pub name: String,
    pub version: String,
    pub base_elem_bytes: u64,
    pub ext_elem_bytes: u64,
    pub digest_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Aggregation {
    pub num_app_segments: u64,
    pub leaf_arity: u64,
    pub internal_arity: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Sampling {
    pub seed: u64,
    pub samples: u32,
    pub ns_per_row_range: [f64; 2],
}

#[derive(Debug, Clone, Deserialize)]
pub struct CircuitSpec {
    pub name: String,
    pub log_trace: u32,
    pub log_inv_rate: u32,
    pub fri_fold_rounds: u32,
    pub num_queries: u64,
    pub batch_size: u64,
    pub opening_points: u64,
    pub grind_batch: u32,
    pub grind_query: u32,
    pub grind_deep: u32,
    #[serde(default)]
    #[allow(dead_code)] // topology is resolved by circuit name; kept as documentation
    pub verifies: Option<String>,
}

impl CircuitSpec {
    fn domain(&self) -> u64 {
        1u64 << (self.log_trace + self.log_inv_rate)
    }
    fn cols_per_leaf(&self) -> u64 {
        self.batch_size / self.opening_points
    }
}

impl ZkvmSpec {
    pub fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {path}: {e}"))?;
        toml::from_str(&text).map_err(|e| format!("cannot parse {path}: {e}"))
    }
    fn circuit(&self, name: &str) -> Result<&CircuitSpec, String> {
        self.circuits
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| format!("spec has no circuit named '{name}'"))
    }
}

// ---------------------------------------------------------------------------
// Hash loads: lists of (message length in bytes, expected invocation count)
// ---------------------------------------------------------------------------

type Load = Vec<(u64, f64)>;

/// Expected number of distinct sibling/internal-node hashes in a Merkle
/// multi-proof: eMP hash-count term from soundcalc's fri.tex / utils.py.
fn emp_hash_count(num_leafs: u64, t: u64) -> f64 {
    let depth = (num_leafs as f64).log2().ceil() as u32;
    let mut total = 0.0;
    for d in 1..=depth {
        let p_in = (1.0 - 2f64.powi(-(d as i32))).powi(t as i32)
            - (1.0 - 2f64.powi(1 - d as i32)).powi(t as i32);
        total += (2f64.powi(d as i32) * p_in).ceil();
    }
    total
}

/// Native Merkle-commitment + grinding hashing for producing one proof.
fn prover_native_load(c: &CircuitSpec, m: &ZkvmMeta) -> Load {
    let d = c.domain();
    let compress = 2 * m.digest_bytes;
    let mut load: Load = vec![
        (c.cols_per_leaf() * m.base_elem_bytes, d as f64), // initial leaves
        (compress, (d - 1) as f64),                        // initial tree
    ];
    for i in 0..c.fri_fold_rounds {
        let leaves = d >> (i + 1);
        if leaves == 0 {
            break;
        }
        load.push((2 * m.ext_elem_bytes, leaves as f64)); // sibling-pair leaves
        if leaves > 1 {
            load.push((compress, (leaves - 1) as f64)); // fold tree
        }
    }
    let grinding = 2f64.powi(c.grind_batch as i32)
        + 2f64.powi(c.grind_query as i32)
        + 2f64.powi(c.grind_deep as i32);
    load.push((compress, grinding));
    load
}

/// Hashing the verifier re-executes (i.e. hashing that is PROVEN) when one
/// proof of circuit `c` is verified inside an aggregation circuit.
fn verifier_load(c: &CircuitSpec, m: &ZkvmMeta) -> Load {
    let d = c.domain();
    let t = c.num_queries;
    let compress = 2 * m.digest_bytes;
    let mut load: Load = vec![
        (compress, (c.fri_fold_rounds + 16) as f64), // transcript absorption
        (c.cols_per_leaf() * m.base_elem_bytes, t as f64), // initial leaves
        (compress, emp_hash_count(d, t)),            // initial paths (dedup)
    ];
    for i in 0..c.fri_fold_rounds {
        let leaves = d >> (i + 1);
        if leaves <= 1 {
            break;
        }
        load.push((2 * m.ext_elem_bytes, t as f64));
        load.push((compress, emp_hash_count(leaves, t)));
    }
    load
}

fn load_invocations(load: &Load) -> f64 {
    load.iter().map(|&(_, n)| n).sum()
}

fn load_perms(load: &Load, hash: HashId, p: &PoseidonParams) -> f64 {
    load.iter()
        .map(|&(len, n)| n * perms_per_msg(hash, len, p) as f64)
        .sum()
}

fn load_native_ns(load: &Load, hash: HashId, cal: &Calibration, p: &PoseidonParams) -> f64 {
    let a = cal.native[&hash];
    load.iter()
        .map(|&(len, n)| n * (a.c0_ns + a.c1_ns * perms_per_msg(hash, len, p) as f64))
        .sum()
}

// ---------------------------------------------------------------------------
// Deterministic sampling (no external RNG; Date-free)
// ---------------------------------------------------------------------------

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn uniform(state: &mut u64, lo: f64, hi: f64) -> f64 {
    lo + (hi - lo) * ((splitmix64(state) >> 11) as f64 / (1u64 << 53) as f64)
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

fn fmt_ns(ns: f64) -> String {
    if ns >= 60e9 {
        format!("{:.1} min", ns / 60e9)
    } else if ns >= 1e9 {
        format!("{:.2} s", ns / 1e9)
    } else if ns >= 1e6 {
        format!("{:.2} ms", ns / 1e6)
    } else if ns >= 1e3 {
        format!("{:.2} us", ns / 1e3)
    } else {
        format!("{:.0} ns", ns)
    }
}

fn fmt_count(n: f64) -> String {
    if n >= 1e9 {
        format!("{:.2}G", n / 1e9)
    } else if n >= 1e6 {
        format!("{:.2}M", n / 1e6)
    } else if n >= 1e3 {
        format!("{:.1}k", n / 1e3)
    } else {
        format!("{:.0}", n)
    }
}

pub fn run_zkvm(spec_path: &str, cal_path: &str) -> Result<(), String> {
    let spec = ZkvmSpec::load(spec_path)?;
    let (cal, cal_loaded) = Calibration::load_or_placeholder(cal_path);
    let m = &spec.zkvm;
    let p = &spec.poseidon;

    let app = spec.circuit("app")?;
    let leaf = spec.circuit("leaf")?;
    let internal = spec.circuit("internal")?;

    println!("# {} v{} hashing benchmark (soundcalc-derived)\n", m.name, m.version);
    if !cal_loaded {
        println!("> **warning:** no calibration.json -- native atoms are placeholders.\n");
    }
    if !cal.native[&HashId::Poseidon].measured {
        println!("> **warning:** Poseidon native atom is a placeholder (no backend yet).\n");
    }
    println!(
        "> Prover per-row cost sampled uniformly from [{:.0}, {:.0}] ns/row, {} samples, seed {}.\n",
        spec.sampling.ns_per_row_range[0],
        spec.sampling.ns_per_row_range[1],
        spec.sampling.samples,
        spec.sampling.seed
    );

    // ---- hash-independent invocation counts --------------------------------
    println!("## Hash invocations (hash-independent)\n");
    println!("| circuit | D (LDE leaves) | cols/leaf | native invocations per proof | proven invocations per proof verified |");
    println!("|---|---|---|---|---|");
    for c in [app, leaf, internal] {
        let native = prover_native_load(c, m);
        let verif = verifier_load(c, m);
        println!(
            "| {} | 2^{} | {} | {} | {} |",
            c.name,
            c.log_trace + c.log_inv_rate,
            c.cols_per_leaf(),
            fmt_count(load_invocations(&native)),
            fmt_count(load_invocations(&verif)),
        );
    }

    // ---- per-hash native commit cost & proven rows -------------------------
    println!("\n## Per-hash costs\n");
    println!("Native = prover Merkle commitments + grinding, using this machine's measured atoms.");
    println!("Proven rows = verifier hashing mapped to trace rows (perms x rows/perm); utilization = proven hash rows for all children vs. the aggregation circuit's own trace budget.\n");
    println!("| hash | native/app proof | native/leaf | native/internal | rows to verify 1 app proof | leaf util. | rows to verify 1 leaf | internal util. |");
    println!("|---|---|---|---|---|---|---|---|");
    let leaf_budget = (1u64 << leaf.log_trace) as f64;
    let internal_budget = (1u64 << internal.log_trace) as f64;
    for &h in &ALL_HASHES {
        let rows_pp = cal.circuit_rows_per_perm[&h] as f64;
        let rows_app = load_perms(&verifier_load(app, m), h, p) * rows_pp;
        let rows_leaf = load_perms(&verifier_load(leaf, m), h, p) * rows_pp;
        let util_leaf = spec.aggregation.leaf_arity as f64 * rows_app / leaf_budget;
        let util_internal = spec.aggregation.internal_arity as f64 * rows_leaf / internal_budget;
        println!(
            "| {} | {} | {} | {} | {} | {:.0}% | {} | {:.0}% |",
            h.name(),
            fmt_ns(load_native_ns(&prover_native_load(app, m), h, &cal, p)),
            fmt_ns(load_native_ns(&prover_native_load(leaf, m), h, &cal, p)),
            fmt_ns(load_native_ns(&prover_native_load(internal, m), h, &cal, p)),
            fmt_count(rows_app),
            100.0 * util_leaf,
            fmt_count(rows_leaf),
            100.0 * util_internal,
        );
    }
    println!("\nUtilization > 100% means the verifier's hashing alone exceeds the circuit's submitted trace length -- that hash cannot be used with these parameters.");

    // ---- end-to-end continuation run ---------------------------------------
    let s = spec.aggregation.num_app_segments;
    let l = s.div_ceil(spec.aggregation.leaf_arity);
    println!("\n## End-to-end continuation run: {} app segments\n", s);

    // Topology: count proofs per stage and accumulate loads.
    // native_total: all Merkle commitment hashing across every proof produced.
    // proven_perms: all verifier hashing that must be proven, per hash.
    let mut stages: Vec<(String, u64, &CircuitSpec, Option<(&CircuitSpec, u64)>)> = vec![
        ("app".into(), s, app, None),
        (format!("leaf (x{} app each)", spec.aggregation.leaf_arity), l, leaf, Some((app, spec.aggregation.leaf_arity))),
    ];
    let mut n = l;
    let mut child = leaf;
    let mut level = 1;
    while n > 1 {
        let parents = n.div_ceil(spec.aggregation.internal_arity);
        // Children verified across this whole level = n (spread over parents).
        stages.push((format!("internal L{} ({} children)", level, n), parents, internal, Some((child, n.div_ceil(parents)))));
        n = parents;
        child = internal;
        level += 1;
    }

    println!("| stage | proofs | verifies per proof |");
    println!("|---|---|---|");
    for (name, count, _, verifies) in &stages {
        println!(
            "| {} | {} | {} |",
            name,
            count,
            verifies.map_or("-".into(), |(c, k)| format!("~{k} x {}", c.name)),
        );
    }

    println!("\n| hash | native hashing (all proofs) | proven-hash rows | proving time of hash rows (median [min..max] over samples) | total (median) |");
    println!("|---|---|---|---|---|");
    let mut summary: Vec<(HashId, f64)> = Vec::new();
    for &h in &ALL_HASHES {
        let rows_pp = cal.circuit_rows_per_perm[&h] as f64;
        let mut native_ns = 0.0;
        let mut proven_rows = 0.0;
        for (_, count, circ, verifies) in &stages {
            native_ns += *count as f64 * load_native_ns(&prover_native_load(circ, m), h, &cal, p);
            if let Some((child_circ, k)) = verifies {
                proven_rows += (*count * k) as f64 * load_perms(&verifier_load(child_circ, m), h, p) * rows_pp;
            }
        }
        let mut state = spec.sampling.seed;
        let mut times: Vec<f64> = (0..spec.sampling.samples)
            .map(|_| {
                let ns_per_row = uniform(
                    &mut state,
                    spec.sampling.ns_per_row_range[0],
                    spec.sampling.ns_per_row_range[1],
                );
                proven_rows * ns_per_row
            })
            .collect();
        times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = times[times.len() / 2];
        let total = native_ns + median;
        summary.push((h, total));
        println!(
            "| {} | {} | {} | {} [{} .. {}] | {} |",
            h.name(),
            fmt_ns(native_ns),
            fmt_count(proven_rows),
            fmt_ns(median),
            fmt_ns(times[0]),
            fmt_ns(times[times.len() - 1]),
            fmt_ns(total),
        );
    }
    summary.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    println!("\n**Winner (end-to-end hashing cost): {}**", summary[0].0.name());
    println!("\nCaveats: `batch_size` is a soundness bound, not committed width -- native hashing is inflated ~100-200x and proven hashing ~10-40x, though the hash RANKING is robust to this (see the CAVEATS block in the zkvm spec TOML for the full analysis). Leaf/internal arities are SDK assumptions; guest-program hashing inside the app circuit is out of scope.");
    Ok(())
}
