//! zkVM workload expansion: translate a soundcalc-style FRI-STARK submission
//! (a workload TOML with a [zkvm] section, e.g. workloads/openvm.toml) into
//! an ORDINARY use-case workload — message lengths, call counts, and weights
//! derived from the zkVM's architecture — which then flows through the same
//! report pipeline as any hand-written workload.
//!
//! Derivation (soundcalc math companion, fri.tex "FRI proof size" + pcs/fri.py):
//!
//! NATIVE use cases (Merkle commitments + grinding), per proof of circuit c
//! with LDE domain D = 2^(log_trace + log_inv_rate):
//!   c:commit-leaves   msg = cols_per_leaf * base_elem_bytes, calls = D
//!   c:commit-tree     msg = 2*digest,  calls = D - 1
//!   c:fold-leaves     msg = 2*ext,     calls = sum_i D >> (i+1)
//!   c:fold-trees      msg = 2*digest,  calls = sum_i (D >> (i+1)) - 1
//!   c:grinding        msg = 2*digest,  calls = 2^gb + 2^gq + 2^gd
//!
//! CIRCUIT (proven) use cases: hashing the verifier re-executes when one
//! proof of circuit c is verified inside an aggregation circuit:
//!   verify-c:transcript   msg = 2*digest, calls = rounds + 16
//!   verify-c:leaves       msg = cols_per_leaf * base, calls = t
//!   verify-c:init-paths   msg = 2*digest, calls = eMP(D, t)
//!   verify-c:fold-leaves  msg = 2*ext,    calls = t per fold round
//!   verify-c:fold-paths   msg = 2*digest, calls = sum_i eMP(D >> (i+1), t)
//! where eMP(n, t) = sum_d ceil(2^d ((1-2^-d)^t - (1-2^(1-d))^t)) is the
//! expected deduplicated Merkle multi-proof hash count.
//!
//! WEIGHTS (probabilities) come from the continuation topology: native use
//! cases are weighted by how many proofs of that circuit one full run
//! produces; proven use cases by how many times a proof of that circuit is
//! verified inside a parent (leaf verifies app; internal levels verify
//! leaf/internal, arity children each, until a single root).

use crate::calibration::Calibration;
use crate::report;
use crate::workload::{ModelParams, PoseidonParams, Role, UseCase, Workload};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Spec parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ZkvmSpec {
    pub zkvm: ZkvmMeta,
    pub aggregation: Aggregation,
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
// Expansion into use cases
// ---------------------------------------------------------------------------

/// Expected number of distinct sibling/internal-node hashes in a Merkle
/// multi-proof: eMP hash-count term from soundcalc's fri.tex / utils.py.
fn emp_hash_count(num_leafs: u64, t: u64) -> u64 {
    let depth = (num_leafs as f64).log2().ceil() as u32;
    let mut total = 0.0;
    for d in 1..=depth {
        let p_in = (1.0 - 2f64.powi(-(d as i32))).powi(t as i32)
            - (1.0 - 2f64.powi(1 - d as i32)).powi(t as i32);
        total += (2f64.powi(d as i32) * p_in).ceil();
    }
    total as u64
}

fn usecase(name: String, weight: f64, msg_len: u64, num_calls: u64, role: Role) -> UseCase {
    UseCase { name, prob: weight, msg_len, num_calls, role }
}

/// Native (prover-side) use cases for producing one proof of circuit `c`,
/// each weighted by `w` = number of such proofs in one continuation run.
fn native_usecases(c: &CircuitSpec, m: &ZkvmMeta, w: f64) -> Vec<UseCase> {
    let d = c.domain();
    let compress = 2 * m.digest_bytes;
    let leaf_msg = c.cols_per_leaf() * m.base_elem_bytes;
    let (mut fold_leaves, mut fold_tree) = (0u64, 0u64);
    for i in 0..c.fri_fold_rounds {
        let leaves = d >> (i + 1);
        if leaves == 0 {
            break;
        }
        fold_leaves += leaves;
        fold_tree += leaves.saturating_sub(1);
    }
    let grinding = (1u64 << c.grind_batch) + (1u64 << c.grind_query) + (1u64 << c.grind_deep);
    vec![
        usecase(format!("{}:commit-leaves", c.name), w, leaf_msg, d, Role::Native),
        usecase(format!("{}:commit-tree", c.name), w, compress, d - 1, Role::Native),
        usecase(format!("{}:fold-leaves", c.name), w, 2 * m.ext_elem_bytes, fold_leaves, Role::Native),
        usecase(format!("{}:fold-trees", c.name), w, compress, fold_tree, Role::Native),
        usecase(format!("{}:grinding", c.name), w, compress, grinding, Role::Native),
    ]
}

/// Proven use cases: hashing the verifier re-executes when one proof of
/// circuit `c` is verified inside an aggregation circuit; `w` = number of
/// such verifications in one continuation run.
fn verify_usecases(c: &CircuitSpec, m: &ZkvmMeta, w: f64) -> Vec<UseCase> {
    let d = c.domain();
    let t = c.num_queries;
    let compress = 2 * m.digest_bytes;
    let (mut fold_leaves, mut fold_paths) = (0u64, 0u64);
    for i in 0..c.fri_fold_rounds {
        let leaves = d >> (i + 1);
        if leaves <= 1 {
            break;
        }
        fold_leaves += t;
        fold_paths += emp_hash_count(leaves, t);
    }
    vec![
        usecase(format!("verify-{}:transcript", c.name), w, compress, (c.fri_fold_rounds + 16) as u64, Role::Circuit),
        usecase(format!("verify-{}:leaves", c.name), w, c.cols_per_leaf() * m.base_elem_bytes, t, Role::Circuit),
        usecase(format!("verify-{}:init-paths", c.name), w, compress, emp_hash_count(d, t), Role::Circuit),
        usecase(format!("verify-{}:fold-leaves", c.name), w, 2 * m.ext_elem_bytes, fold_leaves, Role::Circuit),
        usecase(format!("verify-{}:fold-paths", c.name), w, compress, fold_paths, Role::Circuit),
    ]
}

/// Expand a zkVM spec into a standard use-case workload. Weights follow the
/// continuation topology for `num_app_segments` and are left unnormalized
/// (Workload semantics renormalize).
pub fn expand(spec: &ZkvmSpec) -> Result<Workload, String> {
    let app = spec.circuit("app")?;
    let leaf = spec.circuit("leaf")?;
    let internal = spec.circuit("internal")?;
    let agg = &spec.aggregation;

    // Topology: proofs produced and child-verifications performed per run.
    let s = agg.num_app_segments;
    let l = s.div_ceil(agg.leaf_arity);
    let mut internal_proofs = 0u64;
    let mut leaf_verified = 0u64; // leaf proofs verified by internal L1
    let mut internal_verified = 0u64; // internal proofs verified by L2+
    let mut n = l;
    let mut first_level = true;
    while n > 1 {
        let parents = n.div_ceil(agg.internal_arity);
        internal_proofs += parents;
        if first_level {
            leaf_verified += n;
            first_level = false;
        } else {
            internal_verified += n;
        }
        n = parents;
    }

    let mut usecases = Vec::new();
    usecases.extend(native_usecases(app, &spec.zkvm, s as f64));
    usecases.extend(native_usecases(leaf, &spec.zkvm, l as f64));
    usecases.extend(verify_usecases(app, &spec.zkvm, s as f64)); // each app proof verified once, in a leaf
    if internal_proofs > 0 {
        usecases.extend(native_usecases(internal, &spec.zkvm, internal_proofs as f64));
        usecases.extend(verify_usecases(leaf, &spec.zkvm, leaf_verified as f64));
        if internal_verified > 0 {
            usecases.extend(verify_usecases(internal, &spec.zkvm, internal_verified as f64));
        }
    }

    // Normalize weights into probabilities.
    let total: f64 = usecases.iter().map(|u| u.prob).sum();
    for u in &mut usecases {
        u.prob /= total;
    }

    Ok(Workload {
        model: ModelParams { sweep_num_calls: vec![1, 8, 64, 1024, 32768] },
        poseidon: spec.poseidon.clone(),
        usecases,
    })
}

// ---------------------------------------------------------------------------
// Entry point: expand, show the derived workload, run the standard report
// ---------------------------------------------------------------------------

pub fn run_zkvm(spec_path: &str, cal_path: &str, out_json: &str) -> Result<(), String> {
    let spec = ZkvmSpec::load(spec_path)?;
    let wl = expand(&spec)?;
    let (cal, cal_loaded) = Calibration::load_or_placeholder(cal_path);

    println!(
        "# {} v{}: derived use-case workload\n",
        spec.zkvm.name, spec.zkvm.version
    );
    println!(
        "Expanded from the soundcalc submission ({} app segments, leaf arity {}, internal arity {}).",
        spec.aggregation.num_app_segments, spec.aggregation.leaf_arity, spec.aggregation.internal_arity
    );
    println!("Weights = occurrences per continuation run; renormalized to probabilities below.");
    println!("See the CAVEATS block in {spec_path}: absolute sizes inherit soundcalc's conservative batch_size (native hashing inflated ~100-200x, proven ~10-40x); the hash ranking is robust.\n");
    println!("| usecase | weight (prob) | msg bytes | calls | role |");
    println!("|---|---|---|---|---|");
    for u in &wl.usecases {
        println!(
            "| {} | {:.4} | {} | {} | {} |",
            u.name,
            u.prob,
            u.msg_len,
            u.num_calls,
            if u.role.circuit() { "circuit" } else { "native" },
        );
    }
    println!();

    report::run_report(&wl, &cal, cal_loaded, out_json)
}
