//! Calibration atoms: the measured (or placeholder) per-atom costs that the
//! analytic model multiplies by call counts.
//!
//! Workflow:
//!   1. `hash-bench measure` fits native (c0, c1) per hash on this machine
//!      and writes calibration.json.
//!   2. Circuit rows/perm and Flock prover constants are PLACEHOLDERS until
//!      measured on real Flock traces -- edit calibration.json by hand or
//!      extend `measure` once a Flock adapter exists.
//!   3. `hash-bench report` consumes calibration.json (or defaults).

use crate::callcount::HashId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Calibration {
    /// Per-hash native cost model: time_ns(msg) = c0_ns + c1_ns * perms(msg).
    /// c0 = fixed per-call overhead (setup, padding, finalization),
    /// c1 = marginal cost of one permutation/compression.
    pub native: HashMap<HashId, NativeAtom>,
    /// Per-hash in-circuit cost: trace rows contributed by one permutation.
    pub circuit_rows_per_perm: HashMap<HashId, u64>,
    /// Prover backend cost model (a parameter -- Flock, OpenVM, ...):
    /// prove_ns = setup_ns + ns_per_row * padded_height, where
    /// padded_height = next_power_of_two(num_calls * perms * rows_per_perm).
    #[serde(alias = "flock")]
    pub prover: ProverModel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NativeAtom {
    pub c0_ns: f64,
    pub c1_ns: f64,
    /// True once fitted by `measure` on this machine (false = placeholder).
    pub measured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverModel {
    /// Which prover backend these constants describe ("flock", "openvm", ...).
    #[serde(default = "default_prover_name")]
    pub name: String,
    pub setup_ns: f64,
    pub ns_per_row: f64,
    /// Minimum trace height the prover pads to regardless of workload.
    pub min_height: u64,
    /// True once calibrated against real prover runs.
    pub measured: bool,
}

fn default_prover_name() -> String {
    "flock".into()
}

impl Calibration {
    /// Placeholder defaults. Native numbers are order-of-magnitude priors for
    /// a modern x86 core WITHOUT hardware SHA extensions; they exist only so
    /// `report` runs before `measure` has been executed, and are flagged.
    ///
    /// Circuit rows/perm priors are loosely based on published small-field
    /// AIR implementations: an arithmetization-friendly permutation as the
    /// cheap baseline; Keccak-f and SHA-256 compression cost 2-3 orders more
    /// rows/area; BLAKE3 sits in between. Poseidon v1's dense MDS in the many
    /// partial rounds makes it a somewhat wider/taller AIR than Poseidon2,
    /// but still the same order. REPLACE WITH FLOCK MEASUREMENTS.
    pub fn placeholder() -> Self {
        let mut native = HashMap::new();
        native.insert(HashId::Sha256, NativeAtom { c0_ns: 40.0, c1_ns: 90.0, measured: false });
        native.insert(HashId::Sha3_256, NativeAtom { c0_ns: 50.0, c1_ns: 220.0, measured: false });
        native.insert(HashId::Blake3, NativeAtom { c0_ns: 60.0, c1_ns: 45.0, measured: false });
        // Poseidon v1 native: strongly field/impl dependent; the full-width
        // MDS multiply in every round (incl. partial) makes it ~2x Poseidon2;
        // prior ~2us/perm.
        native.insert(HashId::Poseidon, NativeAtom { c0_ns: 30.0, c1_ns: 2000.0, measured: false });

        let mut rows = HashMap::new();
        rows.insert(HashId::Poseidon, 2u64); // repetitive AIR: ~a few wide rows/perm
        rows.insert(HashId::Blake3, 64);
        rows.insert(HashId::Sha256, 128);
        rows.insert(HashId::Sha3_256, 256); // Keccak-f: large state, bitwise

        Calibration {
            native,
            circuit_rows_per_perm: rows,
            prover: ProverModel {
                name: default_prover_name(),
                setup_ns: 5.0e6,   // 5 ms fixed prover overhead (placeholder)
                ns_per_row: 500.0, // amortized per-row proving cost (placeholder)
                min_height: 1 << 10,
                measured: false,
            },
        }
    }

    pub fn load_or_placeholder(path: &str) -> (Self, bool) {
        match std::fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str(&text) {
                Ok(c) => (c, true),
                Err(e) => {
                    eprintln!("warning: {path} unparseable ({e}); using placeholders");
                    (Self::placeholder(), false)
                }
            },
            Err(_) => (Self::placeholder(), false),
        }
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|e| format!("cannot write {path}: {e}"))
    }
}
