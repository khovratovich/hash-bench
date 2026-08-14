//! Strategy C core: combine analytic call counts with calibrated atom costs.
//!
//! Native:  cost_ns(usecase) = num_calls * (c0 + c1 * perms(msg_len))
//! Circuit: height = num_calls * perms(msg_len) * rows_per_perm
//!          padded = max(next_pow2(height), min_height)      (repetitive AIR)
//!          prove_ns = setup_ns + ns_per_row * padded
//!
//! The power-of-two padding is why `num_calls` is a first-class use-case
//! parameter: per-call prover cost drops in steps as repetition fills the
//! padded trace.

use crate::calibration::Calibration;
use crate::callcount::{perms_per_msg, HashId};
use crate::workload::{UseCase, Workload};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct UseCaseCost {
    pub usecase: String,
    pub prob: f64,
    pub hash: HashId,
    pub perms_per_msg: u64,
    pub total_perms: u64,
    /// Native wall time for all num_calls invocations (ns). None if role=circuit.
    pub native_ns: Option<f64>,
    /// Trace height before padding. None if role=native.
    pub trace_height: Option<u64>,
    pub padded_height: Option<u64>,
    pub prove_ns: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HashScore {
    pub hash: HashId,
    /// Probability-weighted expected native cost (ns) over native-role usecases.
    pub expected_native_ns: f64,
    /// Probability-weighted expected proving cost (ns) over circuit-role usecases.
    pub expected_prove_ns: f64,
    /// Combined wall-clock: expected_native + expected_prove (both are time,
    /// paid once per use-case occurrence). Frequency asymmetries belong in
    /// the workload as separate native-role usecases.
    pub combined_ns: f64,
}

pub fn usecase_cost(
    uc: &UseCase,
    hash: HashId,
    wl: &Workload,
    cal: &Calibration,
) -> UseCaseCost {
    let perms = perms_per_msg(hash, uc.msg_len, &wl.poseidon);
    let total_perms = perms * uc.num_calls;

    let native_ns = uc.role.native().then(|| {
        let a = cal.native[&hash];
        uc.num_calls as f64 * (a.c0_ns + a.c1_ns * perms as f64)
    });

    let (trace_height, padded_height, prove_ns) = if uc.role.circuit() {
        let rows = cal.circuit_rows_per_perm[&hash];
        let height = total_perms * rows;
        let padded = height.next_power_of_two().max(cal.prover.min_height);
        let ns = cal.prover.setup_ns + cal.prover.ns_per_row * padded as f64;
        (Some(height), Some(padded), Some(ns))
    } else {
        (None, None, None)
    };

    UseCaseCost {
        usecase: uc.name.clone(),
        prob: uc.prob,
        hash,
        perms_per_msg: perms,
        total_perms,
        native_ns,
        trace_height,
        padded_height,
        prove_ns,
    }
}

pub fn score_hash(hash: HashId, wl: &Workload, cal: &Calibration) -> HashScore {
    let mut native = 0.0;
    let mut prove = 0.0;
    for uc in &wl.usecases {
        let c = usecase_cost(uc, hash, wl, cal);
        if let Some(n) = c.native_ns {
            native += uc.prob * n;
        }
        if let Some(p) = c.prove_ns {
            prove += uc.prob * p;
        }
    }
    HashScore {
        hash,
        expected_native_ns: native,
        expected_prove_ns: prove,
        combined_ns: native + prove,
    }
}

/// Per-call proving cost (ns) for `num_calls` repetitions of a single
/// msg_len-byte hash -- the repetition sweep table.
pub fn sweep_cost_per_call(
    hash: HashId,
    msg_len: u64,
    num_calls: u64,
    wl: &Workload,
    cal: &Calibration,
) -> f64 {
    let perms = perms_per_msg(hash, msg_len, &wl.poseidon);
    let rows = cal.circuit_rows_per_perm[&hash];
    let height = num_calls * perms * rows;
    let padded = height.next_power_of_two().max(cal.prover.min_height);
    (cal.prover.setup_ns + cal.prover.ns_per_row * padded as f64) / num_calls as f64
}
