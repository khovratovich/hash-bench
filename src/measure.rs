//! Native atom calibration: fit time_ns(msg) = c0 + c1 * perms(msg) per hash
//! by timing real implementations at several message lengths and doing a
//! least-squares fit over (perms, ns/call) points.
//!
//! Deliberately simple (median-of-batches, no criterion dependency): the atoms
//! feed a coarse analytic model, so ~5% timer noise is irrelevant next to the
//! placeholder uncertainty on the circuit side. Pin CPU frequency for best
//! results.

use crate::backends::available_backends;
use crate::calibration::{Calibration, NativeAtom};
use crate::callcount::perms_per_msg;
use crate::workload::Workload;
use std::hint::black_box;
use std::time::Instant;

const CALIB_LENGTHS: [u64; 5] = [32, 64, 256, 1024, 65536];
const BATCHES: usize = 15;
const TARGET_BATCH_NS: f64 = 2.0e6; // ~2ms per timed batch

/// Median ns per call at a given message length.
fn time_one(backend: &dyn crate::backends::HashBackend, len: u64) -> f64 {
    let msg = vec![0xabu8; len as usize];

    // Warm up and estimate iterations for ~TARGET_BATCH_NS per batch.
    let t0 = Instant::now();
    let mut sink = 0u8;
    for _ in 0..32 {
        sink ^= backend.hash(black_box(&msg))[0];
    }
    let per_call = (t0.elapsed().as_nanos() as f64 / 32.0).max(1.0);
    let iters = ((TARGET_BATCH_NS / per_call) as usize).clamp(16, 4_000_000);

    let mut samples = Vec::with_capacity(BATCHES);
    for _ in 0..BATCHES {
        let t = Instant::now();
        for _ in 0..iters {
            sink ^= backend.hash(black_box(&msg))[0];
        }
        samples.push(t.elapsed().as_nanos() as f64 / iters as f64);
    }
    black_box(sink);
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[BATCHES / 2]
}

/// Least-squares fit y = c0 + c1 * x; returns (c0, c1).
fn fit(points: &[(f64, f64)]) -> (f64, f64) {
    let n = points.len() as f64;
    let sx: f64 = points.iter().map(|p| p.0).sum();
    let sy: f64 = points.iter().map(|p| p.1).sum();
    let sxx: f64 = points.iter().map(|p| p.0 * p.0).sum();
    let sxy: f64 = points.iter().map(|p| p.0 * p.1).sum();
    let c1 = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    let c0 = (sy - c1 * sx) / n;
    (c0.max(0.0), c1.max(0.0))
}

pub fn run_measure(wl: &Workload, cal_path: &str) -> Result<(), String> {
    let (mut cal, _) = Calibration::load_or_placeholder(cal_path);

    for backend in available_backends() {
        let id = backend.id();
        let mut points = Vec::new();
        for &len in &CALIB_LENGTHS {
            let perms = perms_per_msg(id, len, &wl.poseidon) as f64;
            let ns = time_one(backend.as_ref(), len);
            println!("  {:<10} len={:>6}  perms={:>5}  {:>10.1} ns/call", id.name(), len, perms, ns);
            points.push((perms, ns));
        }
        let (c0, c1) = fit(&points);
        println!("{:<10} fit: c0 = {:.1} ns/call, c1 = {:.1} ns/perm\n", id.name(), c0, c1);
        cal.native.insert(id, NativeAtom { c0_ns: c0, c1_ns: c1, measured: true, source: None });
    }

    println!("note: Poseidon has no native backend yet (field/instance TBD); keeping placeholder atom.");
    cal.save(cal_path)?;
    println!("calibration written to {cal_path}");
    Ok(())
}
