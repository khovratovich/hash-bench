//! Native atom calibration: fit time_ns(msg) = c0 + c1 * perms(msg) per hash
//! by timing real implementations at several message lengths and doing a
//! least-squares fit over (perms, ns/call) points.
//!
//! Deliberately simple (min-of-batches, no criterion dependency): the atoms
//! feed a coarse analytic model, so a few percent of timer noise is irrelevant
//! next to the placeholder uncertainty on the circuit side. Pin CPU frequency
//! for best results.
//!
//! `sweep` reuses the same timing core over a finer length grid and reports
//! per-length detail (ns/call, ns/perm, throughput, factor vs the fastest
//! candidate) instead of collapsing everything into a two-parameter fit.

use crate::backends::available_backends;
use crate::calibration::{Calibration, NativeAtom};
use crate::callcount::{perms_per_msg, HashId};
use crate::workload::Workload;
use std::hint::black_box;
use std::time::Instant;

const CALIB_LENGTHS: [u64; 5] = [32, 64, 256, 1024, 65536];
/// Finer grid for `sweep`: straddles SHA-256's 64 B block, SHA3's 136 B rate,
/// and BLAKE3's 1024 B chunk boundary so mode effects are visible.
const SWEEP_LENGTHS: [u64; 10] = [32, 64, 128, 136, 256, 512, 1024, 2048, 16384, 65536];
const BATCHES: usize = 15;
const TARGET_BATCH_NS: f64 = 2.0e6; // ~2ms per timed batch

/// Minimum ns per call at a given message length, plus the observed spread.
///
/// MINIMUM, not median: background load, scheduler preemption, and frequency
/// dips only ever ADD time to a batch, so the fastest batch is the best
/// estimate of the uncontended cost, while the median tracks whatever else the
/// machine happened to be doing. Measured here across three runs on a loaded
/// machine, the median moved SHA-256 between 98 and 350 ns/perm; the minimum
/// is far more stable. The returned spread (max/min) is the load indicator --
/// a ratio near 1 means a quiet machine.
fn time_one(backend: &dyn crate::backends::HashBackend, len: u64) -> (f64, f64) {
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
    (samples[0], samples[BATCHES - 1] / samples[0])
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

/// Per-length native detail for every available backend: the raw data behind
/// the two-parameter fit. Prints ns/call, the implied ns/perm, throughput, and
/// each candidate's factor versus the fastest candidate at that length --
/// showing where mode effects (padding boundaries, SIMD batching) make the
/// linear model leak, which a single (c0, c1) pair cannot express.
pub fn run_sweep(wl: &Workload) -> Result<(), String> {
    let backends = available_backends(&wl.poseidon);

    // rows[hash_index][length_index] = (perms, ns_per_call, spread)
    let mut rows: Vec<(HashId, Vec<(u64, f64, f64)>)> = Vec::new();
    for backend in &backends {
        let id = backend.id();
        let mut per_len = Vec::new();
        for &len in &SWEEP_LENGTHS {
            let perms = perms_per_msg(id, len, &wl.poseidon);
            let (ns, spread) = time_one(backend.as_ref(), len);
            per_len.push((perms, ns, spread));
        }
        rows.push((id, per_len));
    }

    println!("# Native sweep (min of {BATCHES} batches per point)\n");
    for (id, per_len) in &rows {
        println!("## {}\n", id.name());
        println!("| bytes | perms/msg | ns/call | ns/perm | bytes/perm | MB/s | spread |");
        println!("|---|---|---|---|---|---|---|");
        for (i, &(perms, ns, spread)) in per_len.iter().enumerate() {
            let len = SWEEP_LENGTHS[i];
            println!(
                "| {} | {} | {:.1} | {:.1} | {:.1} | {:.0} | x{:.2} |",
                len,
                perms,
                ns,
                ns / perms as f64,
                len as f64 / perms as f64,
                len as f64 / ns * 1000.0, // bytes/ns -> MB/s
                spread,
            );
        }
        println!();
    }

    // Relative table: factor vs the fastest candidate at each length.
    println!("## Factor vs fastest at each length\n");
    print!("| bytes |");
    for (id, _) in &rows {
        print!(" {} |", id.name());
    }
    println!("\n|---|{}", "---|".repeat(rows.len()));
    for (i, &len) in SWEEP_LENGTHS.iter().enumerate() {
        let best = rows
            .iter()
            .map(|(_, pl)| pl[i].1)
            .fold(f64::INFINITY, f64::min);
        print!("| {} |", len);
        for (_, pl) in &rows {
            let f = pl[i].1 / best;
            if f <= 1.0001 {
                print!(" **1.00** |");
            } else {
                print!(" {:.2} |", f);
            }
        }
        println!();
    }
    println!("\n(fastest candidate at each length in bold; higher = slower)");
    Ok(())
}

pub fn run_measure(wl: &Workload, cal_path: &str) -> Result<(), String> {
    let (mut cal, _) = Calibration::load_or_placeholder(cal_path);

    for backend in available_backends(&wl.poseidon) {
        let id = backend.id();
        let mut points = Vec::new();
        let mut worst_spread: f64 = 1.0;
        for &len in &CALIB_LENGTHS {
            let perms = perms_per_msg(id, len, &wl.poseidon) as f64;
            let (ns, spread) = time_one(backend.as_ref(), len);
            worst_spread = worst_spread.max(spread);
            println!(
                "  {:<10} len={:>6}  perms={:>5}  {:>10.1} ns/call  (spread x{:.2})",
                id.name(), len, perms, ns, spread
            );
            points.push((perms, ns));
        }
        if worst_spread > 2.0 {
            println!(
                "  !! spread up to x{:.1} -- machine is loaded; re-run when idle for a tighter fit",
                worst_spread
            );
        }
        let (c0, c1) = fit(&points);
        println!("{:<10} fit: c0 = {:.1} ns/call, c1 = {:.1} ns/perm\n", id.name(), c0, c1);
        // Poseidon's measurement carries an implementation-maturity caveat that
        // must stay attached to the number: the reference implementation uses
        // ark-ff's GENERIC Montgomery backend (64-bit limbs) for a 31-bit
        // field, while the other candidates here are production crates with
        // SHA-NI/SIMD. Comparing them head-to-head measures engineering effort
        // as much as primitive cost, so record how to correct for it.
        let source = (id == HashId::Poseidon).then(|| {
            format!(
                "measured here: zkhash POSEIDON_BABYBEAR_16_PARAMS (t=16, alpha=7, R_F=8, \
                 R_P=13), optimized permutation(), sponge rate {} over {}-byte elems. \
                 REFERENCE-QUALITY: ark-ff generic 64-bit-limb Montgomery for a 31-bit field. \
                 eprint 2023/323 Tab.2 measures this same code at 7.06us/perm (i7-6700K); a \
                 specialized impl (Plonky3-style BabyBear + AVX-2) is ~3400 ns/perm -- set \
                 c1_ns=3400 to compare production-quality implementations of all four hashes.",
                wl.poseidon.rate, wl.poseidon.bytes_per_elem
            )
        });
        cal.native.insert(id, NativeAtom { c0_ns: c0, c1_ns: c1, measured: true, source });
    }

    #[cfg(not(feature = "poseidon-native"))]
    println!(
        "note: Poseidon not measured (build with --features poseidon-native to wire the \
         zkhash BabyBear t=16 reference implementation); keeping the literature-derived atom."
    );
    cal.save(cal_path)?;
    println!("calibration written to {cal_path}");
    Ok(())
}
