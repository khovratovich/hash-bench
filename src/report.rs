//! Report generation: per-usecase tables, weighted scores, the num_calls
//! repetition sweep, and probability sensitivity analysis. Markdown to stdout,
//! full raw data to results.json.

use crate::calibration::Calibration;
use crate::callcount::ALL_HASHES;
use crate::costmodel::{score_hash, sweep_cost_per_call, usecase_cost};
use crate::workload::Workload;
use serde_json::json;

fn fmt_ns(ns: f64) -> String {
    if ns >= 1e9 {
        format!("{:.2} s", ns / 1e9)
    } else if ns >= 1e6 {
        format!("{:.2} ms", ns / 1e6)
    } else if ns >= 1e3 {
        format!("{:.2} us", ns / 1e3)
    } else {
        format!("{:.0} ns", ns)
    }
}

pub fn run_report(wl: &Workload, cal: &Calibration, cal_loaded: bool, out_json: &str) -> Result<(), String> {
    let unmeasured_native: Vec<_> = ALL_HASHES
        .iter()
        .filter(|h| !cal.native[h].measured)
        .map(|h| h.name())
        .collect();

    println!("# hash-bench report\n");
    if !cal_loaded {
        println!("> **warning:** no calibration.json found -- ALL atoms are placeholders. Run `hash-bench measure` first.\n");
    } else if !unmeasured_native.is_empty() {
        println!("> **warning:** native atoms not measured on this machine for: {}.\n", unmeasured_native.join(", "));
        for &h in ALL_HASHES.iter().filter(|h| !cal.native[h].measured) {
            match &cal.native[&h].source {
                Some(src) => println!(">   - {} ({:.0} ns/perm) {}\n", h.name(), cal.native[&h].c1_ns, src),
                None => println!(">   - {} ({:.0} ns/perm) bare placeholder, no source\n", h.name(), cal.native[&h].c1_ns),
            }
        }
    }
    // Provenance for atoms that ARE measured but carry a caveat (e.g. measured
    // against a reference implementation whose maturity differs from the other
    // candidates') -- the note must travel with the number, not just with
    // unmeasured placeholders.
    for &h in ALL_HASHES.iter().filter(|h| cal.native[h].measured) {
        if let Some(src) = &cal.native[&h].source {
            println!("> **note:** {} native atom ({:.0} ns/perm): {}\n", h.name(), cal.native[&h].c1_ns, src);
        }
    }
    if !cal.prover.measured {
        println!("> **warning:** prover model '{}' (setup_ns, ns_per_row) and circuit rows/perm are placeholders -- calibrate against real prover traces before trusting circuit-side numbers.\n", cal.prover.name);
    }

    // ---- per-usecase table ------------------------------------------------
    println!("## Per-usecase costs\n");
    println!("| usecase | prob | len | calls | hash | perms/msg | native (total) | trace rows | padded | prove |");
    println!("|---|---|---|---|---|---|---|---|---|---|");
    for uc in &wl.usecases {
        for &h in &ALL_HASHES {
            let c = usecase_cost(uc, h, wl, cal);
            println!(
                "| {} | {:.2} | {} | {} | {} | {} | {} | {} | {} | {} |",
                uc.name,
                uc.prob,
                uc.msg_len,
                uc.num_calls,
                h.name(),
                c.perms_per_msg,
                c.native_ns.map_or("-".into(), fmt_ns),
                c.trace_height.map_or("-".into(), |v| v.to_string()),
                c.padded_height.map_or("-".into(), |v| v.to_string()),
                c.prove_ns.map_or("-".into(), fmt_ns),
            );
        }
    }

    // ---- weighted scores ---------------------------------------------------
    println!("\n## Expected (probability-weighted) scores\n");
    println!("Combined = E[native] + E[prove]: both are wall-clock time, paid once per use-case occurrence.");
    println!("Encode frequency asymmetries as separate native-role usecases.\n");
    println!("| hash | E[native] | E[prove] | combined |");
    println!("|---|---|---|---|");
    let mut scores: Vec<_> = ALL_HASHES.iter().map(|&h| score_hash(h, wl, cal)).collect();
    scores.sort_by(|a, b| a.combined_ns.partial_cmp(&b.combined_ns).unwrap());
    for s in &scores {
        println!(
            "| {} | {} | {} | {} |",
            s.hash.name(),
            fmt_ns(s.expected_native_ns),
            fmt_ns(s.expected_prove_ns),
            fmt_ns(s.combined_ns)
        );
    }
    let winner = scores[0].hash;
    println!("\n**Winner (combined): {}**", winner.name());

    // ---- num_calls sweep -----------------------------------------------------
    // Flock circuits are largely repetitive: per-call prover cost falls in
    // power-of-two steps as repetition fills the padded trace.
    println!("\n## Prover cost per call vs. repetition (msg_len = 64 B)\n");
    let sweep = &wl.model.sweep_num_calls;
    let header: Vec<String> = sweep.iter().map(|n| format!("n={n}")).collect();
    println!("| hash | {} |", header.join(" | "));
    println!("|---|{}", "---|".repeat(sweep.len()));
    for &h in &ALL_HASHES {
        let cells: Vec<String> = sweep
            .iter()
            .map(|&n| fmt_ns(sweep_cost_per_call(h, 64, n, wl, cal)))
            .collect();
        println!("| {} | {} |", h.name(), cells.join(" | "));
    }

    // ---- sensitivity ---------------------------------------------------------
    println!("\n## Sensitivity: does the winner survive prob perturbations?\n");
    let mut flips = Vec::new();
    for (i, uc) in wl.usecases.iter().enumerate() {
        for factor in [0.5, 2.0] {
            let mut wl2 = wl.clone();
            wl2.usecases[i].prob *= factor;
            let total: f64 = wl2.usecases.iter().map(|u| u.prob).sum();
            for u in &mut wl2.usecases {
                u.prob /= total;
            }
            let mut s2: Vec<_> = ALL_HASHES.iter().map(|&h| score_hash(h, &wl2, cal)).collect();
            s2.sort_by(|a, b| a.combined_ns.partial_cmp(&b.combined_ns).unwrap());
            if s2[0].hash != winner {
                flips.push(format!(
                    "- p({}) x{} -> winner becomes **{}**",
                    uc.name,
                    factor,
                    s2[0].hash.name()
                ));
            }
        }
    }
    if flips.is_empty() {
        println!("Ranking is stable under x0.5 / x2 perturbation of every usecase probability.");
    } else {
        println!("Ranking FLIPS under these perturbations -- pin down these probabilities:\n");
        for f in flips {
            println!("{f}");
        }
    }

    // ---- raw JSON --------------------------------------------------------------
    let raw = json!({
        "workload": {
            "usecases": wl.usecases.iter().map(|u| json!({
                "name": u.name, "prob": u.prob, "msg_len": u.msg_len, "num_calls": u.num_calls,
            })).collect::<Vec<_>>(),
        },
        "calibration": cal,
        "per_usecase": wl.usecases.iter().flat_map(|uc| {
            ALL_HASHES.iter().map(|&h| serde_json::to_value(usecase_cost(uc, h, wl, cal)).unwrap()).collect::<Vec<_>>()
        }).collect::<Vec<_>>(),
        "scores": scores,
    });
    std::fs::write(out_json, serde_json::to_string_pretty(&raw).unwrap())
        .map_err(|e| format!("cannot write {out_json}: {e}"))?;
    println!("\n(raw data written to {out_json})");
    Ok(())
}
