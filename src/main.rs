//! hash-bench: Strategy-C hybrid benchmark for selecting a hash function
//! by expected cost over a probability-weighted use-case set, natively and
//! inside the Flock proving system.
//!
//! Commands:
//!   hash-bench report  [--workload path] [--calibration path] [--out path]
//!   hash-bench measure [--workload path] [--calibration path]
//!
//! A workload TOML is either a probability-weighted use-case set
//! (workloads/default.toml) or a zkVM spec with a [zkvm] section
//! (workloads/openvm.toml); `report` dispatches on the file's contents.

mod backends;
mod calibration;
mod callcount;
mod costmodel;
mod measure;
mod report;
mod workload;
mod zkvm;

use calibration::Calibration;
use workload::Workload;

fn arg_value(args: &[String], flag: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

/// A workload file with a top-level [zkvm] section is a zkVM spec;
/// otherwise it is a use-case workload.
fn workload_is_zkvm(path: &str) -> Result<bool, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let value: toml::Value =
        toml::from_str(&text).map_err(|e| format!("cannot parse {path}: {e}"))?;
    Ok(value.get("zkvm").is_some())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("report");
    let wl_path = arg_value(&args, "--workload", "workloads/default.toml");
    let cal_path = arg_value(&args, "--calibration", "calibration.json");
    let out_path = arg_value(&args, "--out", "results.json");

    let result = (|| -> Result<(), String> {
        match cmd {
            "measure" => measure::run_measure(&Workload::load(&wl_path)?, &cal_path),
            "report" => {
                if workload_is_zkvm(&wl_path)? {
                    zkvm::run_zkvm(&wl_path, &cal_path, &out_path)
                } else {
                    let (cal, loaded) = Calibration::load_or_placeholder(&cal_path);
                    report::run_report(&Workload::load(&wl_path)?, &cal, loaded, &out_path)
                }
            }
            other => Err(format!("unknown command '{other}' (use: report | measure)")),
        }
    })();

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
