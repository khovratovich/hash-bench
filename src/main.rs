//! hash-bench: Strategy-C hybrid benchmark for selecting a hash function
//! by expected cost over a probability-weighted use-case set, natively and
//! inside the Flock proving system.
//!
//! Commands:
//!   hash-bench report  [--workload path] [--calibration path] [--out path]
//!   hash-bench measure [--workload path] [--calibration path]
//!   hash-bench zkvm    [--zkvm path] [--calibration path]

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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("report");
    let wl_path = arg_value(&args, "--workload", "workloads/default.toml");
    let cal_path = arg_value(&args, "--calibration", "calibration.json");
    let out_path = arg_value(&args, "--out", "results.json");

    let zkvm_path = arg_value(&args, "--zkvm", "provers/openvm.toml");

    let result = (|| -> Result<(), String> {
        match cmd {
            "zkvm" => zkvm::run_zkvm(&zkvm_path, &cal_path),
            "measure" => measure::run_measure(&Workload::load(&wl_path)?, &cal_path),
            "report" => {
                let (cal, loaded) = Calibration::load_or_placeholder(&cal_path);
                report::run_report(&Workload::load(&wl_path)?, &cal, loaded, &out_path)
            }
            other => Err(format!("unknown command '{other}' (use: report | measure | zkvm)")),
        }
    })();

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
