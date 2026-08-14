//! Workload spec: parsed from workloads/*.toml.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Workload {
    pub model: ModelParams,
    pub poseidon: PoseidonParams,
    #[serde(rename = "usecase")]
    pub usecases: Vec<UseCase>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelParams {
    pub sweep_num_calls: Vec<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PoseidonParams {
    /// Permutation width; unused by the sponge call count (rate suffices) but
    /// will parameterize rows/perm once the Flock adapter lands.
    #[allow(dead_code)]
    pub width: u32,
    pub rate: u32,
    pub bytes_per_elem: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UseCase {
    pub name: String,
    pub prob: f64,
    pub msg_len: u64,
    pub num_calls: u64,
    pub role: Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Native,
    Circuit,
    Both,
}

impl Role {
    pub fn native(self) -> bool {
        matches!(self, Role::Native | Role::Both)
    }
    pub fn circuit(self) -> bool {
        matches!(self, Role::Circuit | Role::Both)
    }
}

impl Workload {
    pub fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {path}: {e}"))?;
        let mut wl: Workload =
            toml::from_str(&text).map_err(|e| format!("cannot parse {path}: {e}"))?;
        let total: f64 = wl.usecases.iter().map(|u| u.prob).sum();
        if total <= 0.0 {
            return Err("usecase probabilities sum to zero".into());
        }
        for u in &mut wl.usecases {
            u.prob /= total; // renormalize so weights need not sum to 1
        }
        Ok(wl)
    }
}
