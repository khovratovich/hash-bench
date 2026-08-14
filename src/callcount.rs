//! Analytic call-count model: number of core-permutation / compression-function
//! invocations as a function of message length, per hash.
//!
//! This is the machine-independent atom count that the hybrid (Strategy C)
//! model multiplies by measured per-permutation costs. Formulas follow the
//! padding / mode rules of each function; each is unit-tested below.

use crate::workload::PoseidonParams;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashId {
    Sha256,
    Sha3_256,
    Blake3,
    Poseidon,
}

pub const ALL_HASHES: [HashId; 4] = [
    HashId::Sha256,
    HashId::Sha3_256,
    HashId::Blake3,
    HashId::Poseidon,
];

impl HashId {
    pub fn name(self) -> &'static str {
        match self {
            HashId::Sha256 => "SHA-256",
            HashId::Sha3_256 => "SHA3-256",
            HashId::Blake3 => "BLAKE3",
            HashId::Poseidon => "Poseidon",
        }
    }
}

/// Permutation / compression calls to hash one message of `len` bytes.
pub fn perms_per_msg(hash: HashId, len: u64, p: &PoseidonParams) -> u64 {
    match hash {
        // Merkle-Damgard, 64B block, padding = 0x80 || zeros || 8B length.
        // Blocks = floor((len + 8) / 64) + 1.
        HashId::Sha256 => (len + 8) / 64 + 1,

        // Sponge, rate 136B (Keccak-f[1600] at 256-bit security level),
        // pad10*1 always adds at least one bit: calls = ceil((len + 1) / 136).
        HashId::Sha3_256 => (len + 1).div_ceil(136),

        // 64B compression blocks within 1024B chunks; binary tree of chunks
        // adds one parent compression per non-root internal node = chunks - 1.
        // Empty/short messages still cost one compression.
        HashId::Blake3 => {
            let compressions = len.div_ceil(64).max(1);
            let chunks = len.div_ceil(1024).max(1);
            compressions + (chunks - 1)
        }

        // Sponge over field elements: absorb ceil(elems / rate) permutations,
        // elems = ceil(len / bytes_per_elem). At least one permutation.
        HashId::Poseidon => {
            let elems = len.div_ceil(p.bytes_per_elem as u64).max(1);
            elems.div_ceil(p.rate as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p2() -> PoseidonParams {
        PoseidonParams { width: 16, rate: 8, bytes_per_elem: 4 }
    }

    #[test]
    fn sha256_padding_boundaries() {
        assert_eq!(perms_per_msg(HashId::Sha256, 0, &p2()), 1);
        assert_eq!(perms_per_msg(HashId::Sha256, 55, &p2()), 1); // 55+9 = 64
        assert_eq!(perms_per_msg(HashId::Sha256, 56, &p2()), 2); // spills
        assert_eq!(perms_per_msg(HashId::Sha256, 64, &p2()), 2); // 2-to-1 merkle
    }

    #[test]
    fn sha3_rate_boundaries() {
        assert_eq!(perms_per_msg(HashId::Sha3_256, 0, &p2()), 1);
        assert_eq!(perms_per_msg(HashId::Sha3_256, 135, &p2()), 1);
        assert_eq!(perms_per_msg(HashId::Sha3_256, 136, &p2()), 2); // pad spills
    }

    #[test]
    fn blake3_chunks_and_parents() {
        assert_eq!(perms_per_msg(HashId::Blake3, 0, &p2()), 1);
        assert_eq!(perms_per_msg(HashId::Blake3, 64, &p2()), 1);
        assert_eq!(perms_per_msg(HashId::Blake3, 1024, &p2()), 16);
        // 2048B = 2 chunks * 16 compressions + 1 parent
        assert_eq!(perms_per_msg(HashId::Blake3, 2048, &p2()), 33);
    }

    #[test]
    fn poseidon_absorb() {
        // 64B / 4Bpe = 16 elems / rate 8 = 2 permutations
        assert_eq!(perms_per_msg(HashId::Poseidon, 64, &p2()), 2);
        assert_eq!(perms_per_msg(HashId::Poseidon, 32, &p2()), 1);
    }
}
