//! Native backends: real implementations used ONLY to calibrate the (c0, c1)
//! atoms via `measure`. The model, not these backends, produces the report.

use crate::callcount::HashId;
use sha2::Digest;

pub trait HashBackend {
    fn id(&self) -> HashId;
    fn hash(&self, msg: &[u8]) -> Vec<u8>;
}

pub struct Sha256Backend;
impl HashBackend for Sha256Backend {
    fn id(&self) -> HashId {
        HashId::Sha256
    }
    fn hash(&self, msg: &[u8]) -> Vec<u8> {
        sha2::Sha256::digest(msg).to_vec()
    }
}

pub struct Sha3Backend;
impl HashBackend for Sha3Backend {
    fn id(&self) -> HashId {
        HashId::Sha3_256
    }
    fn hash(&self, msg: &[u8]) -> Vec<u8> {
        sha3::Sha3_256::digest(msg).to_vec()
    }
}

pub struct Blake3Backend;
impl HashBackend for Blake3Backend {
    fn id(&self) -> HashId {
        HashId::Blake3
    }
    fn hash(&self, msg: &[u8]) -> Vec<u8> {
        blake3::hash(msg).as_bytes().to_vec()
    }
}

/// Poseidon (v1) over BabyBear, t=16 -- only under `--features poseidon-native`.
///
/// Uses the Poseidon2 paper's own reference implementation (crate `zkhash`,
/// `POSEIDON_BABYBEAR_16_PARAMS` = PoseidonParams::new(16, 7, 8, 13, MDS16,
/// RC16): width 16, alpha=7, R_F=8, R_P=13) via its `permutation()` entry
/// point -- the OPTIMIZED partial-round representation, i.e. the same code
/// path the paper's Table 2 timings measure. Measuring this replaces the
/// literature-derived atom in calibration.rs with a number from this machine.
///
/// The sponge here mirrors `callcount::perms_per_msg` exactly: bytes are
/// packed little-endian into `bytes_per_elem`-sized field elements and
/// absorbed `rate` at a time, so a message of `len` bytes costs
/// ceil(ceil(len / bytes_per_elem) / rate) permutations -- no extra squeeze
/// permutation. It is a calibration harness, not a standardized sponge:
/// domain separation and padding are deliberately absent because they would
/// change the digest but not the operation count this measures.
#[cfg(feature = "poseidon-native")]
pub struct PoseidonBackend {
    perm: zkhash::poseidon::poseidon::Poseidon<zkhash::fields::babybear::FpBabyBear>,
    width: usize,
    rate: usize,
    bytes_per_elem: usize,
}

#[cfg(feature = "poseidon-native")]
impl PoseidonBackend {
    pub fn new(p: &crate::workload::PoseidonParams) -> Self {
        use zkhash::poseidon::{
            poseidon::Poseidon, poseidon_instance_babybear::POSEIDON_BABYBEAR_16_PARAMS,
        };
        assert_eq!(
            p.width, 16,
            "the wired zkhash instance is BabyBear t=16; set [poseidon].width = 16 \
             or add the matching instance (t=24 is also available)"
        );
        PoseidonBackend {
            perm: Poseidon::new(&POSEIDON_BABYBEAR_16_PARAMS),
            width: p.width as usize,
            rate: p.rate as usize,
            bytes_per_elem: p.bytes_per_elem as usize,
        }
    }
}

#[cfg(feature = "poseidon-native")]
impl HashBackend for PoseidonBackend {
    fn id(&self) -> HashId {
        HashId::Poseidon
    }

    fn hash(&self, msg: &[u8]) -> Vec<u8> {
        use ark_ff::{BigInteger, PrimeField, Zero};
        type Scalar = zkhash::fields::babybear::FpBabyBear;

        // Pack bytes -> field elements (little-endian, zero-padded tail).
        // From<u64> reduces mod p, so a 4-byte word above p wraps rather than
        // panicking -- fine for timing, and matches the byte budget the model
        // assumes.
        let mut elems: Vec<Scalar> = msg
            .chunks(self.bytes_per_elem)
            .map(|c| {
                let mut buf = [0u8; 8];
                buf[..c.len()].copy_from_slice(c);
                Scalar::from(u64::from_le_bytes(buf))
            })
            .collect();
        if elems.is_empty() {
            elems.push(Scalar::zero()); // empty message still costs one permutation
        }

        let mut state = vec![Scalar::zero(); self.width];
        for chunk in elems.chunks(self.rate) {
            for (lane, e) in chunk.iter().enumerate() {
                state[lane] += *e;
            }
            state = self.perm.permutation(&state);
        }

        // Squeeze 256 bits from the rate lanes (no further permutation).
        let per_elem = self.bytes_per_elem;
        state
            .iter()
            .take(32usize.div_ceil(per_elem))
            .flat_map(|s| s.into_bigint().to_bytes_le()[..per_elem].to_vec())
            .collect()
    }
}

pub fn available_backends(
    #[allow(unused_variables)] poseidon: &crate::workload::PoseidonParams,
) -> Vec<Box<dyn HashBackend>> {
    #[allow(unused_mut)] // `mut` is only needed when poseidon-native is on
    let mut v: Vec<Box<dyn HashBackend>> = vec![
        Box::new(Sha256Backend),
        Box::new(Sha3Backend),
        Box::new(Blake3Backend),
    ];
    #[cfg(feature = "poseidon-native")]
    v.push(Box::new(PoseidonBackend::new(poseidon)));
    v
}
