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

// TODO(poseidon): wire a real Poseidon (v1) implementation once Flock's field
// and instance (width, rate, R_F/R_P) are fixed (e.g. the zkhash crate, or a
// hand-rolled permutation). Until then Poseidon keeps its placeholder native
// atom and `measure` skips it with a warning.

pub fn available_backends() -> Vec<Box<dyn HashBackend>> {
    vec![
        Box::new(Sha256Backend),
        Box::new(Sha3Backend),
        Box::new(Blake3Backend),
    ]
}
