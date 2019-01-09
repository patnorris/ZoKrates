use field::Field;
use helpers::{Executable, Signed};
use libsnark::{get_ethsha256_witness, get_sha256_witness, get_merkleread_witness};
use serde_json;
use standard;
use std::fmt;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum LibsnarkGadgetHelper {
    Sha256Compress,
    Sha256Ethereum,

    MerkleRead,
}

impl fmt::Display for LibsnarkGadgetHelper {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LibsnarkGadgetHelper::Sha256Compress => write!(f, "Sha256Compress"),
            LibsnarkGadgetHelper::Sha256Ethereum => write!(f, "Sha256Ethereum"),

            LibsnarkGadgetHelper::MerkleRead => write!(f, "MerkleRead"),
        }
    }
}

impl<T: Field> Executable<T> for LibsnarkGadgetHelper {
    fn execute(&self, inputs: &Vec<T>) -> Result<Vec<T>, String> {
        let witness_result: Result<standard::Witness, serde_json::Error> = match self {
            LibsnarkGadgetHelper::Sha256Compress => {
                serde_json::from_str(&get_sha256_witness(inputs))
            }
            LibsnarkGadgetHelper::Sha256Ethereum => {
                serde_json::from_str(&get_ethsha256_witness(inputs))
            }

            LibsnarkGadgetHelper::MerkleRead => {
                serde_json::from_str(&get_merkleread_witness(inputs))
            }
        };

        if let Err(e) = witness_result {
            return Err(format!("{}", e));
        }

        Ok(witness_result
            .unwrap()
            .variables
            .iter()
            .map(|&i| T::from(i))
            .collect())
    }
}

impl Signed for LibsnarkGadgetHelper {
    fn get_signature(&self) -> (usize, usize) {
        match self {
            LibsnarkGadgetHelper::Sha256Compress => (512, 25561),
            LibsnarkGadgetHelper::Sha256Ethereum => (512, 50610),

            LibsnarkGadgetHelper::MerkleRead => (512, 50610),
        }
    }
}
