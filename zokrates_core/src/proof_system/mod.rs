mod bn128;
mod utils;

use field::FieldPrime;
use std::fs::File;

pub use self::bn128::GM17;
pub use self::bn128::PGHR13;
use flat_absy::flat_variable::FlatVariable;
use std::io::BufReader;

pub trait ProofSystem {
    fn setup(
        &self,
        variables: Vec<FlatVariable>,
        a: Vec<Vec<(usize, FieldPrime)>>,
        b: Vec<Vec<(usize, FieldPrime)>>,
        c: Vec<Vec<(usize, FieldPrime)>>,
        num_inputs: usize,
        pk_path: &str,
        vk_path: &str,
    ) -> bool;

    fn generate_proof(
        &self,
        pk_path: &str,
        proof_path: &str,
        public_inputs: Vec<FieldPrime>,
        private_inputs: Vec<FieldPrime>,
    ) -> bool;

    fn export_solidity_verifier(&self, reader: BufReader<File>) -> String;
}
