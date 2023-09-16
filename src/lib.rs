pub mod signature_verification;

use crate::signature_verification::*;

use halo2_base::halo2_proofs::circuit;
use halo2_base::halo2_proofs::circuit::{SimpleFloorPlanner, Value};
use halo2_base::halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Instance};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::utils::fe_to_biguint;
use halo2_base::utils::{decompose_fe_to_u64_limbs, value_to_option};
use halo2_base::QuantumCell;
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::PrimeField,
};

pub use halo2_rsa;
use halo2_rsa::*;
use rsa::PublicKeyParts;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::marker::PhantomData;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

pub const VERIFY_CONFIG_ENV: &'static str = "VERIFY_CONFIG";

/// Configuration for [`DefaultMynaCircuit`].
#[derive(Debug, Clone)]
pub struct DefaultMynaConfig<F: PrimeField> {
    pub signature_verification_config: SignatureVerificationConfig<F>,
    pub instances: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct DefaultMynaCircuit<F: PrimeField> {
    pub hashed: Vec<u8>, // A SHA256 hashed message
    pub signature: Vec<u8>, // A signature
    pub public_key_n: BigUint, // pub public_key: RSAPublicKey<F>,
    _f: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for DefaultMynaCircuit<F> {
    type Config = DefaultMynaConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            hashed: vec![],
            signature: vec![],
            public_key_n: self.public_key_n.clone(),
            _f: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // todo read from config file
        let range_config = RangeConfig::configure(meta, Vertical, &[10], &[1], 10, 17, 0, 18);
        // todo read public_key_bits from config file
        let signature_verification_config = SignatureVerificationConfig::configure(range_config.clone(), 2048);
        let instances = meta.instance_column();

        DefaultMynaConfig {
            signature_verification_config,
            instances
        }
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use halo2_base::halo2_proofs::dev::MockProver;
    use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
    use halo2_base::{
        gates::{
            flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions,
        },
        utils::PrimeField,
    };
    use rand::thread_rng;
    use rand::Rng;
    use rsa::BigUint;
    use rsa::{Hash, PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
    use sha2::{Digest, Sha256};

    #[test]
    fn test_signature_verification() {
        let bits = 2048;

        // 1. Generate a key pair.
        let mut rng = thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        // 2. Uniformly sample a message.
        let mut msg: [u8; 128] = [0; 128];
        for x in &mut msg[..] {
            *x = rng.gen();
        }

        // 3. Compute the SHA256 hash of `msg`.
        let hashed_msg = Sha256::digest(&msg);

        // 4. Generate a pkcs1v15 signature.
        let padding = PaddingScheme::PKCS1v15Sign {
            hash: Some(Hash::SHA2_256),
        };
        let mut sign = private_key
            .sign(padding, &hashed_msg)
            .expect("fail to sign a hashed message.");

        // 5. Generate a SignatureVerificationConfig

        // let range_config = RangeConfig::configure(meta, Vertical, &[10], &[1], 10, 17, 0, 18);

        // let signature_verification_config =
        //     SignatureVerificationConfig::configure(range_config, bits as usize);
    }
}
