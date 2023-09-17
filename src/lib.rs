pub mod signature_verification;

use crate::signature_verification::*;

use halo2_base::halo2_proofs::circuit;
use halo2_base::halo2_proofs::circuit::{Cell, SimpleFloorPlanner, Value};
use halo2_base::halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Instance};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::utils::fe_to_biguint;
use halo2_base::utils::{decompose_fe_to_u64_limbs, value_to_option};
use halo2_base::{AssignedValue, QuantumCell};
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
use halo2_base::halo2_proofs::dev::CellValue::Assigned;
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
    pub hashed: BigUint, // A SHA256 hashed message
    pub signature: Vec<u8>, // A signature
    pub public_key_n: BigUint, // pub public_key: RSAPublicKey<F>,
    _f: PhantomData<F>,
}
impl<F: PrimeField> Circuit<F> for DefaultMynaCircuit<F> {
    type Config = DefaultMynaConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            hashed: self.hashed.clone(),
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
        meta.enable_equality(instances);

        DefaultMynaConfig {
            signature_verification_config,
            instances
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut first_pass = SKIP_FIRST_PASS;
        let signature_bytes = &self.signature;
        let public_key_n = &self.public_key_n;
        let hashed_message = &self.hashed;

        layouter.assign_region(|| "MynaWallet", |region| {
            // todo what is this?
            if first_pass {
                first_pass = false;
                return Ok(());
            }

            let ctx = &mut config.signature_verification_config.rsa_config.new_context(region);
            let e = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
            let public_key = RSAPublicKey::<F>::new(Value::known(public_key_n.clone()), e);
            let signature = RSASignature::<F>::new(Value::known(BigUint::from_bytes_be(&signature_bytes)));
            // todo is this ok?
            let hashed_msg_limbs = decompose_biguint::<F>(&hashed_message, 4, 256/4);
            let hashed_msg_assigned = hashed_msg_limbs.into_iter().map(|limb| config.signature_verification_config.rsa_config.gate().load_witness(ctx, Value::known(limb))).collect::<Vec<AssignedValue<F>>>();
            let (assigned_public_key, assigned_signature) = config.signature_verification_config.verify_signature(ctx, &hashed_msg_assigned, public_key, signature.clone())?;
            Ok(())
        },)?;

        Ok(())
    }
}

impl<F: PrimeField> DefaultMynaCircuit<F> {
    pub const DEFAULT_E: u128 = 65537;

    pub fn new(hashed: BigUint, signature: Vec<u8>, public_key_n: BigUint) -> Self {
        Self {
            hashed,
            signature,
            public_key_n,
            _f: PhantomData,
        }
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
