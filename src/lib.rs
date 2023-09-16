pub mod signature_verification;

use crate::signature_verification::*;

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
