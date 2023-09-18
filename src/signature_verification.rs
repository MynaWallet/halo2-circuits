use halo2_base::halo2_proofs::plonk::Error;
use halo2_base::{
    gates::{range::RangeConfig, GateInstructions},
    utils::PrimeField,
    Context,
};
use halo2_base::{AssignedValue, QuantumCell};
use halo2_rsa::{
    AssignedRSAPublicKey, AssignedRSASignature, RSAConfig, RSAInstructions, RSAPublicKey,
    RSASignature,
};

/// Configuration to verify the RSA signature.
#[derive(Debug, Clone)]
pub struct SignVerifyConfig<F: PrimeField> {
    /// Configuration for [`RSAConfig`].
    pub rsa_config: RSAConfig<F>,
}

pub const LIMB_BITS: usize = 64;

impl<F: PrimeField> SignVerifyConfig<F> {
    /// Construct a new [`SignVerifyConfig`].
    ///
    /// # Arguments
    /// * `range_config` - a configuration for [`RangeConfig`].
    /// * `public_key_bits` - the number of bits of RSA public key.
    /// # Return values
    /// Return a new [`SignVerifyConfig`].
    pub fn configure(range_config: RangeConfig<F>, public_key_bits: usize) -> Self {
        let biguint_config = halo2_rsa::BigUintConfig::construct(range_config, LIMB_BITS);
        let rsa_config = RSAConfig::construct(biguint_config, public_key_bits, 5);
        Self { rsa_config }
    }

    /// Assign the given RSA public key.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_key` - an RSA public key.
    /// # Return values
    /// Return an assigned RSA public key.
    pub fn assign_public_key<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        public_key: RSAPublicKey<F>,
    ) -> Result<AssignedRSAPublicKey<'v, F>, Error> {
        self.rsa_config.assign_public_key(ctx, public_key)
    }

    /// Assign the given RSA signature.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `signature` - an RSA signature.
    /// # Return values
    /// Return an assigned RSA signature.
    pub fn assign_signature<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        signature: RSASignature<F>,
    ) -> Result<AssignedRSASignature<'v, F>, Error> {
        self.rsa_config.assign_signature(ctx, signature)
    }

    /// Verify the given RSA signature with the given RSA public key and the given assgined bytes.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `hash_bytes` - a list of the assigned bytes.
    /// * `public_key` - an RSA public key.
    /// * `signature` - an RSA signature.
    /// # Return values
    /// Return a tuple of the assigned RSA public key and the assigned RSA signature.
    /// # Notes
    /// The constraints are not satisfied if the given RSA signature is invalid.
    pub fn verify_signature<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        hash_bytes: &[AssignedValue<'v, F>],
        public_key: RSAPublicKey<F>,
        signature: RSASignature<F>,
    ) -> Result<(AssignedRSAPublicKey<'a, F>, AssignedRSASignature<'a, F>), Error> {
        let gate = self.rsa_config.gate();
        let mut hash_bytes = hash_bytes.to_vec();
        hash_bytes.reverse();

        let bytes_bits = hash_bytes.len() * 8;
        let limb_bits = self.rsa_config.biguint_config().limb_bits;
        let limb_bytes = limb_bits / 8;
        let mut hashed_u64s = vec![];

        let bases = (0..limb_bytes)
            .map(|i| F::from(1u64 << (8 * i)))
            .map(QuantumCell::Constant)
            .collect::<Vec<QuantumCell<F>>>();

        for i in 0..(bytes_bits / limb_bits) {
            let left = hash_bytes[limb_bytes * i..limb_bytes * (i + 1)]
                .iter()
                .map(QuantumCell::Existing)
                .collect::<Vec<QuantumCell<F>>>();
            let sum = gate.inner_product(ctx, left, bases.clone());
            hashed_u64s.push(sum);
        }

        let public_key = self.rsa_config.assign_public_key(ctx, public_key)?;
        let signature = self.rsa_config.assign_signature(ctx, signature)?;
        let is_sign_valid = self.rsa_config.verify_pkcs1v15_signature(
            ctx,
            &public_key,
            &hashed_u64s,
            &signature,
        )?;
        gate.assert_is_const(ctx, &is_sign_valid, F::one());

        Ok((public_key, signature))
    }
}
