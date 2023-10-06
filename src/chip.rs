use crate::{
    AssignedBigUint, AssignedRSAPubE, AssignedRSAPublicKey, AssignedRSASignature, BigUintConfig,
    Fresh, RSAInstructions, RSAPubE, RSAPublicKey, RSASignature,
};

use halo2_base::halo2_proofs::{circuit::Region, circuit::Value, plonk::Error};
use halo2_base::utils::fe_to_bigint;
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, BigPrimeField},
    AssignedValue, Context,
};

use num_bigint::BigUint;
use std::marker::PhantomData;

/// Configuration for [`RSAConfig`].
#[derive(Clone, Debug)]
pub struct RSAConfig<F: BigPrimeField> {
    /// Configuration for [`BigUintConfig`].
    biguint_config: BigUintConfig<F>,
    /// The default bit length of [`Fresh`] type integers in this chip.
    default_bits: usize,
    /// The bit length of exponents.
    exp_bits: usize,
}

impl<F: BigPrimeField> RSAInstructions<F> for RSAConfig<F> {
    /// Assigns a [`AssignedRSAPublicKey`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_key` - a RSA public key to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedRSAPublicKey`].
    fn assign_public_key<'v>(
        &self,
        ctx: &mut Context<F>,
        public_key: RSAPublicKey<F>,
    ) -> Result<AssignedRSAPublicKey<F>, Error> {
        let biguint_config = self.biguint_config();
        let n = biguint_config.assign_integer(ctx, public_key.n, self.default_bits)?;
        let e = match public_key.e {
            RSAPubE::Var(e) => {
                let assigned = self.gate().load_witness(ctx, e.map(|v| biguint_to_fe(&v)));
                self.range().range_check(ctx, &assigned, self.exp_bits);
                AssignedRSAPubE::Var(assigned)
            }
            RSAPubE::Fix(e) => AssignedRSAPubE::Fix(e),
        };
        Ok(AssignedRSAPublicKey::new(n, e))
    }

    /// Assigns a [`AssignedRSASignature`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `signature` - a RSA signature to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedRSASignature`].
    fn assign_signature<'v>(
        &self,
        ctx: &mut Context<F>,
        signature: RSASignature<F>,
    ) -> Result<AssignedRSASignature<F>, Error> {
        let biguint_config = self.biguint_config();
        let c = biguint_config.assign_integer(ctx, signature.c, self.default_bits)?;
        Ok(AssignedRSASignature::new(c))
    }

    /// Given a base `x`, a RSA public key (e,n), performs the modular power `x^e mod n`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `x` - a base integer.
    /// * `public_key` - an assigned RSA public key.
    ///
    /// # Return values
    /// Returns the modular power result `x^e mod n` as [`AssignedBigUint<F, Fresh>`].
    fn modpow_public_key<'v>(
        &self,
        ctx: &mut Context<F>,
        x: &AssignedBigUint<F, Fresh>,
        public_key: &AssignedRSAPublicKey<F>,
    ) -> Result<AssignedBigUint<F, Fresh>, Error> {
        let biguint_config = self.biguint_config();
        biguint_config.assert_in_field(ctx, x, &public_key.n)?;
        let powed = match &public_key.e {
            AssignedRSAPubE::Var(e) => {
                biguint_config.pow_mod(ctx, x, e, &public_key.n, self.exp_bits)
            }
            AssignedRSAPubE::Fix(e) => biguint_config.pow_mod_fixed_exp(ctx, x, e, &public_key.n),
        }?;
        Ok(powed)
    }

    /// Given a RSA public key, a message hashed with SHA256, and a pkcs1v15 signature, verifies the signature with the public key and the hashed messaged.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_key` - an assigned RSA public key.
    /// * `hashed_msg` - an assigned integer of the message hashed with SHA256.
    /// * `signature` - an assigned pkcs1v15 signature.
    ///
    /// # Return values
    /// Returns the assigned bit as [`AssignedValue<F>`].
    /// If `signature` is valid for `public_key` and `hashed_msg`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    fn verify_pkcs1v15_signature<'v>(
        &self,
        ctx: &mut Context<F>,
        public_key: &AssignedRSAPublicKey<F>,
        hashed_msg: &[AssignedValue<F>],
        signature: &AssignedRSASignature<F>,
    ) -> Result<AssignedValue<F>, Error> {
        assert_eq!(self.biguint_config.limb_bits(), 64);
        let gate = self.gate();
        let mut is_eq = gate.load_constant(ctx, F::one());
        let powed = self.modpow_public_key(ctx, &signature.c, public_key)?;
        let hash_len = hashed_msg.len();
        assert_eq!(hash_len, 4);
        // 1. Check hashed data
        // 64 * 4 = 256 bit, that is the first 4 numbers.
        for (limb, hash) in powed.limbs()[0..hash_len].iter().zip(hashed_msg.iter()) {
            let is_hash_eq = gate.is_equal(
                ctx,
                QuantumCell::Existing(limb),
                QuantumCell::Existing(hash),
            );
            is_eq = gate.and(
                ctx,
                QuantumCell::Existing(&is_eq),
                QuantumCell::Existing(&is_hash_eq),
            );
        }

        // 2. Check hash prefix and 1 byte 0x00
        // sha256/152 bit
        // 0b00110000001100010011000000001101000001100000100101100000100001100100100000000001011001010000001100000100000000100000000100000101000000000000010000100000
        let is_prefix_64_1_eq = gate.is_equal(
            ctx,
            QuantumCell::Existing(&powed.limbs()[hash_len]),
            QuantumCell::Constant(biguint_to_fe(&BigUint::from(217300885422736416u64))),
        );
        let is_prefix_64_2_eq = gate.is_equal(
            ctx,
            QuantumCell::Existing(&powed.limbs()[hash_len + 1]),
            QuantumCell::Constant(biguint_to_fe(&BigUint::from(938447882527703397u64))),
        );
        let is_eq = gate.and(
            ctx,
            QuantumCell::Existing(&is_eq),
            QuantumCell::Existing(&is_prefix_64_1_eq),
        );
        let is_eq = gate.and(
            ctx,
            QuantumCell::Existing(&is_eq),
            QuantumCell::Existing(&is_prefix_64_2_eq),
        );
        // remain 24 bit
        let u32_v: BigUint = BigUint::from(1usize) << 32;
        let (remain_low, remain_high) = powed
            .limb(hash_len + 2)
            .value()
            .map(|v| {
                let big_v = fe_to_biguint(v);
                let low = biguint_to_fe::<F>(&(&big_v % &u32_v));
                let high = biguint_to_fe::<F>(&(&big_v / &u32_v));
                (low, high)
            })
            .unzip();
        let range = self.range();
        let remain_low = gate.load_witness(ctx, remain_low);
        range.range_check(ctx, &remain_low, 32);
        let remain_high = gate.load_witness(ctx, remain_high);
        range.range_check(ctx, &remain_high, 32);
        let remain_concat = gate.mul_add(
            ctx,
            QuantumCell::Existing(&remain_high),
            QuantumCell::Constant(biguint_to_fe(&u32_v)),
            QuantumCell::Existing(&remain_low),
        );
        gate.assert_equal(
            ctx,
            QuantumCell::Existing(&powed.limbs()[hash_len + 2]),
            QuantumCell::Existing(&remain_concat),
        );
        let is_prefix_32_eq = gate.is_equal(
            ctx,
            QuantumCell::Existing(&remain_low),
            QuantumCell::Constant(biguint_to_fe(&BigUint::from(3158320u32))),
        );
        let is_eq = gate.and(
            ctx,
            QuantumCell::Existing(&is_eq),
            QuantumCell::Existing(&is_prefix_32_eq),
        );

        // 3. Check PS and em[1] = 1. the same code like golang std lib rsa.VerifyPKCS1v15
        let is_ff_32_eq = gate.is_equal(
            ctx,
            QuantumCell::Existing(&remain_high),
            QuantumCell::Constant(biguint_to_fe(&BigUint::from(4294967295u32))),
        );
        let mut is_eq = gate.and(
            ctx,
            QuantumCell::Existing(&is_eq),
            QuantumCell::Existing(&is_ff_32_eq),
        );
        let num_limbs = self.default_bits / self.biguint_config().limb_bits();
        for limb in powed.limbs()[(hash_len + 3)..(num_limbs - 1)].iter() {
            let is_ff_64_eq = gate.is_equal(
                ctx,
                QuantumCell::Existing(limb),
                QuantumCell::Constant(biguint_to_fe(&BigUint::from(18446744073709551615u64))),
            );
            is_eq = gate.and(
                ctx,
                QuantumCell::Existing(&is_eq),
                QuantumCell::Existing(&is_ff_64_eq),
            );
        }
        //562949953421311 = 0b1111111111111111111111111111111111111111111111111 = 0x00 || 0x01 || (0xff)^*
        let is_last_em_eq = gate.is_equal(
            ctx,
            QuantumCell::Existing(&powed.limbs()[num_limbs - 1]),
            QuantumCell::Constant(biguint_to_fe(&BigUint::from(562949953421311u64))),
        );
        let is_eq = gate.and(
            ctx,
            QuantumCell::Existing(&is_eq),
            QuantumCell::Existing(&is_last_em_eq),
        );
        Ok(is_eq.clone())
    }
}

impl<F: BigPrimeField> RSAConfig<F> {
    /// Creates new [`RSAConfig`] from [`BigUintInstructions`].
    ///
    /// # Arguments
    /// * biguint_config - a configuration for [`BigUintConfig`].
    /// * default_bits - the default bit length of [`Fresh`] type integers in this chip.
    /// * exp_bits - the bit length of exponents.
    ///
    /// # Return values
    /// Returns new [`RSAConfig`].
    pub fn construct(
        biguint_config: BigUintConfig<F>,
        default_bits: usize,
        exp_bits: usize,
    ) -> Self {
        Self {
            biguint_config,
            default_bits,
            exp_bits,
        }
    }

    /// Return [`Context<F>`]
    pub fn new_context(&self, witness_only: bool, context_id: usize) -> Context<F> {
        self.biguint_config.new_context(witness_only, context_id)
    }

    /// Getter for [`BigUintConfig`].
    pub fn biguint_config(&self) -> &BigUintConfig<F> {
        &self.biguint_config
    }

    /// Getter for [`FlexGateConfig`].
    pub fn gate(&self) -> &FlexGateConfig<F> {
        &self.biguint_config.gate()
    }

    /// Getter for [`RangeConfig`].
    pub fn range(&self) -> &RangeConfig<F> {
        &self.biguint_config.range()
    }
}
