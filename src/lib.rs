pub mod big_uint;
mod instructions;
use big_uint::*;
pub use instructions::*;
mod chip;
pub use chip::*;

use std::marker::PhantomData;

pub use big_uint::*;

use halo2_base::halo2_proofs::{circuit::Value, plonk::Error};
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, BigPrimeField},
    AssignedValue, Context,
};
use halo2_ecc::bigint::{
    big_is_equal, big_is_zero, big_less_than, carry_mod, mul_no_carry, negative, select, sub,
    CRTInteger, FixedCRTInteger, FixedOverflowInteger, OverflowInteger,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, Zero};

/// A parameter `e` in the RSA public key that is about to be assigned.
#[derive(Clone, Debug)]
pub enum RSAPubE {
    /// A variable parameter `e`.
    Var(Value<BigUint>),
    /// A fixed parameter `e`.
    Fix(BigUint),
}

/// A parameter `e` in the assigned RSA public key.
#[derive(Clone, Debug)]
pub enum AssignedRSAPubE<F: BigPrimeField> {
    /// A variable parameter `e`.
    Var(AssignedValue<F>),
    /// A fixed parameter `e`.
    Fix(BigUint),
}

/// RSA public key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct RSAPublicKey<F: BigPrimeField> {
    /// a modulus parameter
    pub n: Value<BigUint>,
    /// an exponent parameter
    pub e: RSAPubE,
    _f: PhantomData<F>,
}

impl<F: BigPrimeField> RSAPublicKey<F> {
    /// Creates new [`RSAPublicKey`] from `n` and `e`.
    ///
    /// # Arguments
    /// * n - an integer of `n`.
    /// * e - a parameter `e`.
    ///
    /// # Return values
    /// Returns new [`RSAPublicKey`].
    pub fn new(n: Value<BigUint>, e: RSAPubE) -> Self {
        Self {
            n,
            e,
            _f: PhantomData,
        }
    }

    pub fn without_witness(fix_e: BigUint) -> Self {
        let n = Value::unknown();
        let e = RSAPubE::Fix(fix_e);
        Self {
            n,
            e,
            _f: PhantomData,
        }
    }
}

/// An assigned RSA public key.
#[derive(Clone, Debug)]
pub struct AssignedRSAPublicKey<F: BigPrimeField> {
    /// a modulus parameter
    pub n: AssignedBigUint<F, Fresh>,
    /// an exponent parameter
    pub e: AssignedRSAPubE<F>,
}

impl<'v, F: BigPrimeField> AssignedRSAPublicKey<F> {
    /// Creates new [`AssignedRSAPublicKey`] from assigned `n` and `e`.
    ///
    /// # Arguments
    /// * n - an assigned integer of `n`.
    /// * e - an assigned parameter `e`.
    ///
    /// # Return values
    /// Returns new [`AssignedRSAPublicKey`].
    pub fn new(n: AssignedBigUint<F, Fresh>, e: AssignedRSAPubE<F>) -> Self {
        Self { n, e }
    }
}

/// RSA signature that is about to be assigned.
#[derive(Clone, Debug)]
pub struct RSASignature<F: BigPrimeField> {
    /// an integer of the signature.
    pub c: Value<BigUint>,
    _f: PhantomData<F>,
}

impl<F: BigPrimeField> RSASignature<F> {
    /// Creates new [`RSASignature`] from its integer.
    ///
    /// # Arguments
    /// * c - an integer of the signature.
    ///
    /// # Return values
    /// Returns new [`RSASignature`].
    pub fn new(c: Value<BigUint>) -> Self {
        Self { c, _f: PhantomData }
    }

    pub fn without_witness() -> Self {
        let c = Value::unknown();
        Self { c, _f: PhantomData }
    }
}

/// An assigned RSA signature.
#[derive(Clone, Debug)]
pub struct AssignedRSASignature<F: BigPrimeField> {
    /// an integer of the signature.
    pub c: AssignedBigUint<F, Fresh>,
}

impl<F: BigPrimeField> AssignedRSASignature<F> {
    /// Creates new [`AssignedRSASignature`] from its assigned integer.
    ///
    /// # Arguments
    /// * c - an assigned integer of the signature.
    ///
    /// # Return values
    /// Returns new [`AssignedRSASignature`].
    pub fn new(c: AssignedBigUint<F, Fresh>) -> Self {
        Self { c }
    }
}
