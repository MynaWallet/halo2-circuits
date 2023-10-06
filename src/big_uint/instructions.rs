use crate::{AssignedBigUint, Fresh, Muled, RangeType, RefreshAux};
use halo2_base::gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateChip, RangeChip};
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::plonk::Error;
use halo2_base::{utils::BigPrimeField, AssignedValue, Context};
use num_bigint::BigUint;

pub trait BigUintInstructions<F: BigPrimeField> {
    /// Return [`FlexGateConfig`]
    fn gate(&self) -> &GateChip<F>;
    /// Return [`RangeConfig`]
    fn range(&self) -> &RangeChip<F>;

    /// Return limb bits.
    fn limb_bits(&self) -> usize;

    /// Assigns a variable [`AssignedBigUint`] whose [`RangeType`] is [`Fresh`].
    fn assign_integer(
        &self,
        ctx: &mut Context<F>,
        value: Value<BigUint>,
        bit_len: usize,
    ) -> Result<AssignedBigUint<F, Fresh>, Error>;

    /// Assigns a constant [`AssignedBigUint`] whose [`RangeType`] is [`Fresh`].
    fn assign_constant(
        &self,
        ctx: &mut Context<F>,
        value: BigUint,
    ) -> Result<AssignedBigUint<F, Fresh>, Error>;

    /// Assigns the maximum integer whose number of limbs is `num_limbs`.
    fn max_value(
        &self,
        ctx: &mut Context<F>,
        num_limbs: usize,
    ) -> Result<AssignedBigUint<F, Fresh>, Error>;

    /// Converts a [`Muled`] type integer to a [`Fresh`] type integer.
    fn refresh(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Muled>,
        aux: &RefreshAux,
    ) -> Result<AssignedBigUint<F, Fresh>, Error>;

    /// Given a bit value `sel`, return `a` if `a`=1 and `b` otherwise.
    fn select<T: RangeType>(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, T>,
        b: &AssignedBigUint<F, T>,
        sel: &AssignedValue<F>,
    ) -> Result<AssignedBigUint<F, T>, Error>;

    /// Given two inputs `a,b`, performs the addition `a + b`.
    fn add(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedBigUint<F, Fresh>, Error>;

    /// Given two inputs `a,b`, performs the subtraction `a - b`.
    /// The result is correct iff `a>=b`.
    fn sub_unsafe(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
    ) -> Result<(AssignedBigUint<F, Fresh>, AssignedValue<F>), Error>;

    /// Given two inputs `a,b`, performs the multiplication `a * b`.
    fn mul(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedBigUint<F, Muled>, Error>;

    /// Given a inputs `a`, performs the square `a^2`.
    fn square(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedBigUint<F, Muled>, Error>;

    /// Given two inputs `a,b` and a modulus `n`, performs the modular addition `a + b mod n`.
    fn add_mod(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
        n: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedBigUint<F, Fresh>, Error>;

    /// Given two inputs `a,b` and a modulus `n`, performs the modular subtraction `a - b mod n`.
    fn sub_mod(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
        n: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedBigUint<F, Fresh>, Error>;

    /// Given two inputs `a,b` and a modulus `n`, performs the modular multiplication `a * b mod n`.
    fn mul_mod(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
        n: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedBigUint<F, Fresh>, Error>;

    /// Given a input `a` and a modulus `n`, performs the modular square `a^2 mod n`.
    fn square_mod(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        n: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedBigUint<F, Fresh>, Error>;

    /// Given a base `a`, a variable exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    fn pow_mod(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        e: &AssignedValue<F>,
        n: &AssignedBigUint<F, Fresh>,
        exp_bits: usize,
    ) -> Result<AssignedBigUint<F, Fresh>, Error>;

    /// Given a base `a`, a fixed exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    fn pow_mod_fixed_exp(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        e: &BigUint,
        n: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedBigUint<F, Fresh>, Error>;

    /// Returns an assigned bit representing whether `a` is zero or not.
    fn is_zero(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error>;

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn is_equal_fresh(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error>;

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Muled`].
    fn is_equal_muled(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Muled>,
        b: &AssignedBigUint<F, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<AssignedValue<F>, Error>;

    /// Returns an assigned bit representing whether `a` is less than `b` (`a<b`).
    fn is_less_than(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error>;

    /// Returns an assigned bit representing whether `a` is less than or equal to `b` (`a<=b`).
    fn is_less_than_or_equal(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error>;

    /// Returns an assigned bit representing whether `a` is greater than `b` (`a>b`).
    fn is_greater_than(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error>;

    /// Returns an assigned bit representing whether `a` is greater than or equal to `b` (`a>=b`).
    fn is_greater_than_or_equal(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error>;

    /// Returns an assigned bit representing whether `a` is in the order-`n` finite field.
    fn is_in_field(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
    ) -> Result<AssignedValue<F>, Error>;

    /// Assert that an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn assert_equal_fresh(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
    ) -> Result<(), Error>;

    /// Assert that an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn assert_equal_muled(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Muled>,
        b: &AssignedBigUint<F, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<(), Error>;

    /// Assert that an assigned bit representing whether `a` is in the order-`n` finite field.
    fn assert_in_field(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedBigUint<F, Fresh>,
        b: &AssignedBigUint<F, Fresh>,
    ) -> Result<(), Error>;
}
