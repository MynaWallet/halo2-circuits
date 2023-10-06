use halo2_base::utils::{decompose_biguint as _decompose_biguint, BigPrimeField};
use num_bigint::{BigInt, BigUint};
use num_traits::Signed;

pub(crate) fn big_pow_mod(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    let one = BigUint::from(1usize);
    let two = BigUint::from(2usize);
    if b == &BigUint::default() {
        return one;
    }
    let is_odd = b % &two == one;
    let b = if is_odd { b - &one } else { b.clone() };
    let x = big_pow_mod(a, &(&b / &two), n);
    let x2 = (&x * &x) % n;
    if is_odd {
        (a * &x2) % n
    } else {
        x2
    }
}

// https://github.com/axiom-crypto/halo2-lib/blob/main/halo2-base/src/utils.rs#L61
pub(crate) fn decompose_u64_digits_to_limbs(
    e: impl IntoIterator<Item = u64>,
    number_of_limbs: usize,
    bit_len: usize,
) -> Vec<u64> {
    debug_assert!(bit_len < 64);

    let mut e = e.into_iter();
    // Mask to extract the bits from each digit
    let mask: u64 = (1u64 << bit_len) - 1u64;
    let mut u64_digit = e.next().unwrap_or(0);
    let mut rem = 64;

    // For each digit, we extract its individual limbs by repeatedly masking and shifting the digit based on how many bits we have left to extract.
    (0..number_of_limbs)
        .map(|_| match rem.cmp(&bit_len) {
            // If `rem` > `bit_len`, we mask the bits from the `u64_digit` to return the first limb.
            // We shift the digit to the right by `bit_len` bits and subtract `bit_len` from `rem`
            core::cmp::Ordering::Greater => {
                let limb = u64_digit & mask;
                u64_digit >>= bit_len;
                rem -= bit_len;
                limb
            }
            // If `rem` == `bit_len`, then we mask the bits from the `u64_digit` to return the first limb
            // We retrieve the next digit and reset `rem` to 64
            core::cmp::Ordering::Equal => {
                let limb = u64_digit & mask;
                u64_digit = e.next().unwrap_or(0);
                rem = 64;
                limb
            }
            // If `rem` < `bit_len`, we retrieve the next digit, mask it, and shift left `rem` bits from the `u64_digit` to return the first limb.
            // we shift the digit to the right by `bit_len` - `rem` bits to retrieve the start of the next limb and add 64 - bit_len to `rem` to get the remainder.
            core::cmp::Ordering::Less => {
                let mut limb = u64_digit;
                u64_digit = e.next().unwrap_or(0);
                limb |= (u64_digit & ((1u64 << (bit_len - rem)) - 1u64)) << rem;
                u64_digit >>= bit_len - rem;
                rem += 64 - bit_len;
                limb
            }
        })
        .collect()
}

pub fn decompose_biguint<F: BigPrimeField>(
    e: &BigUint,
    number_of_limbs: usize,
    limb_bits_len: usize,
) -> Vec<F> {
    assert!(limb_bits_len < 128);
    if limb_bits_len <= 64 {
        decompose_u64_digits_to_limbs(e.to_u64_digits(), number_of_limbs, limb_bits_len)
            .into_iter()
            .map(|v| F::from(v))
            .collect()
    } else {
        _decompose_biguint(e, number_of_limbs, limb_bits_len)
    }
}

pub fn decompose_bigint<F: BigPrimeField>(
    e: &BigInt,
    number_of_limbs: usize,
    limb_bits_len: usize,
) -> Vec<F> {
    if e.is_negative() {
        decompose_biguint::<F>(e.magnitude(), number_of_limbs, limb_bits_len)
            .into_iter()
            .map(|x| -x)
            .collect()
    } else {
        decompose_biguint(e.magnitude(), number_of_limbs, limb_bits_len)
    }
}
