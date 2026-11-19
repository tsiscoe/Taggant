//! Two-Branch Uniform `Elligator2` map over Curve25519 ($v^2 = u^3 + 486662 u^2 + u$,
//! $Z = 2$ non-square) (`#![forbid(unsafe_code)]`).
//!
//! Critical security property:
//! For every Curve25519 coordinate $u \notin \{0, -A\}$ where $w = -2 u (u + A)$ is a quadratic
//! residue, there exist two distinct preimages in $[0, (p-1)/2]$:
//! - $r_1 = \sqrt{w} / (2u)$ (forward map branch $\varepsilon = +1$, $u = d$)
//! - $r_2 = \sqrt{w} / (2(u + A))$ (forward map branch $\varepsilon = -1$, $u = -d - A$)
//!
//! Selecting randomly between $r_1$ and $r_2$ and padding the unused top 2 bits with CSPRNG
//! entropy yields uniform 256-bit representatives `repr: [u8; 32]` with balanced $\varepsilon = \pm 1$.

use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use super::fe25519::{Fe25519, P_MINUS_1_DIV_2, ct_gt_le};

/// Curve25519 Montgomery parameter $A = 486662$.
const CURVE_A: u64 = 486662;

/// Forward `Elligator2` map $\iota: \{0,1\}^{256} \to \text{Curve25519 } u\text{-coordinate}$.
///
/// Clears the two padding bits (`repr[31] &= 0x3f`) and evaluates:
/// - $d = -A / (1 + 2 r^2)$
/// - $g(d) = d^3 + A d^2 + d$
/// - $\varepsilon = g(d)^{(p-1)/2}$
/// - Returns $u = d$ when $\varepsilon \neq -1$, and $u = -d - A$ when $\varepsilon = -1$.
pub fn elligator2_decode(repr: &[u8; 32]) -> [u8; 32] {
    let mut r_bytes = *repr;
    r_bytes[31] &= 0x3f;
    let r = Fe25519::from_bytes(&r_bytes);

    let a = Fe25519::from_u64(CURVE_A);
    let denom = Fe25519::ONE + (Fe25519::TWO * r.square());
    let d = (-a) * denom.inv();

    let gx = d * (d.square() + (a * d) + Fe25519::ONE);
    let eps = gx.pow_le_bytes(&P_MINUS_1_DIV_2);
    let is_non_square = eps.ct_eq(Fe25519::MINUS_ONE);

    let d_prime = -d - a;
    let u = Fe25519::ct_select(is_non_square, d_prime, d);
    u.to_bytes()
}

/// Evaluate the Legendre branch $\varepsilon(g(d))$ (`+1` or `-1` as `i8`) for diagnostics and
/// uniformity assertions.
pub fn elligator2_branch_sign(repr: &[u8; 32]) -> i8 {
    let mut r_bytes = *repr;
    r_bytes[31] &= 0x3f;
    let r = Fe25519::from_bytes(&r_bytes);

    let a = Fe25519::from_u64(CURVE_A);
    let denom = Fe25519::ONE + (Fe25519::TWO * r.square());
    let d = (-a) * denom.inv();
    let gx = d * (d.square() + (a * d) + Fe25519::ONE);
    let eps = gx.pow_le_bytes(&P_MINUS_1_DIV_2);
    if eps.ct_eq(Fe25519::MINUS_ONE) == 1 {
        -1
    } else {
        1
    }
}

/// Sample an ephemeral X25519 keypair whose public key admits a uniform two-branch `Elligator2`
/// representative `repr: [u8; 32]`.
pub fn elligator2_generate_ephemeral<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (StaticSecret, [u8; 32]) {
    let a = Fe25519::from_u64(CURVE_A);
    let neg_two = -Fe25519::TWO;

    loop {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let sk = StaticSecret::from(seed);
        seed.zeroize();

        let pk = PublicKey::from(&sk);
        let u = Fe25519::from_bytes(pk.as_bytes());
        let u_plus_a = u + a;

        if u.is_zero() || u_plus_a.is_zero() {
            continue;
        }

        let w = neg_two * u * u_plus_a;
        let Some(root_w) = w.sqrt() else {
            continue;
        };

        let mut rand_byte = [0u8; 1];
        rng.fill_bytes(&mut rand_byte);
        let branch_bit = rand_byte[0] & 1;
        let top2 = (rand_byte[0] >> 1) & 0b11;

        let r1 = root_w * (Fe25519::TWO * u).inv();
        let r2 = root_w * (Fe25519::TWO * u_plus_a).inv();
        let r_raw = Fe25519::ct_select(branch_bit, r2, r1);

        let r_bytes = r_raw.to_bytes();
        let needs_neg = ct_gt_le(&r_bytes, &P_MINUS_1_DIV_2);
        let r_canon = Fe25519::ct_select(needs_neg, -r_raw, r_raw);

        let mut repr = r_canon.to_bytes();
        repr[31] |= top2 << 6;

        // Defense-in-depth self-verification before releasing any canary capsule.
        if elligator2_decode(&repr) == *pk.as_bytes() {
            return (sk, repr);
        }
    }
}
