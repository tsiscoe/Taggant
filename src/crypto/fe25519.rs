//! Constant-time field arithmetic over $\mathbb{F}_{2^{255}-19}$ in 5x51-bit radix
//! (`#![forbid(unsafe_code)]`).

use std::ops::{Add, Mul, Neg, Sub};

/// 51-bit limb mask: `(1 << 51) - 1`.
const MASK51: u64 = (1u64 << 51) - 1;

/// `2 * p` limb biases for subtraction without unsigned underflow.
const TWO_P0: u64 = 0x000f_ffff_ffff_ffda; // 2 * (2^51 - 19)
const TWO_PI: u64 = 0x000f_ffff_ffff_fffe; // 2 * (2^51 - 1)

/// Little-endian bytes of `p - 2 = 2^255 - 21` for Fermat inversion.
pub const P_MINUS_2: [u8; 32] = {
    let mut b = [0xff; 32];
    b[0] = 0xeb;
    b[31] = 0x7f;
    b
};

/// Little-endian bytes of `(p - 1) / 2 = 2^254 - 10` for Legendre symbol & canonical bound.
pub const P_MINUS_1_DIV_2: [u8; 32] = {
    let mut b = [0xff; 32];
    b[0] = 0xf6;
    b[31] = 0x3f;
    b
};

/// Little-endian bytes of `(p + 3) / 8 = 2^252 - 2` for Atkin square root.
pub const P_PLUS_3_DIV_8: [u8; 32] = {
    let mut b = [0xff; 32];
    b[0] = 0xfe;
    b[31] = 0x0f;
    b
};

/// Little-endian bytes of `(p - 1) / 4 = 2^253 - 5` for `sqrt(-1) = 2^((p - 1) / 4)`.
const P_MINUS_1_DIV_4: [u8; 32] = {
    let mut b = [0xff; 32];
    b[0] = 0xfb;
    b[31] = 0x1f;
    b
};

/// Element of `GF(2^255 - 19)` represented as 5 limbs in radix `2^51`.
#[derive(Debug, Clone, Copy)]
pub struct Fe25519(pub [u64; 5]);

impl Fe25519 {
    pub const ZERO: Self = Self([0, 0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0, 0]);
    pub const TWO: Self = Self([2, 0, 0, 0, 0]);
    pub const MINUS_ONE: Self = Self([
        (1u64 << 51) - 20,
        (1u64 << 51) - 1,
        (1u64 << 51) - 1,
        (1u64 << 51) - 1,
        (1u64 << 51) - 1,
    ]);

    /// Construct a field element from a `u64`.
    #[inline]
    pub const fn from_u64(v: u64) -> Self {
        let l0 = v & MASK51;
        let l1 = v >> 51;
        Self([l0, l1, 0, 0, 0])
    }

    /// Unpack 32 little-endian bytes into `Fe25519`, clearing bit 255 as required by RFC 7748.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let load8 = |offset: usize| -> u64 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(buf)
        };
        let l0 = load8(0) & MASK51;
        let l1 = (load8(6) >> 3) & MASK51;
        let l2 = (load8(12) >> 6) & MASK51;
        let l3 = (load8(19) >> 1) & MASK51;
        let l4 = (load8(24) >> 12) & MASK51;
        Self([l0, l1, l2, l3, l4])
    }

    /// Perform two weak carry passes so every limb stays below `2^51 + 38`.
    #[inline]
    fn carry_weak(mut h: [u64; 5]) -> Self {
        for _ in 0..2 {
            let c0 = h[0] >> 51;
            h[0] &= MASK51;
            h[1] += c0;
            let c1 = h[1] >> 51;
            h[1] &= MASK51;
            h[2] += c1;
            let c2 = h[2] >> 51;
            h[2] &= MASK51;
            h[3] += c2;
            let c3 = h[3] >> 51;
            h[3] &= MASK51;
            h[4] += c3;
            let c4 = h[4] >> 51;
            h[4] &= MASK51;
            h[0] += c4 * 19;
        }
        Self(h)
    }

    /// Canonically reduce modulo `2^255 - 19` and serialize to 32 little-endian bytes.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut h = Self::carry_weak(self.0).0;
        // One extra sweep ensures every limb is strictly `< 2^51` (`H in [0, 2^255 - 1]`).
        let c0 = h[0] >> 51;
        h[0] &= MASK51;
        h[1] += c0;
        let c1 = h[1] >> 51;
        h[1] &= MASK51;
        h[2] += c1;
        let c2 = h[2] >> 51;
        h[2] &= MASK51;
        h[3] += c2;
        let c3 = h[3] >> 51;
        h[3] &= MASK51;
        h[4] += c3;
        let c4 = h[4] >> 51;
        h[4] &= MASK51;
        h[0] += c4 * 19;
        let c0b = h[0] >> 51;
        h[0] &= MASK51;
        h[1] += c0b;

        // Constant-time conditional subtraction of `p = 2^255 - 19`:
        // `q = 1` iff `H + 19 >= 2^255`.
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;

        h[0] += 19 * q;
        for i in 0..4 {
            let c = h[i] >> 51;
            h[i] &= MASK51;
            h[i + 1] += c;
        }
        h[4] &= MASK51;

        let w0 = h[0] | (h[1] << 51);
        let w1 = (h[1] >> 13) | (h[2] << 38);
        let w2 = (h[2] >> 26) | (h[3] << 25);
        let w3 = (h[3] >> 39) | (h[4] << 12);

        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&w0.to_le_bytes());
        out[8..16].copy_from_slice(&w1.to_le_bytes());
        out[16..24].copy_from_slice(&w2.to_le_bytes());
        out[24..32].copy_from_slice(&w3.to_le_bytes());
        out
    }

    #[inline]
    pub fn square(self) -> Self {
        self * self
    }

    /// Constant-time conditional select: returns `a` if `choice == 1`, `b` if `choice == 0`.
    #[inline]
    pub fn ct_select(choice: u8, a: Self, b: Self) -> Self {
        let mask = (choice as u64).wrapping_neg(); // 0 -> 0, 1 -> u64::MAX
        Self([
            b.0[0] ^ (mask & (a.0[0] ^ b.0[0])),
            b.0[1] ^ (mask & (a.0[1] ^ b.0[1])),
            b.0[2] ^ (mask & (a.0[2] ^ b.0[2])),
            b.0[3] ^ (mask & (a.0[3] ^ b.0[3])),
            b.0[4] ^ (mask & (a.0[4] ^ b.0[4])),
        ])
    }

    /// Constant-time equality check on canonical encodings.
    pub fn ct_eq(self, rhs: Self) -> u8 {
        let a = self.to_bytes();
        let b = rhs.to_bytes();
        ct_eq_bytes(&a, &b)
    }

    /// Constant-time check whether `self == 0 (mod p)`.
    pub fn is_zero(self) -> bool {
        self.ct_eq(Self::ZERO) == 1
    }

    /// Constant-time square-and-multiply exponentiation for a 256-bit little-endian exponent.
    pub fn pow_le_bytes(self, exp: &[u8; 32]) -> Self {
        let mut res = Self::ONE;
        let mut base = self;
        for byte in exp {
            for bit in 0..8 {
                let flag = (byte >> bit) & 1;
                let prod = res * base;
                res = Self::ct_select(flag, prod, res);
                base = base.square();
            }
        }
        res
    }

    /// Multiplicative inverse in `GF(2^255 - 19)` (`self^(p-2)`). Returns `0` for `0`.
    pub fn inv(self) -> Self {
        self.pow_le_bytes(&P_MINUS_2)
    }

    /// Principal `sqrt(-1) = 2^((p - 1) / 4) mod p`.
    pub fn sqrt_m1() -> Self {
        Self::TWO.pow_le_bytes(&P_MINUS_1_DIV_4)
    }

    /// Compute a square root in `GF(2^255 - 19)` if one exists.
    pub fn sqrt(self) -> Option<Self> {
        let beta = self.pow_le_bytes(&P_PLUS_3_DIV_8);
        if beta.square().ct_eq(self) == 1 {
            return Some(beta);
        }
        let alt = beta * Self::sqrt_m1();
        if alt.square().ct_eq(self) == 1 {
            return Some(alt);
        }
        None
    }
}

impl Add for Fe25519 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self::carry_weak([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
    }
}

impl Sub for Fe25519 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self::carry_weak([
            self.0[0] + TWO_P0 - rhs.0[0],
            self.0[1] + TWO_PI - rhs.0[1],
            self.0[2] + TWO_PI - rhs.0[2],
            self.0[3] + TWO_PI - rhs.0[3],
            self.0[4] + TWO_PI - rhs.0[4],
        ])
    }
}

impl Neg for Fe25519 {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self::ZERO - self
    }
}

impl Mul for Fe25519 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let a = self.0;
        let b = rhs.0;

        let a0 = a[0] as u128;
        let a1 = a[1] as u128;
        let a2 = a[2] as u128;
        let a3 = a[3] as u128;
        let a4 = a[4] as u128;

        let b0 = b[0] as u128;
        let b1 = b[1] as u128;
        let b2 = b[2] as u128;
        let b3 = b[3] as u128;
        let b4 = b[4] as u128;

        let b1_19 = 19 * b1;
        let b2_19 = 19 * b2;
        let b3_19 = 19 * b3;
        let b4_19 = 19 * b4;

        let mut t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let mut t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let mut t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let mut t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let mut t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        let mask = MASK51 as u128;
        let c0 = t0 >> 51;
        t0 &= mask;
        t1 += c0;
        let c1 = t1 >> 51;
        t1 &= mask;
        t2 += c1;
        let c2 = t2 >> 51;
        t2 &= mask;
        t3 += c2;
        let c3 = t3 >> 51;
        t3 &= mask;
        t4 += c3;
        let c4 = t4 >> 51;
        t4 &= mask;
        t0 += c4 * 19;

        let mut r0 = t0 as u64;
        let c0b = r0 >> 51;
        r0 &= MASK51;
        let r1 = (t1 as u64) + c0b;

        Self::carry_weak([r0, r1, t2 as u64, t3 as u64, t4 as u64])
    }
}

impl PartialEq for Fe25519 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(*other) == 1
    }
}

impl Eq for Fe25519 {}

/// Constant-time byte-slice equality returning `1` if equal and `0` otherwise.
#[inline]
pub fn ct_eq_bytes(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    ((diff as u16).wrapping_sub(1) >> 15) as u8
}

/// Constant-time little-endian unsigned comparison: returns `1` iff `a > b`.
#[inline]
pub fn ct_gt_le(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    let mut gt = 0u8;
    let mut lt = 0u8;
    for i in (0..32).rev() {
        let undecided = (gt | lt) ^ 1;
        let is_gt = ((b[i] as i16 - a[i] as i16) >> 8) as u8 & 1;
        let is_lt = ((a[i] as i16 - b[i] as i16) >> 8) as u8 & 1;
        gt |= undecided & is_gt;
        lt |= undecided & is_lt;
    }
    gt
}
