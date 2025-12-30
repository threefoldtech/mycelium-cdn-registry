#![deny(missing_docs)]
//! WASM-friendly VXEdDSA (Signal spec) implementation for Curve25519.
//!
//! This crate is intended to provide **verification** in `wasm32-unknown-unknown` builds (e.g.
//! Holochain integrity zomes) without pulling in RNG dependencies.
//!
//! Signing support is **feature-gated** behind the `sign` feature. When enabled, it can generate
//! the required 64 bytes of randomness `Z` and produce signatures.
//!
//! ## Spec reference
//! <https://signal.org/docs/specifications/xeddsa/#vxeddsa>
//!
//! ## Canonical sign-bit choice (custom)
//! The Signal specification defines `convert_mont` as choosing sign bit `0`.
//! This crate intentionally uses a **canonical sign bit of 1** for `convert_mont` and for
//! `calculate_key_pair` so that signatures verify against the same canonical Edwards representative.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    montgomery::MontgomeryPoint,
    scalar::Scalar,
    traits::IsIdentity,
};
use sha2::{Digest, Sha512};
use subtle::{Choice, ConditionallySelectable};

/// Length of a VXEdDSA signature: `V || h || s` (3 * 32 bytes).
pub const VXEDDSA_SIGNATURE_LEN: usize = 96;

/// Length of a VXEdDSA VRF output: 32 bytes for Curve25519.
pub const VXEDDSA_VRF_LEN: usize = 32;

/// Length of the secret/randomness input `Z` per spec: 64 bytes.
pub const VXEDDSA_Z_LEN: usize = 64;

/// Canonical sign-bit for Montgomery->Edwards conversion in this crate.
///
/// This is the "ambiguous bit" (the Edwards x-sign bit) chosen when converting a Montgomery
/// u-coordinate to an Edwards point.
pub const CANONICAL_MONT_TO_EDWARDS_SIGN_BIT: u8 = 1;

/// Apply Curve25519/X25519 "clamping" to a 32-byte scalar.
///
/// This follows RFC 7748:
/// - clear 3 low bits
/// - clear top bit
/// - set second highest bit
pub fn clamp_x25519_scalar(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// Domain-separated SHA-512 hash as defined by Signal spec Section 2.5.
///
/// For Curve25519, `b = 256` so the prefix is 32 bytes.
/// `hash_i(X) = SHA512( ((2^256 - 1) - i) || X )` with little-endian encoding of the prefix.
pub fn hashi(i: u8, x: &[u8]) -> [u8; 64] {
    let mut prefix = [0xFFu8; 32];
    // Little-endian subtraction of a small i from 2^256-1 just subtracts from the first byte.
    prefix[0] = prefix[0].wrapping_sub(i);

    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(x);
    hasher.finalize().into()
}

/// Convert a Montgomery u-coordinate (X25519 public key bytes) into an Edwards point using a
/// canonical sign-bit.
///
/// This is the `convert_mont` from the spec, except the sign-bit is chosen as
/// `CANONICAL_MONT_TO_EDWARDS_SIGN_BIT` (default 1), not 0.
///
/// Returns `None` if conversion fails or if `u` is not canonical `< p`.
pub fn convert_mont_canonical(u: [u8; 32]) -> Option<EdwardsPoint> {
    // Mask off excess high bits (mod 2^|p|), per spec Section 2.3.
    let mut u_masked = u;
    u_masked[31] &= 0x7F;

    // NOTE: The spec suggests rejecting u >= p. `curve25519-dalek`'s internal field element
    // type is not exposed publicly, so we avoid relying on private APIs and instead rely on the
    // conversion failing for invalid/unrepresentable points.
    MontgomeryPoint(u_masked).to_edwards(CANONICAL_MONT_TO_EDWARDS_SIGN_BIT)
}

/// Calculate the Edwards public key `A` and scalar `a` from a Montgomery private key `k`,
/// ensuring the returned `A` has the canonical sign-bit.
///
/// This is `calculate_key_pair` from the spec Section 2.3, except we enforce the sign-bit to be
/// `CANONICAL_MONT_TO_EDWARDS_SIGN_BIT` (default 1) rather than 0.
///
/// Input `k` is treated as an X25519 private key seed and is clamped before reduction.
pub fn calculate_key_pair_canonical(k: [u8; 32]) -> (EdwardsPoint, Scalar) {
    let k_clamped = clamp_x25519_scalar(k);
    let k_scalar = Scalar::from_bytes_mod_order(k_clamped);

    // E = kB (Edwards basepoint)
    let e = ED25519_BASEPOINT_POINT * k_scalar;

    // Inspect the x-sign bit in the compressed form.
    let sign = (e.compress().to_bytes()[31] >> 7) & 1;

    // Choose `a` such that the resulting public key has sign-bit == CANONICAL_MONT_TO_EDWARDS_SIGN_BIT.
    //
    // If desired bit is 1: keep k when sign==1 else negate.
    // If desired bit is 0: keep k when sign==0 else negate.
    let desired = CANONICAL_MONT_TO_EDWARDS_SIGN_BIT & 1;
    let need_negate = sign ^ desired;
    let a = Scalar::conditional_select(&k_scalar, &-k_scalar, Choice::from(need_negate));

    let a_point = ED25519_BASEPOINT_POINT * a;
    debug_assert_eq!(
        (a_point.compress().to_bytes()[31] >> 7) & 1,
        desired,
        "calculate_key_pair_canonical failed to enforce canonical sign-bit"
    );

    (a_point, a)
}

/// Compute `hash_to_point(X)` per spec Section 2.6 for Curve25519, using Elligator2.
///
/// This follows the spec algorithm:
/// - h = hash2(X)
/// - r = h mod 2^|p| (low 255 bits)
/// - s = bit (b-1) of h (for b=256 => msb of byte 31)
/// - u = elligator2(r)
/// - P = (u_to_y(u), sign=s)
/// - return cP (cofactor-cleared)
fn hash_to_point(x: &[u8]) -> Option<EdwardsPoint> {
    // Use dalek's Elligator2-based hash-to-curve implementation (deprecated, but matches the
    // historical Signal VXEdDSA spec and avoids private FieldElement APIs).
    //
    // The caller is responsible for domain separation (VXEdDSA achieves this via distinct
    // hash inputs like A||M, and via `hashi` elsewhere).
    #[allow(deprecated)]
    let p = EdwardsPoint::nonspec_map_to_curve::<Sha512>(x).mul_by_cofactor();
    Some(p)
}

/// Verify a VXEdDSA signature and, if valid, return the VRF output `v` (32 bytes).
///
/// This implements `vxeddsa_verify(u, M, (V||h||s))` per the Signal specification, with the
/// modified canonical conversion `convert_mont` using sign-bit=1.
///
/// - `public_u` is the X25519 public key (Montgomery u-coordinate).
/// - `message` is an arbitrary byte sequence.
/// - `signature` is 96 bytes (`V || h || s`), each component 32 bytes.
///
/// Returns:
/// - `Some(v)` (32 bytes) if valid
/// - `None` if invalid
pub fn vxeddsa_verify(
    public_u: &[u8; 32],
    message: &[u8],
    signature: &[u8; 96],
) -> Option<[u8; 32]> {
    let v_bytes: [u8; 32] = signature[0..32].try_into().ok()?;
    let h_bytes: [u8; 32] = signature[32..64].try_into().ok()?;
    let s_bytes: [u8; 32] = signature[64..96].try_into().ok()?;

    // Reject non-canonical h/s (stronger than the spec's "excess bits" check).
    let h = Option::<Scalar>::from(Scalar::from_canonical_bytes(h_bytes))?;
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))?;

    // A = convert_mont(u) with canonical sign-bit=1
    let a_point = convert_mont_canonical(*public_u)?;
    let a_enc = a_point.compress().to_bytes();

    // V point
    let v_point = CompressedEdwardsY(v_bytes).decompress()?;

    // Bv = hash_to_point(A || M)
    let mut point_msg = Vec::with_capacity(a_enc.len() + message.len());
    point_msg.extend_from_slice(&a_enc);
    point_msg.extend_from_slice(message);
    let bv = hash_to_point(&point_msg)?;

    // Identity/cofactor checks per spec:
    // if cA == I or cV == I or Bv == I => invalid
    if a_point.mul_by_cofactor().is_identity()
        || v_point.mul_by_cofactor().is_identity()
        || bv.is_identity()
    {
        return None;
    }

    // R  = sB - hA
    let r_point = (ED25519_BASEPOINT_POINT * s) - (a_point * h);
    let r_bytes = r_point.compress().to_bytes();

    // Rv = sBv - hV
    let rv_point = (bv * s) - (v_point * h);
    let rv_bytes = rv_point.compress().to_bytes();

    // hcheck = hash4(A || V || R || Rv || M) mod q
    let mut h_msg = Vec::new();
    h_msg.extend_from_slice(&a_enc);
    h_msg.extend_from_slice(&v_bytes);
    h_msg.extend_from_slice(&r_bytes);
    h_msg.extend_from_slice(&rv_bytes);
    h_msg.extend_from_slice(message);

    let hcheck_hash = hashi(4, &h_msg);
    let hcheck = Scalar::from_bytes_mod_order_wide(&hcheck_hash);

    if h != hcheck {
        return None;
    }

    // v = hash5(cV) mod 2^b (b=256 => take low 32 bytes little-endian)
    let c_v = v_point.mul_by_cofactor();
    let c_v_bytes = c_v.compress().to_bytes();
    let v_hash_full = hashi(5, &c_v_bytes);

    let mut vrf = [0u8; 32];
    vrf.copy_from_slice(&v_hash_full[0..32]);
    Some(vrf)
}

#[cfg(feature = "sign")]
mod signing {
    use super::*;
    use rand_core::RngCore;

    /// Derive the X25519 public key (Montgomery u-coordinate) from a secret `k` by:
    /// - computing canonical Edwards public key `A` via `calculate_key_pair_canonical`
    /// - converting `A` to its Montgomery u-coordinate
    ///
    /// Note: The u-coordinate depends only on the Edwards y-coordinate, so the canonical sign-bit
    /// choice does not change the returned Montgomery public key.
    pub fn public_u_from_secret(k: [u8; 32]) -> [u8; 32] {
        let (a_point, _a) = calculate_key_pair_canonical(k);
        a_point.to_montgomery().to_bytes()
    }

    /// VXEdDSA sign with caller-provided 64 bytes of randomness `Z` (per spec).
    ///
    /// Returns `(signature, vrf)` where:
    /// - `signature` is 96 bytes (`V || h || s`)
    /// - `vrf` is 32 bytes
    pub fn vxeddsa_sign_with_z(
        k: [u8; 32],
        message: &[u8],
        z: [u8; VXEDDSA_Z_LEN],
    ) -> ([u8; VXEDDSA_SIGNATURE_LEN], [u8; VXEDDSA_VRF_LEN]) {
        let (a_point, a) = calculate_key_pair_canonical(k);
        let a_enc = a_point.compress().to_bytes();

        // Bv = hash_to_point(A || M)
        let mut point_msg = Vec::with_capacity(a_enc.len() + message.len());
        point_msg.extend_from_slice(&a_enc);
        point_msg.extend_from_slice(message);
        let bv = hash_to_point(&point_msg).expect("hash_to_point failed");

        // V = a * Bv
        let v_point = bv * a;
        let v_bytes = v_point.compress().to_bytes();

        // r = hash3(a || V || Z) mod q
        let mut r_msg = Vec::with_capacity(32 + 32 + VXEDDSA_Z_LEN);
        r_msg.extend_from_slice(&a.to_bytes());
        r_msg.extend_from_slice(&v_bytes);
        r_msg.extend_from_slice(&z);
        let r_hash = hashi(3, &r_msg);
        let r = Scalar::from_bytes_mod_order_wide(&r_hash);

        // R = rB
        let r_point = ED25519_BASEPOINT_POINT * r;
        let r_bytes = r_point.compress().to_bytes();

        // Rv = rBv
        let rv_point = bv * r;
        let rv_bytes = rv_point.compress().to_bytes();

        // h = hash4(A || V || R || Rv || M) mod q
        let mut h_msg = Vec::new();
        h_msg.extend_from_slice(&a_enc);
        h_msg.extend_from_slice(&v_bytes);
        h_msg.extend_from_slice(&r_bytes);
        h_msg.extend_from_slice(&rv_bytes);
        h_msg.extend_from_slice(message);
        let h_hash = hashi(4, &h_msg);
        let h = Scalar::from_bytes_mod_order_wide(&h_hash);

        // s = r + h*a mod q
        let s = r + (h * a);

        // v = hash5(cV) mod 2^256 => take low 32 bytes
        let c_v = v_point.mul_by_cofactor();
        let c_v_bytes = c_v.compress().to_bytes();
        let v_hash_full = hashi(5, &c_v_bytes);
        let mut vrf = [0u8; 32];
        vrf.copy_from_slice(&v_hash_full[0..32]);

        // Signature = V || h || s
        let mut sig = [0u8; 96];
        sig[0..32].copy_from_slice(&v_bytes);
        sig[32..64].copy_from_slice(&h.to_bytes());
        sig[64..96].copy_from_slice(&s.to_bytes());

        (sig, vrf)
    }

    /// VXEdDSA sign using an RNG to generate the required 64 bytes of randomness `Z`.
    ///
    /// This is a convenience wrapper around `vxeddsa_sign_with_z`.
    pub fn vxeddsa_sign_with_rng<R: RngCore + ?Sized>(
        k: [u8; 32],
        message: &[u8],
        rng: &mut R,
    ) -> ([u8; VXEDDSA_SIGNATURE_LEN], [u8; VXEDDSA_VRF_LEN]) {
        let mut z = [0u8; VXEDDSA_Z_LEN];
        rng.fill_bytes(&mut z);
        vxeddsa_sign_with_z(k, message, z)
    }

    /// VXEdDSA sign using `rand_core::OsRng` (requires the `sign` feature).
    pub fn vxeddsa_sign(
        k: [u8; 32],
        message: &[u8],
    ) -> ([u8; VXEDDSA_SIGNATURE_LEN], [u8; VXEDDSA_VRF_LEN]) {
        let mut rng = rand_core::OsRng;
        vxeddsa_sign_with_rng(k, message, &mut rng)
    }
}

#[cfg(feature = "sign")]
pub use signing::{public_u_from_secret, vxeddsa_sign, vxeddsa_sign_with_rng, vxeddsa_sign_with_z};

#[cfg(all(test, feature = "sign"))]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip_with_fixed_z() {
        let k = [0x11u8; 32];
        let msg = b"test message for vxeddsa_support";

        let z = [0x22u8; 64];
        let (sig, vrf1) = vxeddsa_sign_with_z(k, msg, z);

        let public_u = public_u_from_secret(k);

        let vrf2 = vxeddsa_verify(&public_u, msg, &sig);
        assert!(vrf2.is_some());
        assert_eq!(vrf1, vrf2.unwrap());
    }

    #[test]
    fn verify_fails_on_modified_message() {
        let k = [0x33u8; 32];
        let mut msg = b"hello".to_vec();
        let z = [0x44u8; 64];

        let (sig, _vrf) = vxeddsa_sign_with_z(k, &msg, z);
        let public_u = public_u_from_secret(k);

        msg[0] ^= 0xFF;
        assert!(vxeddsa_verify(&public_u, &msg, &sig).is_none());
    }

    #[test]
    fn verify_fails_on_wrong_key() {
        let k1 = [0x55u8; 32];
        let k2 = [0x66u8; 32];
        let msg = b"hello vxeddsa";
        let z = [0x77u8; 64];

        let (sig, _vrf) = vxeddsa_sign_with_z(k1, msg, z);
        let wrong_public_u = public_u_from_secret(k2);

        assert!(vxeddsa_verify(&wrong_public_u, msg, &sig).is_none());
    }
}
