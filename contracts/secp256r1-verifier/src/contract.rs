//! # Accesly — Secp256r1 / WebAuthn Verifier
//!
//! Verifier compartido para passkeys (biométrico del dispositivo).
//! Uso exclusivo para SEP-10 challenge-response. No se usa en transacciones
//! normales — para esas, el ed25519 verifier maneja la auth.
//!
//! key_data layout: 65 bytes de pubkey secp256r1 (uncompressed) + credential ID variable
//! sig_data: XDR-encoded WebAuthnSigData { authenticator_data, client_data_json, signature }
use soroban_sdk::{contract, contractimpl, xdr::FromXdr, Bytes, BytesN, Env, Vec};
use stellar_accounts::verifiers::{
    utils::extract_from_bytes,
    webauthn::{self, WebAuthnSigData},
    Verifier,
};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;

    use hex_literal::hex;
    use p256::{
        ecdsa::{signature::hazmat::PrehashSigner, Signature as P256Sig, SigningKey as P256SigningKey},
        elliptic_curve::sec1::ToEncodedPoint,
        SecretKey as P256SecretKey,
    };
    use soroban_sdk::{xdr::ToXdr, Bytes, BytesN, Env};
    use stellar_accounts::verifiers::webauthn::{
        WebAuthnSigData, AUTH_DATA_FLAGS_BE, AUTH_DATA_FLAGS_BS, AUTH_DATA_FLAGS_UP,
        AUTH_DATA_FLAGS_UV,
    };
    use stellar_accounts::verifiers::utils::base64_url_encode;

    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    const SECRET: [u8; 32] = [
        33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
    ];

    /// Devuelve (pubkey_bytes_65, sig_bytes_64) — key como Bytes para coincidir
    /// con `type KeyData = Bytes` del contrato.
    fn sign_digest(e: &Env, digest: &[u8; 32]) -> (Bytes, BytesN<64>) {
        let secret = P256SecretKey::from_slice(&SECRET).unwrap();
        let signing_key = P256SigningKey::from(&secret);
        let pubkey = secret.public_key().to_encoded_point(false).to_bytes().to_vec();
        let mut pub_arr = [0u8; 65];
        pub_arr.copy_from_slice(&pubkey);

        let sig: P256Sig = signing_key.sign_prehash(digest).unwrap();
        let sig_norm = sig.normalize_s().unwrap_or(sig);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_norm.to_bytes());

        (Bytes::from_slice(e, &pub_arr), BytesN::from_array(e, &sig_arr))
    }

    fn make_authenticator_data(e: &Env, flags: u8) -> Bytes {
        let mut data = [0u8; 37]; // mínimo: 32 rpIdHash + 1 flags + 4 counter
        data[32] = flags;
        Bytes::from_array(e, &data)
    }

    fn make_client_data(e: &Env, challenge_b64: &str) -> Bytes {
        let json = std::format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"https://accesly.app","crossOrigin":false}}"#
        );
        Bytes::from_slice(e, json.as_bytes())
    }

    /// Construye un WebAuthnSigData válido y firmado para el payload dado.
    /// Devuelve (signature_payload, key_data: Bytes(65), sig_data_xdr).
    fn build_valid_sig_data(e: &Env, payload: &[u8; 32]) -> (Bytes, Bytes, Bytes) {
        let mut encoded = [0u8; 43];
        base64_url_encode(&mut encoded, payload);
        let challenge_str = std::str::from_utf8(&encoded).unwrap();

        let auth_data = make_authenticator_data(
            e, AUTH_DATA_FLAGS_UP | AUTH_DATA_FLAGS_UV | AUTH_DATA_FLAGS_BE | AUTH_DATA_FLAGS_BS,
        );
        let client_data = make_client_data(e, challenge_str);

        // message = authenticator_data || sha256(client_data)
        let mut msg = auth_data.clone();
        msg.extend_from_array(&e.crypto().sha256(&client_data).to_array());
        let digest = e.crypto().sha256(&msg).to_array();

        let (key_data, signature) = sign_digest(e, &digest);

        let sig_struct = WebAuthnSigData { signature, authenticator_data: auth_data, client_data };
        let sig_data_xdr = sig_struct.to_xdr(e);

        (Bytes::from_array(e, payload), key_data, sig_data_xdr)
    }

    fn deploy(e: &Env) -> soroban_sdk::Address {
        e.register(Secp256r1Verifier, ())
    }

    // ── verify ────────────────────────────────────────────────────────────────

    #[test]
    fn verify_valid_webauthn_signature() {
        let e = Env::default();
        let addr = deploy(&e);

        let payload: [u8; 32] =
            hex!("4bb7a8b99609b0b8b1d534694bb1f31f129138a2f2a11f8e8702eedbb792922e");

        let (sig_payload, key_data, sig_data) = build_valid_sig_data(&e, &payload);

        assert!(Secp256r1VerifierClient::new(&e, &addr)
            .verify(&sig_payload, &key_data, &sig_data));
    }

    #[test]
    #[should_panic(expected = "Error(Crypto, InvalidInput)")]
    fn verify_corrupted_signature_fails() {
        let e = Env::default();
        let addr = deploy(&e);

        let payload: [u8; 32] =
            hex!("4bb7a8b99609b0b8b1d534694bb1f31f129138a2f2a11f8e8702eedbb792922e");

        let mut encoded = [0u8; 43];
        base64_url_encode(&mut encoded, &payload);
        let challenge_str = std::str::from_utf8(&encoded).unwrap();

        let auth_data = make_authenticator_data(
            &e, AUTH_DATA_FLAGS_UP | AUTH_DATA_FLAGS_UV | AUTH_DATA_FLAGS_BE | AUTH_DATA_FLAGS_BS,
        );
        let client_data = make_client_data(&e, challenge_str);

        let mut msg = auth_data.clone();
        msg.extend_from_array(&e.crypto().sha256(&client_data).to_array());
        let digest = e.crypto().sha256(&msg).to_array();
        let (key_data, mut signature) = sign_digest(&e, &digest);

        // Corromper firma
        let mut sig_arr = signature.to_array();
        sig_arr[0] = sig_arr[0].wrapping_add(1);
        signature = BytesN::from_array(&e, &sig_arr);

        let sig_struct = WebAuthnSigData { signature, authenticator_data: auth_data, client_data };
        let sig_data_xdr = sig_struct.to_xdr(&e);

        Secp256r1VerifierClient::new(&e, &addr).verify(
            &Bytes::from_array(&e, &payload),
            &key_data,
            &sig_data_xdr,
        );
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #3114)")]
    fn verify_wrong_challenge_fails() {
        let e = Env::default();
        let addr = deploy(&e);

        let payload: [u8; 32] = [1u8; 32];

        let auth_data = make_authenticator_data(
            &e, AUTH_DATA_FLAGS_UP | AUTH_DATA_FLAGS_UV | AUTH_DATA_FLAGS_BE | AUTH_DATA_FLAGS_BS,
        );
        // client_data con challenge incorrecto
        let client_data = make_client_data(&e, "challenge_incorrecto_AAAAAAAAAAAAAAAAAAAAAAAAA");

        let mut msg = auth_data.clone();
        msg.extend_from_array(&e.crypto().sha256(&client_data).to_array());
        let digest = e.crypto().sha256(&msg).to_array();
        let (key_data, signature) = sign_digest(&e, &digest);

        let sig_struct = WebAuthnSigData { signature, authenticator_data: auth_data, client_data };
        let sig_data_xdr = sig_struct.to_xdr(&e);

        Secp256r1VerifierClient::new(&e, &addr).verify(
            &Bytes::from_array(&e, &payload),
            &key_data,
            &sig_data_xdr,
        );
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #3116)")]
    fn verify_up_bit_not_set_fails() {
        let e = Env::default();
        let addr = deploy(&e);

        let payload: [u8; 32] = [2u8; 32];
        let mut encoded = [0u8; 43];
        base64_url_encode(&mut encoded, &payload);

        // flags sin UP bit
        let auth_data = make_authenticator_data(&e, AUTH_DATA_FLAGS_UV);
        let client_data = make_client_data(&e, std::str::from_utf8(&encoded).unwrap());

        let mut msg = auth_data.clone();
        msg.extend_from_array(&e.crypto().sha256(&client_data).to_array());
        let digest = e.crypto().sha256(&msg).to_array();
        let (key_data, signature) = sign_digest(&e, &digest);

        let sig_struct = WebAuthnSigData { signature, authenticator_data: auth_data, client_data };

        Secp256r1VerifierClient::new(&e, &addr).verify(
            &Bytes::from_array(&e, &payload),
            &key_data,
            &sig_struct.to_xdr(&e),
        );
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #3117)")]
    fn verify_uv_bit_not_set_fails() {
        let e = Env::default();
        let addr = deploy(&e);

        let payload: [u8; 32] = [3u8; 32];
        let mut encoded = [0u8; 43];
        base64_url_encode(&mut encoded, &payload);

        // flags sin UV bit
        let auth_data = make_authenticator_data(&e, AUTH_DATA_FLAGS_UP);
        let client_data = make_client_data(&e, std::str::from_utf8(&encoded).unwrap());

        let mut msg = auth_data.clone();
        msg.extend_from_array(&e.crypto().sha256(&client_data).to_array());
        let digest = e.crypto().sha256(&msg).to_array();
        let (key_data, signature) = sign_digest(&e, &digest);

        let sig_struct = WebAuthnSigData { signature, authenticator_data: auth_data, client_data };

        Secp256r1VerifierClient::new(&e, &addr).verify(
            &Bytes::from_array(&e, &payload),
            &key_data,
            &sig_struct.to_xdr(&e),
        );
    }

    // ── canonicalize_key ──────────────────────────────────────────────────────

    #[test]
    fn canonicalize_key_strips_credential_id_suffix() {
        let e = Env::default();
        let addr = deploy(&e);

        // 65 bytes de pubkey + 16 bytes de credential ID
        let pub_bytes = Bytes::from_array(&e, &[7u8; 65]);
        let mut key_data = pub_bytes.clone();
        key_data.extend_from_array(&[9u8; 16]);

        let result = Secp256r1VerifierClient::new(&e, &addr).canonicalize_key(&key_data);
        assert_eq!(result, pub_bytes);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #3119)")]
    fn canonicalize_key_too_short_fails() {
        let e = Env::default();
        let addr = deploy(&e);

        // Solo 64 bytes — falta 1 para completar la pubkey secp256r1
        let short = Bytes::from_array(&e, &[1u8; 64]);
        Secp256r1VerifierClient::new(&e, &addr).canonicalize_key(&short);
    }

    // ── batch_canonicalize_key ────────────────────────────────────────────────

    #[test]
    fn batch_canonicalize_preserves_order() {
        let e = Env::default();
        let addr = deploy(&e);

        let k1 = Bytes::from_array(&e, &[1u8; 65]);
        let k2 = Bytes::from_array(&e, &[2u8; 65]);
        let k3 = Bytes::from_array(&e, &[3u8; 65]);

        let mut keys = soroban_sdk::Vec::new(&e);
        keys.push_back(k1.clone());
        keys.push_back(k2.clone());
        keys.push_back(k3.clone());

        let result = Secp256r1VerifierClient::new(&e, &addr).batch_canonicalize_key(&keys);
        assert_eq!(result.len(), 3);
        assert_eq!(result.get(0).unwrap(), k1);
        assert_eq!(result.get(1).unwrap(), k2);
        assert_eq!(result.get(2).unwrap(), k3);
    }
}

#[contract]
pub struct Secp256r1Verifier;

#[contractimpl]
impl Verifier for Secp256r1Verifier {
    type KeyData = Bytes;
    type SigData = Bytes;

    fn verify(
        e: &Env,
        signature_payload: Bytes,
        key_data: Bytes,
        sig_data: Bytes,
    ) -> bool {
        let sig_struct = WebAuthnSigData::from_xdr(e, &sig_data)
            .expect("sig_data must be XDR-encoded WebAuthnSigData");

        let pub_key: BytesN<65> = extract_from_bytes(e, &key_data, 0..65)
            .expect("key_data must start with 65-byte secp256r1 pubkey");

        webauthn::verify(e, &signature_payload, &pub_key, &sig_struct)
    }

    fn canonicalize_key(e: &Env, key_data: Bytes) -> Bytes {
        webauthn::canonicalize_key(e, &key_data)
    }

    fn batch_canonicalize_key(e: &Env, keys_data: Vec<Bytes>) -> Vec<Bytes> {
        webauthn::batch_canonicalize_key(e, &keys_data)
    }
}
