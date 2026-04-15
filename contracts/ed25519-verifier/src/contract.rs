//! # Accesly — Ed25519 Verifier
//!
//! Instancia compartida. Todos los Smart Accounts la referencian para
//! verificar firmas ed25519 de la llave reconstruida (F1+F2+F3).
use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env, Vec};
use stellar_accounts::verifiers::{ed25519, Verifier};

#[contract]
pub struct Ed25519Verifier;

#[contractimpl]
impl Verifier for Ed25519Verifier {
    type KeyData = BytesN<32>;
    type SigData = BytesN<64>;

    fn verify(
        e: &Env,
        signature_payload: Bytes,
        key_data: BytesN<32>,
        sig_data: BytesN<64>,
    ) -> bool {
        ed25519::verify(e, &signature_payload, &key_data, &sig_data)
    }

    fn canonicalize_key(e: &Env, key_data: BytesN<32>) -> Bytes {
        ed25519::canonicalize_key(e, &key_data)
    }

    fn batch_canonicalize_key(e: &Env, keys_data: Vec<BytesN<32>>) -> Vec<Bytes> {
        ed25519::batch_canonicalize_key(e, &keys_data)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;

    use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};
    use soroban_sdk::{Address, Bytes, BytesN, Env};

    use super::*;

    const SECRET: [u8; 32] = [
        157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196,
        68, 73, 197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
    ];
    const SECRET2: [u8; 32] = [
        200, 100, 150, 200, 240, 250, 95, 100, 190, 140, 80, 250, 150, 240, 50, 200,
        70, 80, 200, 110, 130, 55, 110, 30, 115, 65, 175, 10, 35, 180, 130, 100,
    ];

    fn setup(e: &Env) -> (Address, BytesN<32>, [u8; 32]) {
        let addr = e.register(Ed25519Verifier, ());
        let signing_key = SigningKey::from_bytes(&SECRET);
        let pubkey = BytesN::from_array(e, signing_key.verifying_key().as_bytes());
        (addr, pubkey, SECRET)
    }

    fn sign(e: &Env, secret: &[u8; 32], payload: &[u8; 32]) -> BytesN<64> {
        let signing_key = SigningKey::from_bytes(secret);
        let sig = signing_key.sign(payload).to_bytes();
        BytesN::from_array(e, &sig)
    }

    // ── verify ────────────────────────────────────────────────────────────────

    #[test]
    fn verify_valid_signature() {
        let e = Env::default();
        let (addr, pubkey, secret) = setup(&e);

        let data = Bytes::from_array(&e, &[1u8; 64]);
        let payload_hash = e.crypto().keccak256(&data);
        let sig = sign(&e, &secret, &payload_hash.to_array());

        let client = Ed25519VerifierClient::new(&e, &addr);
        assert!(client.verify(&Bytes::from_array(&e, &payload_hash.to_array()), &pubkey, &sig));
    }

    #[test]
    #[should_panic(expected = "Error(Crypto, InvalidInput)")]
    fn verify_corrupted_signature_fails() {
        let e = Env::default();
        let (addr, pubkey, secret) = setup(&e);

        let data = Bytes::from_array(&e, &[1u8; 64]);
        let payload_hash = e.crypto().keccak256(&data);
        let mut sig_bytes = SigningKey::from_bytes(&secret)
            .sign(&payload_hash.to_array()).to_bytes();
        sig_bytes[0] = sig_bytes[0].wrapping_add(1); // corrupt
        let sig = BytesN::from_array(&e, &sig_bytes);

        Ed25519VerifierClient::new(&e, &addr)
            .verify(&Bytes::from_array(&e, &payload_hash.to_array()), &pubkey, &sig);
    }

    #[test]
    #[should_panic(expected = "Error(Crypto, InvalidInput)")]
    fn verify_wrong_key_fails() {
        let e = Env::default();
        let (addr, _pubkey1, _) = setup(&e);

        let signing_key2 = SigningKey::from_bytes(&SECRET2);
        let pubkey1 = BytesN::from_array(&e, SigningKey::from_bytes(&SECRET).verifying_key().as_bytes());

        let data = Bytes::from_array(&e, &[1u8; 64]);
        let payload_hash = e.crypto().keccak256(&data);
        // Firma con key2, verifica con pubkey1
        let sig = sign(&e, &SECRET2, &payload_hash.to_array());

        Ed25519VerifierClient::new(&e, &addr)
            .verify(&Bytes::from_array(&e, &payload_hash.to_array()), &pubkey1, &sig);
    }

    // ── canonicalize_key ──────────────────────────────────────────────────────

    #[test]
    fn canonicalize_key_identity() {
        let e = Env::default();
        let addr = e.register(Ed25519Verifier, ());
        let key = BytesN::from_array(&e, &[42u8; 32]);
        let result = Ed25519VerifierClient::new(&e, &addr).canonicalize_key(&key);
        assert_eq!(result, Bytes::from_array(&e, &[42u8; 32]));
    }

    #[test]
    fn batch_canonicalize_preserves_order() {
        let e = Env::default();
        let addr = e.register(Ed25519Verifier, ());
        let k1 = BytesN::from_array(&e, &[1u8; 32]);
        let k2 = BytesN::from_array(&e, &[2u8; 32]);
        let k3 = BytesN::from_array(&e, &[3u8; 32]);
        let mut keys = soroban_sdk::Vec::new(&e);
        keys.push_back(k1.clone());
        keys.push_back(k2.clone());
        keys.push_back(k3.clone());

        let result = Ed25519VerifierClient::new(&e, &addr).batch_canonicalize_key(&keys);
        assert_eq!(result.len(), 3);
        assert_eq!(result.get(0).unwrap(), Bytes::from_array(&e, &[1u8; 32]));
        assert_eq!(result.get(2).unwrap(), Bytes::from_array(&e, &[3u8; 32]));
    }
}
