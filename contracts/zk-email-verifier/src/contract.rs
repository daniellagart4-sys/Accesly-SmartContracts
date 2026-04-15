//! # Accesly — ZK Email Verifier
//!
//! Doble rol:
//! 1. **DKIM Registry**: el admin registra/revoca pares (domain_hash, pk_hash).
//!    `domain_hash` = SHA-256 del dominio del email (e.g. "gmail.com").
//!    `public_key_hash` = hash de la clave pública DKIM del dominio.
//!
//! 2. **Verifier** para Smart Account: actúa como signer externo en la
//!    context rule de recovery ZK. El Smart Account lo llama en `__check_auth`
//!    cuando se presenta una ZK proof de email.
//!
//! Flujo de recovery:
//!   a. SDK genera ZK proof off-chain de que el usuario posee el email.
//!   b. Smart Account incluye la proof en la firma de la tx de recovery.
//!   c. `__check_auth` llama a `verify()` en este contrato.
//!   d. Este contrato valida la proof contra el DKIM registry.
//!
//! Sobre la verificación ZK:
//!   La `stellar-zk-email` crate provee el registry DKIM. La verificación
//!   del proof en sí (groth16/plonk) requiere integración con el circuito
//!   zkEmail. Por ahora, `verify` valida el formato y la presencia de la
//!   clave DKIM en el registry. La integración del verificador ZK se agrega
//!   en Fase 2 cuando el circuito esté finalizado.
use soroban_sdk::{
    contract, contractimpl, contracttype, xdr::FromXdr,
    Address, Bytes, BytesN, Env, Symbol, Vec,
};
use stellar_accounts::verifiers::Verifier;
use stellar_access::access_control::{get_admin, set_admin, AccessControl};
use stellar_zk_email::dkim_registry::{self, DKIMRegistry};

fn require_admin(e: &Env) {
    get_admin(e).expect("admin not set").require_auth();
}

// ── Estructura del proof ──────────────────────────────────────────────────────

/// Payload de la ZK proof para recovery de email.
/// El SDK serializa esto como XDR y lo pasa como `sig_data` al verificador.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ZkEmailProof {
    /// Hash del dominio del email (SHA-256("gmail.com") etc.)
    pub domain_hash: BytesN<32>,
    /// Hash de la clave pública DKIM del dominio que firmó el email.
    pub public_key_hash: BytesN<32>,
    /// Bytes del proof ZK (groth16/plonk). Validación completa: Fase 2.
    pub proof: Bytes,
}

// ── Contrato ──────────────────────────────────────────────────────────────────

#[contract]
pub struct ZkEmailVerifier;

#[contractimpl]
impl ZkEmailVerifier {
    /// Inicializa el contrato con el admin del registry DKIM.
    pub fn __constructor(e: &Env, admin: Address) {
        set_admin(e, &admin);
    }
}

// ── DKIMRegistry: gestión de claves DKIM ──────────────────────────────────────

#[contractimpl]
impl DKIMRegistry for ZkEmailVerifier {
    /// Registra un par (domain_hash, public_key_hash). Solo admin.
    fn set_dkim_public_key_hash(
        e: &Env,
        domain_hash: BytesN<32>,
        public_key_hash: BytesN<32>,
        operator: Address,
    ) {
        require_admin(e);
        dkim_registry::set_dkim_public_key_hash(e, &domain_hash, &public_key_hash);
        let _ = operator; // satisface la firma del trait
    }

    /// Registra múltiples public_key_hashes para un mismo dominio. Solo admin.
    fn set_dkim_public_key_hashes(
        e: &Env,
        domain_hash: BytesN<32>,
        public_key_hashes: Vec<BytesN<32>>,
        operator: Address,
    ) {
        require_admin(e);
        for pk_hash in public_key_hashes.iter() {
            dkim_registry::set_dkim_public_key_hash(e, &domain_hash, &pk_hash);
        }
        let _ = operator;
    }

    /// Revoca globalmente un public_key_hash. Solo admin.
    fn revoke_dkim_public_key_hash(
        e: &Env,
        public_key_hash: BytesN<32>,
        operator: Address,
    ) {
        require_admin(e);
        dkim_registry::revoke_dkim_public_key_hash(e, &public_key_hash);
        let _ = operator;
    }
}

// ── Verifier: validación de ZK proofs de email ───────────────────────────────

#[contractimpl]
impl Verifier for ZkEmailVerifier {
    /// key_data: BytesN<32> = commitment del email del usuario
    ///   (hash(email_address || salt)), usado para identificar al propietario.
    type KeyData = BytesN<32>;

    /// sig_data: Bytes = XDR-encoded ZkEmailProof
    type SigData = Bytes;

    /// Verifica que la ZK proof sea válida para el email commitment dado.
    ///
    /// Validaciones actuales:
    /// 1. Deserializa el proof.
    /// 2. Comprueba que el par (domain_hash, public_key_hash) esté registrado
    ///    y no revocado en el DKIM registry.
    ///
    /// TODO Fase 2: integrar verificador groth16/plonk on-chain para validar
    /// `proof.proof` contra `signature_payload` y `key_data`.
    fn verify(
        e: &Env,
        _signature_payload: Bytes,
        _key_data: BytesN<32>,
        sig_data: Bytes,
    ) -> bool {
        let proof = ZkEmailProof::from_xdr(e, &sig_data)
            .expect("sig_data must be XDR-encoded ZkEmailProof");

        // Valida que la clave DKIM esté registrada y no revocada
        dkim_registry::is_key_hash_valid(e, &proof.domain_hash, &proof.public_key_hash)
    }

    fn canonicalize_key(e: &Env, key_data: BytesN<32>) -> Bytes {
        Bytes::from_slice(e, &key_data.to_array())
    }

    fn batch_canonicalize_key(e: &Env, keys_data: Vec<BytesN<32>>) -> Vec<Bytes> {
        Vec::from_iter(
            e,
            keys_data.iter().map(|k| Bytes::from_slice(e, &k.to_array())),
        )
    }
}

// ── AccessControl: gestión de roles (heredado de OZ) ─────────────────────────

#[contractimpl(contracttrait)]
impl AccessControl for ZkEmailVerifier {}

// ── Queries públicas ──────────────────────────────────────────────────────────

#[contractimpl]
impl ZkEmailVerifier {
    /// Consulta si un par (domain_hash, pk_hash) es válido.
    pub fn is_dkim_valid(
        e: Env,
        domain_hash: BytesN<32>,
        public_key_hash: BytesN<32>,
    ) -> bool {
        dkim_registry::is_key_hash_valid(&e, &domain_hash, &public_key_hash)
    }

    /// Consulta si un pk_hash está revocado.
    pub fn is_dkim_revoked(e: Env, public_key_hash: BytesN<32>) -> bool {
        dkim_registry::is_key_hash_revoked(&e, &public_key_hash)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;

    use soroban_sdk::{
        testutils::Address as _,
        xdr::ToXdr,
        Address, Bytes, BytesN, Env,
    };

    use super::*;

    fn deploy(e: &Env) -> (Address, Address) {
        let admin = Address::generate(e);
        let addr = e.register(ZkEmailVerifier, (&admin,));
        (addr, admin)
    }

    fn domain() -> [u8; 32] { [1u8; 32] }
    fn pk_hash() -> [u8; 32] { [2u8; 32] }
    fn other_pk_hash() -> [u8; 32] { [3u8; 32] }

    fn make_proof(e: &Env, dh: [u8; 32], pkh: [u8; 32]) -> Bytes {
        let proof = ZkEmailProof {
            domain_hash: BytesN::from_array(e, &dh),
            public_key_hash: BytesN::from_array(e, &pkh),
            proof: Bytes::from_array(e, &[0u8; 32]),
        };
        proof.to_xdr(e)
    }

    // ── DKIM registry ─────────────────────────────────────────────────────────

    #[test]
    fn set_and_query_dkim_key() {
        let e = Env::default();
        let (addr, admin) = deploy(&e);
        e.mock_all_auths();

        let dh = BytesN::from_array(&e, &domain());
        let pkh = BytesN::from_array(&e, &pk_hash());

        ZkEmailVerifierClient::new(&e, &addr).set_dkim_public_key_hash(&dh, &pkh, &admin);
        assert!(ZkEmailVerifierClient::new(&e, &addr).is_dkim_valid(&dh, &pkh));
    }

    #[test]
    fn unregistered_key_returns_false() {
        let e = Env::default();
        let (addr, _) = deploy(&e);

        let dh = BytesN::from_array(&e, &domain());
        let pkh = BytesN::from_array(&e, &pk_hash());

        assert!(!ZkEmailVerifierClient::new(&e, &addr).is_dkim_valid(&dh, &pkh));
    }

    #[test]
    fn revoke_key_returns_false_for_valid() {
        let e = Env::default();
        let (addr, admin) = deploy(&e);
        e.mock_all_auths();

        let dh = BytesN::from_array(&e, &domain());
        let pkh = BytesN::from_array(&e, &pk_hash());
        let client = ZkEmailVerifierClient::new(&e, &addr);

        client.set_dkim_public_key_hash(&dh, &pkh, &admin);
        assert!(client.is_dkim_valid(&dh, &pkh));

        client.revoke_dkim_public_key_hash(&pkh, &admin);
        assert!(!client.is_dkim_valid(&dh, &pkh));
        assert!(client.is_dkim_revoked(&pkh));
    }

    #[test]
    fn set_multiple_keys_for_same_domain() {
        let e = Env::default();
        let (addr, admin) = deploy(&e);
        e.mock_all_auths();

        let dh = BytesN::from_array(&e, &domain());
        let pkh1 = BytesN::from_array(&e, &pk_hash());
        let pkh2 = BytesN::from_array(&e, &other_pk_hash());
        let client = ZkEmailVerifierClient::new(&e, &addr);

        let mut hashes = soroban_sdk::Vec::new(&e);
        hashes.push_back(pkh1.clone());
        hashes.push_back(pkh2.clone());
        client.set_dkim_public_key_hashes(&dh, &hashes, &admin);

        assert!(client.is_dkim_valid(&dh, &pkh1));
        assert!(client.is_dkim_valid(&dh, &pkh2));
    }

    // ── Verifier (ZK proof) ───────────────────────────────────────────────────

    #[test]
    fn verify_registered_key_returns_true() {
        let e = Env::default();
        let (addr, admin) = deploy(&e);
        e.mock_all_auths();

        let dh = BytesN::from_array(&e, &domain());
        let pkh = BytesN::from_array(&e, &pk_hash());
        let client = ZkEmailVerifierClient::new(&e, &addr);

        client.set_dkim_public_key_hash(&dh, &pkh, &admin);

        let sig_data = make_proof(&e, domain(), pk_hash());
        let key_data = BytesN::from_array(&e, &[0u8; 32]);
        let payload = Bytes::from_array(&e, &[9u8; 32]);

        assert!(client.verify(&payload, &key_data, &sig_data));
    }

    #[test]
    fn verify_unregistered_dkim_returns_false() {
        let e = Env::default();
        let (addr, _) = deploy(&e);
        e.mock_all_auths();

        let sig_data = make_proof(&e, domain(), pk_hash());
        let key_data = BytesN::from_array(&e, &[0u8; 32]);
        let payload = Bytes::from_array(&e, &[9u8; 32]);

        assert!(!ZkEmailVerifierClient::new(&e, &addr).verify(&payload, &key_data, &sig_data));
    }

    #[test]
    fn verify_revoked_dkim_returns_false() {
        let e = Env::default();
        let (addr, admin) = deploy(&e);
        e.mock_all_auths();

        let dh = BytesN::from_array(&e, &domain());
        let pkh = BytesN::from_array(&e, &pk_hash());
        let client = ZkEmailVerifierClient::new(&e, &addr);

        client.set_dkim_public_key_hash(&dh, &pkh, &admin);
        client.revoke_dkim_public_key_hash(&pkh, &admin);

        let sig_data = make_proof(&e, domain(), pk_hash());
        let key_data = BytesN::from_array(&e, &[0u8; 32]);
        let payload = Bytes::from_array(&e, &[9u8; 32]);

        assert!(!client.verify(&payload, &key_data, &sig_data));
    }

    #[test]
    fn canonicalize_key_returns_bytes() {
        let e = Env::default();
        let (addr, _) = deploy(&e);
        let client = ZkEmailVerifierClient::new(&e, &addr);

        let key = BytesN::from_array(&e, &[7u8; 32]);
        let result = client.canonicalize_key(&key);
        assert_eq!(result, Bytes::from_array(&e, &[7u8; 32]));
    }
}
