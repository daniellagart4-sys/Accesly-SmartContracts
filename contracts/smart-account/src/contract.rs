//! # Accesly — Smart Account
//!
//! Contrato principal. Un deploy por usuario, generado al registrarse con
//! su email (como Privy, pero en Stellar/Soroban).
//!
//! ## Arquitectura
//!
//! Cada Smart Account es una instancia de este contrato con:
//! - Un signer ed25519 principal (F1+F2+F3 reconstruido en el SDK).
//! - Context rules predefinidas (ver context_rules.rs).
//! - Verifiers compartidos (ed25519, secp256r1, zk-email) — deploy único en la red.
//! - Policies compartidas (spending_limit, session_key, yield_dist) — deploy único.
//!
//! ## Context Rules
//!
//! | ID | Nombre       | Cuándo se usa                                      |
//! |----|--------------|----------------------------------------------------|
//! |  0 | biometric-tx | Transferencias normales (biométrico + spending limit) |
//! |  1 | admin-cfg    | Cambiar signers/rules/upgrade (biométrico estricto) |
//! |  2 | zk-recovery  | Recovery por ZK proof de email                     |
//! |  3 | sep10-auth   | SEP-10 challenge (passkey secp256r1)                |
//! |  4 | yield-auto   | Distribución automática yield CETES (sin firma)     |
//! | +N | session-key  | Pagos pequeños con session key temporal             |
//! | +N | allowlist-tx | Llamadas a contratos terceros permitidos            |
//!
//! ## Upgrade
//!
//! Los upgrades deben pasar por el TimelockController (48h delay).
//! El relayer propone, espera, y ejecuta. El upgrade requiere regla admin-cfg.
//!
//! ## Trustlines
//!
//! Al crear la cuenta se emite `TrustlinesRequired`. El relayer agrega las
//! operaciones `change_trust` en la misma transacción de deploy.
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    Address, BytesN, Env, Map, String, Symbol, Val, Vec,
};
use stellar_accounts::smart_account::{
    self as smart_account_lib, AuthPayload, ContextRule, ContextRuleType,
    ExecutionEntryPoint, Signer, SmartAccount, SmartAccountError,
};
use stellar_contract_utils::upgradeable::{self as upgradeable_lib, Upgradeable};

use crate::context_rules::setup_context_rules;
use crate::trustlines::{emit_trustlines_required, StellarAsset};

// ── Contrato ──────────────────────────────────────────────────────────────────

#[contract]
pub struct AcceslySmartAccount;

#[contractimpl]
impl AcceslySmartAccount {
    /// Crea el Smart Account para un usuario.
    ///
    /// # Arguments
    /// * `owner_ed25519`          — Pubkey ed25519 del propietario (32 bytes).
    ///   Representa la llave reconstruida F1+F2+F3 en el flujo de onboarding.
    ///
    /// * `email_commitment`       — Hash del email del usuario (32 bytes).
    ///   Usado como key_data del signer zk-recovery. Identifica al propietario
    ///   para el recovery ZK sin revelar el email on-chain.
    ///
    /// * `secp256r1_pubkey`       — Pubkey del passkey/biométrico del dispositivo
    ///   (65 bytes, uncompressed). Usado en la regla sep10-auth.
    ///
    /// * `ed25519_verifier`       — Dirección del Ed25519Verifier compartido.
    /// * `secp256r1_verifier`     — Dirección del Secp256r1Verifier compartido.
    /// * `spending_limit_policy`  — Dirección del SpendingLimitPolicy compartido.
    /// * `spending_limit_params`  — Parámetros de instalación del spending limit
    ///   (XDR-encoded SpendingLimitAccountParams).
    /// * `zk_email_verifier`      — Dirección del ZkEmailVerifier compartido.
    /// * `yield_policy`           — Dirección del YieldDistributionPolicy compartido.
    /// * `yield_params`           — Parámetros de instalación del yield policy
    ///   (XDR-encoded YieldInstallParams).
    /// * `cetes_contract`         — Dirección del contrato CETES/Etherfuse.
    /// * `trusted_assets`          — Lista de assets para los que se crearán trustlines.
    ///   El SDK construye esta lista según la configuración del developer (puede ser vacía).
    ///   Los issuers reales (testnet/mainnet) los conoce el SDK, no el contrato.
    #[allow(clippy::too_many_arguments)]
    pub fn __constructor(
        e: &Env,
        owner_ed25519: BytesN<32>,
        email_commitment: BytesN<32>,
        secp256r1_pubkey: BytesN<65>,
        ed25519_verifier: Address,
        secp256r1_verifier: Address,
        spending_limit_policy: Address,
        spending_limit_params: Val,
        zk_email_verifier: Address,
        yield_policy: Address,
        yield_params: Val,
        cetes_contract: Address,
        trusted_assets: Vec<StellarAsset>,
    ) {
        // Nota: email_commitment y secp256r1_pubkey se pasan a setup_context_rules
        // para que los signers tengan los key_data reales desde el primer momento.
        setup_context_rules(
            e,
            &owner_ed25519,
            &email_commitment,
            &secp256r1_pubkey,
            &ed25519_verifier,
            &secp256r1_verifier,
            &spending_limit_policy,
            spending_limit_params,
            &zk_email_verifier,
            &yield_policy,
            yield_params,
            &cetes_contract,
        );

        // Emitir trustlines requeridas para que el relayer las incluya en la tx.
        // La lista viene del SDK según la configuración del developer.
        if !trusted_assets.is_empty() {
            emit_trustlines_required(e, trusted_assets);
        }
    }
}

// ── CustomAccountInterface ────────────────────────────────────────────────────

#[contractimpl]
impl CustomAccountInterface for AcceslySmartAccount {
    type Error = SmartAccountError;
    type Signature = AuthPayload;

    /// Punto central de autorización. OZ maneja toda la lógica de:
    /// - Verificar firmas (ed25519, secp256r1, zk-email)
    /// - Evaluar context rules
    /// - Llamar enforce() en las policies (spending_limit, session_key, yield_dist)
    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        signatures: AuthPayload,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        smart_account_lib::do_check_auth(&e, &signature_payload, &signatures, &auth_contexts)
    }
}

// ── SmartAccount trait (gestión de reglas, signers, policies) ─────────────────

#[contractimpl(contracttrait)]
impl SmartAccount for AcceslySmartAccount {}

// ── ExecutionEntryPoint (llamadas a contratos externos desde la cuenta) ────────

#[contractimpl(contracttrait)]
impl ExecutionEntryPoint for AcceslySmartAccount {}

// ── Upgradeable (protegido por Timelock 48h en la regla admin-cfg) ────────────

#[contractimpl]
impl Upgradeable for AcceslySmartAccount {
    /// Upgrade del contrato. Requiere:
    /// 1. Pasar por la regla "admin-cfg" (biométrico ed25519).
    /// 2. El TimelockController habrá validado las 48h antes de que este
    ///    endpoint sea accesible (el timelock owner propone + ejecuta).
    fn upgrade(e: &Env, new_wasm_hash: BytesN<32>, _operator: Address) {
        e.current_contract_address().require_auth();
        upgradeable_lib::upgrade(e, &new_wasm_hash);
    }
}
