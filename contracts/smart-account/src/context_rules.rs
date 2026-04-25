//! # Context Rules predefinidas (Issues 1.4 y 1.9)
//!
//! Inicializa las 5 context rules base en el constructor del Smart Account.
//!
//! | ID | Nombre        | ContextRuleType           | Signers               | Policies           |
//! |----|---------------|---------------------------|-----------------------|--------------------|
//! |  0 | biometric-tx  | Default                   | ed25519 (External)    | spending_limit     |
//! |  1 | admin-cfg     | Default                   | ed25519 (External)    | —                  |
//! |  2 | zk-recovery   | Default                   | zk_email (External)   | —                  |
//! |  3 | sep10-auth    | Default                   | secp256r1 (External)  | —                  |
//! |  4 | yield-auto    | CallContract(cetes)       | —                     | yield_policy       |
//!
//! Reglas dinámicas (añadidas por el SDK en runtime):
//! - "session-key" (Default): External signer (session ed25519) + session_key_policy
//! - "allowlist-tx" (CallContract(target)): External signer (session key) sin policy
//!
//!
//! Reglas dinámicas instaladas por el SDK (via admin-cfg):
//! - "blend-rule" (Default): session key + blend_rule_policy (restrict pool + request types + max amount)
//! - "upgrade-rule" (Default): session key + upgrade_rule_policy (solo `upgrade` en target_contract)
use soroban_sdk::{Address, Bytes, BytesN, Env, Map, String, Val, Vec};
use stellar_accounts::smart_account::{
    self as smart_account_lib, ContextRuleType, Signer,
};

/// Instala las 5 context rules base.
#[allow(clippy::too_many_arguments)]
pub fn setup_context_rules(
    e: &Env,
    owner_ed25519: &BytesN<32>,
    email_commitment: &BytesN<32>,
    secp256r1_pubkey: &BytesN<65>,
    ed25519_verifier: &Address,
    secp256r1_verifier: &Address,
    spending_limit_policy: &Address,
    spending_limit_params: Val,
    zk_email_verifier: &Address,
    yield_policy: &Address,
    yield_params: Val,
    cetes_contract: &Address,
) {
    // ── Signers ───────────────────────────────────────────────────────────────

    // Signer ed25519 del propietario (biométrico reconstruido F1+F2+F3)
    let owner_signer = Signer::External(
        ed25519_verifier.clone(),
        Bytes::from_slice(e, &owner_ed25519.to_array()),
    );

    // Signer ZK email — key_data = email commitment (hash del email + salt)
    let zk_signer = Signer::External(
        zk_email_verifier.clone(),
        Bytes::from_slice(e, &email_commitment.to_array()),
    );

    // Signer passkey / biométrico de dispositivo (secp256r1 uncompressed 65 bytes)
    let secp_signer = Signer::External(
        secp256r1_verifier.clone(),
        Bytes::from_slice(e, &secp256r1_pubkey.to_array()),
    );

    // ── Regla 0: biometric-tx ─────────────────────────────────────────────────
    // Transferencias normales: biométrico ed25519 + spending limit.
    {
        let mut signers: Vec<Signer> = Vec::new(e);
        signers.push_back(owner_signer.clone());
        let mut policies: Map<Address, Val> = Map::new(e);
        policies.set(spending_limit_policy.clone(), spending_limit_params);

        smart_account_lib::add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "biometric-tx"),
            None,
            &signers,
            &policies,
        );
    }

    // ── Regla 1: admin-cfg ────────────────────────────────────────────────────
    // Operaciones de configuración: biométrico ed25519 estricto, sin policies.
    // Cubre: cambiar signers, cambiar context rules, desactivar yield, revocar sesiones.
    {
        let mut signers: Vec<Signer> = Vec::new(e);
        signers.push_back(owner_signer.clone());
        let policies: Map<Address, Val> = Map::new(e);

        smart_account_lib::add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "admin-cfg"),
            None,
            &signers,
            &policies,
        );
    }

    // ── Regla 2: zk-recovery ─────────────────────────────────────────────────
    // Recovery por ZK proof de email. Autoriza cambiar el signer principal.
    {
        let mut signers: Vec<Signer> = Vec::new(e);
        signers.push_back(zk_signer);
        let policies: Map<Address, Val> = Map::new(e);

        smart_account_lib::add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "zk-recovery"),
            None,
            &signers,
            &policies,
        );
    }

    // ── Regla 3: sep10-auth ───────────────────────────────────────────────────
    // SEP-10 challenge-response con passkey (secp256r1). Solo auth, no transacciones.
    {
        let mut signers: Vec<Signer> = Vec::new(e);
        signers.push_back(secp_signer);
        let policies: Map<Address, Val> = Map::new(e);

        smart_account_lib::add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "sep10-auth"),
            None,
            &signers,
            &policies,
        );
    }

    // ── Regla 4: yield-auto ───────────────────────────────────────────────────
    // Distribución automática de yield CETES. Sin firma del usuario (relayer Lambda).
    // Solo autoriza transfer() SEP-41 sobre el contrato CETES (yield-distribution policy).
    {
        let signers: Vec<Signer> = Vec::new(e);
        let mut policies: Map<Address, Val> = Map::new(e);
        policies.set(yield_policy.clone(), yield_params);

        smart_account_lib::add_context_rule(
            e,
            &ContextRuleType::CallContract(cetes_contract.clone()),
            &String::from_str(e, "yield-auto"),
            None,
            &signers,
            &policies,
        );
    }
}
