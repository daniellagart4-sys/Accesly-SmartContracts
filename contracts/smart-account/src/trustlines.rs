//! # Trustlines automáticas (Issue 1.13)
//!
//! Las trustlines clásicas de Stellar NO se pueden crear desde dentro de un
//! contrato Soroban — son operaciones nativas del ledger (ChangeTrustOp).
//!
//! Por eso, este módulo solo emite un evento con los assets requeridos.
//! El relayer que hace el deploy intercepta este evento y agrega las
//! operaciones `change_trust` en la misma transacción de deploy.
//!
//! Reserva XLM por trustline: 0.5 XLM = 5_000_000 stroops.
//! El relayer paga la reserva y la descuenta del saldo del usuario.
use soroban_sdk::{contractevent, contracttype, Address, BytesN, Env, Symbol, Vec};

/// Reserva requerida por trustline en stroops (0.5 XLM).
pub const XLM_PER_TRUSTLINE: i128 = 5_000_000;

/// Asset de Stellar identificado por issuer + código.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct StellarAsset {
    /// Clave pública del emisor del asset.
    pub issuer: BytesN<32>,
    /// Código del asset (e.g. "USDC", "CETES").
    pub code: Symbol,
}

/// Evento emitido al crear el Smart Account con los assets que necesitan trustline.
/// El relayer escucha este evento y construye las operaciones change_trust.
#[contractevent]
#[derive(Clone)]
pub struct TrustlinesRequired {
    #[topic]
    pub smart_account: Address,
    pub assets: Vec<StellarAsset>,
    pub xlm_reserve_needed: i128,
}

/// Emite el evento `TrustlinesRequired` con los assets necesarios.
pub fn emit_trustlines_required(e: &Env, assets: Vec<StellarAsset>) {
    let smart_account = e.current_contract_address();
    let count = assets.len() as i128;
    TrustlinesRequired {
        smart_account,
        assets,
        xlm_reserve_needed: count * XLM_PER_TRUSTLINE,
    }
    .publish(e);
}

