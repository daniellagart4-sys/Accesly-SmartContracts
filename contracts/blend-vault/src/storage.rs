//! # Storage del Blend Vault
//!
//! Guarda:
//! - Configuración del pool (pool_address, usdc_reserve_index)
//! - Principal depositado por usuario (para calcular yield = valor_actual - principal)
use soroban_sdk::{contracterror, contracttype, panic_with_error, Address, Env};

const DAY_IN_LEDGERS: u32 = 17_280;
/// 1-year TTL ensures principal never expires while shares can still exist.
const EXTEND_AMOUNT: u32 = 365 * DAY_IN_LEDGERS;
const TTL_THRESHOLD: u32 = EXTEND_AMOUNT - 30 * DAY_IN_LEDGERS;

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
enum StorageError {
    PrincipalOverflow = 8100,
}

// ── Claves de storage ─────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum StorageKey {
    /// One-time initialization flag.
    Initialized,
    /// Dirección del pool de Blend
    BlendPool,
    /// Índice del reserve USDC en el pool de Blend (varía por pool)
    UsdcReserveIndex,
    /// Wallet fija de Accesly — validada en distribute_yield para evitar redireccionamiento de fees.
    AcceslyWallet,
    /// Principal depositado por usuario (en USDC/stroops)
    UserPrincipal(Address),
}

// ── Config del vault ──────────────────────────────────────────────────────────

pub fn set_blend_pool(e: &Env, pool: &Address) {
    e.storage().instance().set(&StorageKey::BlendPool, pool);
}

pub fn get_blend_pool(e: &Env) -> Address {
    e.storage().instance().get(&StorageKey::BlendPool).expect("blend pool not set")
}

pub fn set_usdc_reserve_index(e: &Env, index: u32) {
    e.storage().instance().set(&StorageKey::UsdcReserveIndex, &index);
}

pub fn get_usdc_reserve_index(e: &Env) -> u32 {
    e.storage().instance().get(&StorageKey::UsdcReserveIndex).expect("reserve index not set")
}

pub fn set_accesly_wallet(e: &Env, wallet: &Address) {
    e.storage().instance().set(&StorageKey::AcceslyWallet, wallet);
}

pub fn get_accesly_wallet(e: &Env) -> Address {
    e.storage().instance().get(&StorageKey::AcceslyWallet).expect("accesly wallet not set")
}

// ── Principal por usuario ─────────────────────────────────────────────────────

/// Añade `amount` USDC al principal del usuario (al depositar).
pub fn add_principal(e: &Env, user: &Address, amount: i128) {
    let key = StorageKey::UserPrincipal(user.clone());
    let current: i128 = e.storage().persistent().get(&key).unwrap_or(0);
    let new_val = current.checked_add(amount)
        .unwrap_or_else(|| panic_with_error!(e, StorageError::PrincipalOverflow));
    e.storage().persistent().set(&key, &new_val);
    e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
}

/// Reduce el principal del usuario proporcionalmente a las shares retiradas.
/// `shares_redeemed / total_user_shares_before` = fracción retirada.
pub fn reduce_principal_proportional(
    e: &Env,
    user: &Address,
    shares_redeemed: i128,
    total_user_shares_before: i128,
) {
    if total_user_shares_before == 0 {
        return;
    }
    let key = StorageKey::UserPrincipal(user.clone());
    let current: i128 = e.storage().persistent().get(&key).unwrap_or(0);

    // principal_withdrawn = current * shares_redeemed / total_user_shares_before
    let principal_withdrawn = current
        .checked_mul(shares_redeemed)
        .unwrap_or_else(|| panic_with_error!(e, StorageError::PrincipalOverflow))
        .checked_div(total_user_shares_before)
        .unwrap_or_else(|| panic_with_error!(e, StorageError::PrincipalOverflow));

    let new_principal = current.saturating_sub(principal_withdrawn);
    if new_principal == 0 {
        e.storage().persistent().remove(&key);
    } else {
        e.storage().persistent().set(&key, &new_principal);
        e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
    }
}

/// Devuelve el principal depositado por el usuario.
pub fn get_principal(e: &Env, user: &Address) -> i128 {
    let key = StorageKey::UserPrincipal(user.clone());
    if let Some(val) = e.storage().persistent().get(&key) {
        e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
        val
    } else {
        0
    }
}
