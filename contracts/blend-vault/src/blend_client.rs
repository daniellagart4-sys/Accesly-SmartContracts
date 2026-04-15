//! # Blend Protocol Client (Testnet)
//!
//! Wrapper de cross-contract calls al Pool de Blend v2.
//!
//! ⚠️ TESTNET NOTE:
//!   Los tipos `BlendPositions` y `BlendReserveData` deben coincidir
//!   EXACTAMENTE con los structs del contrato Pool de Blend desplegado
//!   en testnet (orden de campos incluido). Verificar contra:
//!   https://github.com/blend-capital/blend-contracts-v2
//!
//! RequestType constants (Blend v2):
//!   0 = SupplyCollateral
//!   1 = WithdrawCollateral
//!
//! SCALAR_7 = 10^7 — factor de escala de b_rate de Blend.
//!   USDC_value = b_tokens * b_rate / SCALAR_7
use soroban_sdk::{contracttype, Address, Env, IntoVal, Map, Symbol, Vec};

pub const REQUEST_SUPPLY_COLLATERAL: u32 = 0;
pub const REQUEST_WITHDRAW_COLLATERAL: u32 = 1;
pub const SCALAR_7: i128 = 10_000_000;

// ── Tipos que deben coincidir con Blend v2 ────────────────────────────────────

/// Una acción dentro de una llamada submit al pool de Blend.
#[contracttype]
#[derive(Clone)]
pub struct BlendRequest {
    /// Tipo de operación (0=SupplyCollateral, 1=WithdrawCollateral, …)
    pub request_type: u32,
    /// Dirección del asset (USDC en testnet)
    pub address: Address,
    /// Monto en unidades del asset subyacente (stroops de USDC)
    pub amount: i128,
}

/// Posiciones del usuario/vault en el pool de Blend.
/// NOTA: Orden de campos debe ser idéntico al contrato Blend v2.
#[contracttype]
#[derive(Clone)]
pub struct BlendPositions {
    pub liabilities: Map<u32, i128>, // reserve_index -> dTokens
    pub collateral: Map<u32, i128>,  // reserve_index -> bTokens (supply collateral)
    pub supply: Map<u32, i128>,      // reserve_index -> bTokens (supply non-collateral)
}

/// Datos del reserve de Blend (sólo los campos que necesitamos).
/// NOTA: Blend v2 puede tener más campos — si la deserialización falla
/// en testnet, ajustar el struct para que coincida exactamente.
#[contracttype]
#[derive(Clone)]
pub struct BlendReserveData {
    pub b_rate: i128,         // tasa de cambio bToken→underlying, escalada por SCALAR_7
    pub d_rate: i128,         // tasa de cambio dToken→underlying
    pub ir_mod: i128,         // modificador de tasa de interés
    pub b_supply: i128,       // oferta total de bTokens
    pub d_supply: i128,       // oferta total de dTokens
    pub backstop_credit: i128,
    pub last_time: u64,
}

// ── Funciones ─────────────────────────────────────────────────────────────────

/// Deposita `amount` USDC como colateral en el pool de Blend.
/// Devuelve las posiciones actualizadas del vault.
pub fn supply_collateral(
    e: &Env,
    pool: &Address,
    usdc: &Address,
    amount: i128,
) -> BlendPositions {
    let vault = e.current_contract_address();
    let mut requests: Vec<BlendRequest> = Vec::new(e);
    requests.push_back(BlendRequest {
        request_type: REQUEST_SUPPLY_COLLATERAL,
        address: usdc.clone(),
        amount,
    });

    e.invoke_contract::<BlendPositions>(
        pool,
        &Symbol::new(e, "submit"),
        soroban_sdk::vec![
            e,
            vault.clone().into_val(e),
            vault.clone().into_val(e),
            vault.into_val(e),
            requests.into_val(e),
        ],
    )
}

/// Retira `amount` USDC de colateral en Blend y lo envía a `receiver`.
/// Devuelve las posiciones actualizadas del vault.
pub fn withdraw_collateral(
    e: &Env,
    pool: &Address,
    usdc: &Address,
    amount: i128,
    receiver: &Address,
) -> BlendPositions {
    let vault = e.current_contract_address();
    let mut requests: Vec<BlendRequest> = Vec::new(e);
    requests.push_back(BlendRequest {
        request_type: REQUEST_WITHDRAW_COLLATERAL,
        address: usdc.clone(),
        amount,
    });

    e.invoke_contract::<BlendPositions>(
        pool,
        &Symbol::new(e, "submit"),
        soroban_sdk::vec![
            e,
            vault.clone().into_val(e),
            vault.clone().into_val(e),
            receiver.clone().into_val(e),
            requests.into_val(e),
        ],
    )
}

/// Obtiene las posiciones actuales del vault en el pool de Blend.
pub fn get_positions(e: &Env, pool: &Address) -> BlendPositions {
    let vault = e.current_contract_address();
    e.invoke_contract::<BlendPositions>(
        pool,
        &Symbol::new(e, "get_positions"),
        soroban_sdk::vec![e, vault.into_val(e)],
    )
}

/// Obtiene el b_rate actual del asset USDC en el pool de Blend.
/// b_rate determina cuánto USDC vale cada bToken: usdc = bTokens * b_rate / SCALAR_7
pub fn get_b_rate(e: &Env, pool: &Address, usdc: &Address) -> i128 {
    let reserve_data = e.invoke_contract::<BlendReserveData>(
        pool,
        &Symbol::new(e, "get_reserve_data"),
        soroban_sdk::vec![e, usdc.clone().into_val(e)],
    );
    reserve_data.b_rate
}

/// Calcula el valor en USDC de los bTokens del vault.
pub fn b_tokens_to_usdc(b_tokens: i128, b_rate: i128) -> i128 {
    b_tokens
        .checked_mul(b_rate)
        .unwrap_or(i128::MAX)
        .checked_div(SCALAR_7)
        .unwrap_or(0)
}
