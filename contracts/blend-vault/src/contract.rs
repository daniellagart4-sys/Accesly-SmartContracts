//! # Accesly — Blend Vault (SEP-56 / ERC-4626)
//!
//! Vault tokenizado que usa Blend Protocol como estrategia de yield.
//! Contrato compartido: un deploy, todos los Smart Accounts lo usan.
//!
//! ## Flujo
//!
//! Depósito:
//!   Smart Account aprueba USDC al Vault → llama `deposit(amount, receiver)` →
//!   Vault envía USDC a Blend pool → Vault emite shares al Smart Account.
//!
//! Retiro:
//!   Smart Account llama `redeem(shares, receiver)` →
//!   Vault retira USDC de Blend → devuelve USDC al receiver.
//!
//! Distribución de yield (llamada por relayer Lambda):
//!   Relayer llama `distribute_yield(smart_account, developer, accesly)` →
//!   SmartAccount.require_auth() → __check_auth dispara blend-yield-policy →
//!   Policy valida condiciones → Vault retira yield de Blend → divide 60/30/10.
//!
//! ## `total_assets()` override
//!
//! Lee las posiciones del vault en Blend + b_rate para convertir bTokens→USDC.
//! Esto hace que las shares aprecien con el yield de Blend automáticamente.
//!
//! ## Constructor params (testnet)
//!   - usdc_address: USDC SAC en testnet
//!   - blend_pool: Blend pool contract en testnet
//!   - usdc_reserve_index: índice de USDC en el pool (verificar en testnet)
//!   - name/symbol: metadatos del share token (e.g. "Accesly Blend USDC", "abUSDC")
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error,
    contracterror, token, Address, Env, MuxedAddress, String,
};
use stellar_tokens::{
    fungible::{Base, FungibleToken},
    vault::{emit_deposit, emit_withdraw, FungibleVault, Vault, VaultTokenError},
};

use crate::{
    blend_client,
    storage,
};

// ── Errores ───────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum BlendVaultError {
    /// No hay yield suficiente para distribuir.
    NoYield = 8000,
    /// El monto de distribución excede el yield disponible.
    ExceedsYield = 8001,
    /// Addresses de distribución no coinciden con las configuradas.
    InvalidRecipients = 8002,
}

// ── Struct de posición del usuario ────────────────────────────────────────────

/// Posición de un Smart Account en el Vault.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct UserPosition {
    /// Shares del vault que posee el usuario.
    pub shares: i128,
    /// Valor actual en USDC (incluye yield acumulado).
    pub current_value: i128,
    /// USDC depositado originalmente (principal).
    pub principal: i128,
    /// Yield acumulado = current_value - principal (0 si negativo).
    pub yield_accrued: i128,
}

// ── Contrato ──────────────────────────────────────────────────────────────────

#[contract]
pub struct BlendVaultContract;

#[contractimpl]
impl BlendVaultContract {
    /// Inicializa el Vault.
    ///
    /// # Arguments
    /// * `usdc_address`        — USDC SAC address en testnet.
    /// * `blend_pool`          — Dirección del pool de Blend en testnet.
    /// * `usdc_reserve_index`  — Índice del reserve USDC en el pool (verificar).
    /// * `name`                — Nombre del share token (e.g. "Accesly Blend USDC").
    /// * `symbol`              — Símbolo del share token (e.g. "abUSDC").
    pub fn __constructor(
        e: &Env,
        usdc_address: Address,
        blend_pool: Address,
        usdc_reserve_index: u32,
        name: String,
        symbol: String,
    ) {
        // Guarda config del vault (asset subyacente = USDC)
        Vault::set_asset(e, usdc_address);
        // decimals_offset = 0 (shares y USDC tienen la misma precisión)
        Vault::set_decimals_offset(e, 0);
        Base::set_metadata(e, Self::decimals(e), name, symbol);

        // Guarda config de Blend
        storage::set_blend_pool(e, &blend_pool);
        storage::set_usdc_reserve_index(e, usdc_reserve_index);
    }
}

// ── FungibleToken (OZ base) ───────────────────────────────────────────────────

#[contractimpl(contracttrait)]
impl FungibleToken for BlendVaultContract {
    type ContractType = Vault;

    fn decimals(e: &Env) -> u32 {
        Vault::decimals(e)
    }
}

// ── FungibleVault (SEP-56) con Blend backend ──────────────────────────────────

#[contractimpl(contracttrait)]
impl FungibleVault for BlendVaultContract {
    // ── Override: total_assets lee de Blend, no del balance propio ──────────

    /// Valor total de los activos del vault en USDC.
    /// Lee las posiciones del vault en Blend y convierte bTokens → USDC
    /// usando el b_rate actual. Crece automáticamente con el yield de Blend.
    fn total_assets(e: &Env) -> i128 {
        let pool = storage::get_blend_pool(e);
        let reserve_index = storage::get_usdc_reserve_index(e);

        let positions = blend_client::get_positions(e, &pool);
        let b_tokens = positions.collateral.get(reserve_index).unwrap_or(0);

        if b_tokens == 0 {
            return 0;
        }

        let usdc = Vault::query_asset(e);
        let b_rate = blend_client::get_b_rate(e, &pool, &usdc);
        blend_client::b_tokens_to_usdc(b_tokens, b_rate)
    }

    // ── Override: deposit → USDC va a Blend ──────────────────────────────────

    /// Deposita `assets` USDC en el Vault y emite shares al `receiver`.
    /// El USDC se deposita en Blend como colateral. El `operator` debe
    /// estar autorizado por el Smart Account.
    fn deposit(
        e: &Env,
        assets: i128,
        receiver: Address,
        from: Address,
        operator: Address,
    ) -> i128 {
        operator.require_auth();

        let max = Vault::max_deposit(e, receiver.clone());
        if assets > max {
            panic_with_error!(e, VaultTokenError::VaultExceededMaxDeposit);
        }

        let shares = Vault::preview_deposit(e, assets);

        // 1. Transferir USDC del `from` al vault
        let usdc = Vault::query_asset(e);
        let usdc_client = token::Client::new(e, &usdc);
        if operator == from {
            usdc_client.transfer(&from, &e.current_contract_address(), &assets);
        } else {
            usdc_client.transfer_from(&operator, &from, &e.current_contract_address(), &assets);
        }

        // 2. Depositar USDC en Blend (vault → Blend pool)
        let pool = storage::get_blend_pool(e);
        blend_client::supply_collateral(e, &pool, &usdc, assets);

        // 3. Emitir shares al receiver
        Base::update(e, None, Some(&receiver), shares);

        // 4. Registrar principal del receiver
        storage::add_principal(e, &receiver, assets);

        emit_deposit(e, &operator, &from, &receiver, assets, shares);
        shares
    }

    // ── Override: redeem → retira de Blend ───────────────────────────────────

    /// Quema `shares` del vault y devuelve USDC al `receiver`.
    /// Retira los activos desde el pool de Blend.
    fn redeem(
        e: &Env,
        shares: i128,
        receiver: Address,
        owner: Address,
        operator: Address,
    ) -> i128 {
        operator.require_auth();

        let max = Vault::max_redeem(e, owner.clone());
        if shares > max {
            panic_with_error!(e, VaultTokenError::VaultExceededMaxRedeem);
        }

        let assets = Vault::preview_redeem(e, shares);

        // Guardar shares antes de quemar (para cálculo proporcional de principal)
        let shares_before = Base::balance(e, &owner);

        // 1. Quemar shares
        if operator != owner {
            Base::spend_allowance(e, &owner, &operator, shares);
        }
        Base::update(e, Some(&owner), None, shares);

        // 2. Retirar USDC de Blend → receiver
        let pool = storage::get_blend_pool(e);
        let usdc = Vault::query_asset(e);
        blend_client::withdraw_collateral(e, &pool, &usdc, assets, &receiver);

        // 3. Actualizar principal del owner (reducción proporcional)
        storage::reduce_principal_proportional(e, &owner, shares, shares_before);

        emit_withdraw(e, &operator, &receiver, &owner, assets, shares);
        assets
    }

    // ── Override: withdraw → retira de Blend por monto exacto ────────────────

    fn withdraw(
        e: &Env,
        assets: i128,
        receiver: Address,
        owner: Address,
        operator: Address,
    ) -> i128 {
        operator.require_auth();

        let max = Vault::max_withdraw(e, owner.clone());
        if assets > max {
            panic_with_error!(e, VaultTokenError::VaultExceededMaxWithdraw);
        }

        let shares = Vault::preview_withdraw(e, assets);
        let shares_before = Base::balance(e, &owner);

        if operator != owner {
            Base::spend_allowance(e, &owner, &operator, shares);
        }
        Base::update(e, Some(&owner), None, shares);

        let pool = storage::get_blend_pool(e);
        let usdc = Vault::query_asset(e);
        blend_client::withdraw_collateral(e, &pool, &usdc, assets, &receiver);

        storage::reduce_principal_proportional(e, &owner, shares, shares_before);

        emit_withdraw(e, &operator, &receiver, &owner, assets, shares);
        shares
    }
}

// ── Funciones extra ───────────────────────────────────────────────────────────

#[contractimpl]
impl BlendVaultContract {
    /// Devuelve la posición completa de un Smart Account en el Vault.
    /// Usado por la blend-yield-policy y el SDK para calcular yield vs principal.
    pub fn get_position(e: Env, account: Address) -> UserPosition {
        let shares = Base::balance(&e, &account);

        // Calcula current_value usando total_assets de Blend (no el balance USDC del vault),
        // proporcional a las shares del usuario sobre el total de shares emitidas.
        let total_supply = Base::total_supply(&e);
        let total_ta = BlendVaultContract::total_assets(&e);
        let current_value = if total_supply == 0 || shares == 0 {
            0
        } else {
            shares
                .checked_mul(total_ta)
                .unwrap_or(i128::MAX)
                .checked_div(total_supply)
                .unwrap_or(0)
        };

        let principal = storage::get_principal(&e, &account);
        let yield_accrued = current_value.saturating_sub(principal);

        UserPosition { shares, current_value, principal, yield_accrued }
    }

    /// Distribuye el yield acumulado de un Smart Account: 60% al usuario,
    /// 30% al developer, 10% a Accesly.
    ///
    /// Solo retira el yield (principal intocable).
    /// Requiere autorización del Smart Account — esto dispara `__check_auth`
    /// con la context rule `yield-blend`, que valida todo con la blend-yield-policy.
    ///
    /// Llamada por el relayer Lambda (sin firma del usuario).
    pub fn distribute_yield(
        e: Env,
        smart_account: Address,
        developer_wallet: Address,
        accesly_wallet: Address,
    ) {
        // Requiere auth del Smart Account → dispara blend-yield-policy
        smart_account.require_auth();

        let position = Self::get_position(e.clone(), smart_account.clone());

        if position.yield_accrued <= 0 {
            panic_with_error!(&e, BlendVaultError::NoYield);
        }

        let yield_amount = position.yield_accrued;

        // Calcular partes (60/30/10)
        // Usamos aritmética de enteros: primero 10% y 30%, el resto al usuario.
        let accesly_part   = yield_amount / 10;           // 10%
        let developer_part = yield_amount * 30 / 100;     // 30%
        let user_part      = yield_amount - accesly_part - developer_part; // 60%

        let pool = storage::get_blend_pool(&e);
        let usdc = Vault::query_asset(&e);
        let usdc_client = token::Client::new(&e, &usdc);

        // Retirar yield total de Blend al vault (temporalmente)
        blend_client::withdraw_collateral(&e, &pool, &usdc, yield_amount, &e.current_contract_address());

        // Distribuir desde el vault
        usdc_client.transfer(&e.current_contract_address(), &smart_account, &user_part);
        usdc_client.transfer(&e.current_contract_address(), &developer_wallet, &developer_part);
        usdc_client.transfer(&e.current_contract_address(), &accesly_wallet, &accesly_part);

        // El principal no se toca — solo actualizamos el stored principal para
        // reflejar que el yield fue extraído (el valor en Blend bajó = bTokens quemados).
        // El principal sigue igual porque solo se retiró yield, no principal.
    }
}
