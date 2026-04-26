extern crate std;

use soroban_sdk::{
    contract, contractimpl, contracttype,
    testutils::{Address as _, StellarAssetContract},
    token::StellarAssetClient,
    Address, Env, Map, String,
};

use crate::{
    blend_client::{BlendPositions, BlendReserveData, BlendRequest, SCALAR_7},
    contract::{BlendVaultContract, BlendVaultContractClient, UserPosition},
};

// ── Mock Blend Pool ───────────────────────────────────────────────────────────
// Simula el pool de Blend v2 con estado configurable desde los tests.

#[contracttype]
#[derive(Clone)]
enum MockPoolKey {
    BTokens,  // collateral bTokens del vault (reserve_index=0)
    BRate,    // b_rate actual
}

#[contract]
struct MockBlendPool;

#[contractimpl]
impl MockBlendPool {
    /// Configura los bTokens de colateral del vault en el mock
    pub fn set_b_tokens(e: Env, amount: i128) {
        e.storage().instance().set(&MockPoolKey::BTokens, &amount);
    }

    /// Configura el b_rate del mock
    pub fn set_b_rate(e: Env, rate: i128) {
        e.storage().instance().set(&MockPoolKey::BRate, &rate);
    }

    /// submit: simula depositar/retirar — no hace nada real en el mock,
    /// devuelve posiciones vacías
    pub fn submit(
        e: Env,
        _from: Address,
        _spender: Address,
        _to: Address,
        _requests: soroban_sdk::Vec<BlendRequest>,
    ) -> BlendPositions {
        let b_tokens: i128 = e.storage().instance().get(&MockPoolKey::BTokens).unwrap_or(0);
        let mut collateral = Map::new(&e);
        collateral.set(0u32, b_tokens);
        BlendPositions {
            liabilities: Map::new(&e),
            collateral,
            supply: Map::new(&e),
        }
    }

    /// get_positions: devuelve posiciones actuales del vault
    pub fn get_positions(e: Env, _account: Address) -> BlendPositions {
        let b_tokens: i128 = e.storage().instance().get(&MockPoolKey::BTokens).unwrap_or(0);
        let mut collateral = Map::new(&e);
        collateral.set(0u32, b_tokens);
        BlendPositions {
            liabilities: Map::new(&e),
            collateral,
            supply: Map::new(&e),
        }
    }

    /// get_reserve_data: devuelve datos del reserve con el b_rate configurado
    pub fn get_reserve_data(e: Env, _asset: Address) -> BlendReserveData {
        let b_rate: i128 = e.storage().instance().get(&MockPoolKey::BRate).unwrap_or(SCALAR_7);
        BlendReserveData {
            b_rate,
            d_rate: SCALAR_7,
            ir_mod: SCALAR_7,
            b_supply: 0,
            d_supply: 0,
            backstop_credit: 0,
            last_time: 0,
        }
    }
}

// ── Setup helpers ─────────────────────────────────────────────────────────────

struct Setup<'a> {
    e: Env,
    vault: Address,
    pool: Address,
    usdc: Address,
    usdc_admin: StellarAssetClient<'a>,
    user: Address,
}

fn setup(e: &Env) -> (Address, Address, Address, Address) {
    let pool = e.register(MockBlendPool, ());
    let usdc_issuer = Address::generate(e);
    let sac: StellarAssetContract = e.register_stellar_asset_contract_v2(usdc_issuer.clone());
    let usdc = sac.address();
    let accesly = Address::generate(e);
    let vault = e.register(
        BlendVaultContract,
        (&usdc, &pool, &0u32, &accesly, &String::from_str(e, "Accesly Blend USDC"), &String::from_str(e, "abUSDC")),
    );
    (vault, pool, usdc, usdc_issuer)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn deposit_mints_shares_and_supplies_blend() {
    let e = Env::default();
    e.mock_all_auths();

    let (vault, pool, usdc, usdc_issuer) = setup(&e);
    let usdc_admin = StellarAssetClient::new(&e, &usdc);
    let user = Address::generate(&e);

    // Mintear USDC al usuario
    usdc_admin.mint(&user, &1_000_000i128);

    // Configurar mock: b_rate = SCALAR_7 (1:1), sin bTokens iniciales
    MockBlendPoolClient::new(&e, &pool).set_b_rate(&SCALAR_7);
    MockBlendPoolClient::new(&e, &pool).set_b_tokens(&0i128);

    let client = BlendVaultContractClient::new(&e, &vault);
    let shares = client.deposit(&1_000_000i128, &user, &user, &user);

    // Con b_rate = 1:1 y decimals_offset = 0, shares == assets
    assert_eq!(shares, 1_000_000);
}

#[test]
fn get_position_no_deposit_returns_zeros() {
    let e = Env::default();
    e.mock_all_auths();

    let (vault, pool, _, _) = setup(&e);
    let user = Address::generate(&e);

    MockBlendPoolClient::new(&e, &pool).set_b_tokens(&0i128);
    MockBlendPoolClient::new(&e, &pool).set_b_rate(&SCALAR_7);

    let pos: UserPosition = BlendVaultContractClient::new(&e, &vault).get_position(&user);
    assert_eq!(pos.shares, 0);
    assert_eq!(pos.principal, 0);
    assert_eq!(pos.yield_accrued, 0);
}

#[test]
fn get_position_after_deposit_tracks_principal() {
    let e = Env::default();
    e.mock_all_auths();

    let (vault, pool, usdc, _) = setup(&e);
    let usdc_admin = StellarAssetClient::new(&e, &usdc);
    let user = Address::generate(&e);

    usdc_admin.mint(&user, &500_000i128);
    MockBlendPoolClient::new(&e, &pool).set_b_rate(&SCALAR_7);
    MockBlendPoolClient::new(&e, &pool).set_b_tokens(&0i128);

    let client = BlendVaultContractClient::new(&e, &vault);
    client.deposit(&500_000i128, &user, &user, &user);

    // Simular que Blend retornó 500_000 bTokens al vault
    MockBlendPoolClient::new(&e, &pool).set_b_tokens(&500_000i128);

    let pos: UserPosition = client.get_position(&user);
    assert_eq!(pos.principal, 500_000);
    assert_eq!(pos.shares, 500_000);
    // current_value = 500_000 * SCALAR_7 / SCALAR_7 = 500_000
    assert_eq!(pos.current_value, 500_000);
    assert_eq!(pos.yield_accrued, 0);
}

#[test]
fn get_position_shows_yield_when_b_rate_increases() {
    let e = Env::default();
    e.mock_all_auths();

    let (vault, pool, usdc, _) = setup(&e);
    let usdc_admin = StellarAssetClient::new(&e, &usdc);
    let user = Address::generate(&e);

    usdc_admin.mint(&user, &1_000_000i128);
    MockBlendPoolClient::new(&e, &pool).set_b_rate(&SCALAR_7); // 1:1 al depositar
    MockBlendPoolClient::new(&e, &pool).set_b_tokens(&0i128);

    let client = BlendVaultContractClient::new(&e, &vault);
    client.deposit(&1_000_000i128, &user, &user, &user);

    // Simular que el pool tiene 1_000_000 bTokens y el b_rate creció 10%
    // total_assets = 1_000_000 bTokens * 1.1 b_rate = 1_100_000 USDC
    let new_rate = SCALAR_7 * 11 / 10; // 1.1x
    MockBlendPoolClient::new(&e, &pool).set_b_tokens(&1_000_000i128);
    MockBlendPoolClient::new(&e, &pool).set_b_rate(&new_rate);

    let pos: UserPosition = client.get_position(&user);
    assert_eq!(pos.principal, 1_000_000);
    assert_eq!(pos.current_value, 1_100_000); // 1_000_000 bTokens * 1.1 b_rate
    assert_eq!(pos.yield_accrued, 100_000);   // 10% yield
}

#[test]
fn total_assets_reads_blend_positions() {
    let e = Env::default();
    e.mock_all_auths();

    let (vault, pool, _, _) = setup(&e);

    MockBlendPoolClient::new(&e, &pool).set_b_tokens(&2_000_000i128);
    MockBlendPoolClient::new(&e, &pool).set_b_rate(&SCALAR_7);

    let total = BlendVaultContractClient::new(&e, &vault).total_assets();
    assert_eq!(total, 2_000_000);
}

#[test]
fn b_tokens_to_usdc_math() {
    // 1000 bTokens * SCALAR_7 / SCALAR_7 = 1000
    assert_eq!(crate::blend_client::b_tokens_to_usdc(1000, SCALAR_7), Some(1000));
    // 1000 bTokens * (SCALAR_7 * 2) / SCALAR_7 = 2000
    assert_eq!(crate::blend_client::b_tokens_to_usdc(1000, SCALAR_7 * 2), Some(2000));
    // cero tokens → cero
    assert_eq!(crate::blend_client::b_tokens_to_usdc(0, SCALAR_7), Some(0));
}

#[test]
fn b_tokens_to_usdc_overflow_returns_none() {
    // Overflow returns None (caller panics with BlendVaultError::ArithmeticError).
    assert!(crate::blend_client::b_tokens_to_usdc(i128::MAX, i128::MAX).is_none());
}

#[test]
fn redeem_burns_shares_and_reduces_principal() {
    let e = Env::default();
    e.mock_all_auths();

    let (vault, pool, usdc, _) = setup(&e);
    let usdc_admin = StellarAssetClient::new(&e, &usdc);
    let user = Address::generate(&e);

    usdc_admin.mint(&user, &1_000_000i128);
    MockBlendPoolClient::new(&e, &pool).set_b_rate(&SCALAR_7);
    MockBlendPoolClient::new(&e, &pool).set_b_tokens(&0i128);

    let client = BlendVaultContractClient::new(&e, &vault);
    client.deposit(&1_000_000i128, &user, &user, &user);
    MockBlendPoolClient::new(&e, &pool).set_b_tokens(&1_000_000i128);

    // Mintear USDC al vault para simular que Blend devuelve tokens al retirar
    usdc_admin.mint(&vault, &500_000i128);

    client.redeem(&500_000i128, &user, &user, &user);

    let pos: UserPosition = client.get_position(&user);
    assert_eq!(pos.principal, 500_000); // 50% retirado proporcional
}
