//! # Accesly — Blend Yield Distribution Policy (60/30/10)
//!
//! Política on-chain para distribución automática del yield generado en Blend.
//!
//! Distribución fija (constantes en el contrato, no configurables):
//!   60% → Smart Account del usuario
//!   30% → developer_wallet (definido por appId al instalar)
//!   10% → accesly_wallet (fija de Accesly)
//!
//! Flujo de ejecución (Regla 9, Issue 1.9 / Issue 11.3):
//!   1. Lambda `distributeYield` llama `blend_vault.distribute_yield(smart_account, dev, accesly)`
//!   2. El vault llama `smart_account.require_auth()`
//!   3. `__check_auth` evalúa la context rule `yield-blend` (CallContract(blend_vault))
//!   4. Esta política valida on-chain todas las condiciones
//!   5. Si todo pasa, el vault ejecuta la distribución
//!
//! Seguridad:
//!   - Sin firma del usuario: cualquiera puede llamar, pero la policy valida todo
//!   - developer_wallet y accesly_wallet fijos al instalar — no modificables sin biométrico
//!   - Principal intocable: la policy verifica yield_accrued > 0 en el vault
//!   - Porcentajes 60/30/10 son constantes en el código del contrato
//!   - Cada Smart Account tiene su propia configuración (por appId)
//!   - Coexiste con CETES 50/50: context rules separadas, storage separado
use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contractimpl, contracttype, panic_with_error,
    contracterror, Address, Env, IntoVal, Symbol, TryFromVal, Vec,
};
use stellar_accounts::{
    policies::Policy,
    smart_account::{ContextRule, Signer},
};

// ── Constantes ────────────────────────────────────────────────────────────────

const DAY_IN_LEDGERS: u32 = 17_280;
pub const WEEK_IN_LEDGERS: u32 = 7 * DAY_IN_LEDGERS;

const EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const TTL_THRESHOLD: u32 = EXTEND_AMOUNT - DAY_IN_LEDGERS;

/// Porcentajes fijos. Immutables sin upgrade + timelock 48h.
pub const USER_PCT: u32 = 60;
pub const DEVELOPER_PCT: u32 = 30;
pub const ACCESLY_PCT: u32 = 10;

// ── Errores ──────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum BlendYieldPolicyError {
    /// Política no instalada para esta cuenta y context rule.
    NotInstalled = 9000,
    /// Ya instalada para esta cuenta y context rule.
    AlreadyInstalled = 9001,
    /// Distribución deshabilitada.
    Disabled = 9002,
    /// Período mínimo semanal no cumplido.
    PeriodNotElapsed = 9003,
    /// La función del contexto no es `distribute_yield`.
    UnauthorizedFunction = 9004,
    /// El contrato del contexto no es el vault configurado.
    UnauthorizedVault = 9005,
    /// Los wallets destino en los args no coinciden con los configurados.
    WrongRecipients = 9006,
    /// El yield acumulado en el vault es 0 o negativo.
    NoYieldAvailable = 9007,
    /// El contexto de autorización no es un llamado a contrato.
    InvalidContext = 9008,
    /// args[0] no coincide con el smart_account autorizado.
    WrongSmartAccount = 9009,
    /// accesly_wallet en install_params no coincide con la wallet canónica del contrato.
    InvalidAcceslyWallet = 9010,
    /// El constructor ya fue llamado — no se puede reinicializar.
    AlreadyInitialized = 9011,
}

// ── Storage ──────────────────────────────────────────────────────────────────

/// Instance storage key — holds contract-level config set at deploy time.
#[contracttype]
#[derive(Clone)]
enum InstanceKey {
    AcceslyWallet,
}

#[contracttype]
#[derive(Clone)]
enum StorageKey {
    Config(Address, u32), // (smart_account, context_rule_id)
}

/// Configuración instalada por Smart Account.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct BlendYieldConfig {
    /// Dirección del Blend Vault (Issue 11.2).
    pub blend_vault: Address,
    /// Wallet del developer (determinada por appId al instalar).
    pub developer_wallet: Address,
    /// Wallet fija de Accesly.
    pub accesly_wallet: Address,
    /// Ledgers mínimos entre distribuciones (default WEEK_IN_LEDGERS).
    pub period_ledgers: u32,
    /// Ledger de la última distribución. 0 = nunca.
    pub last_distribution: u32,
    /// Si false, la policy rechaza cualquier distribución.
    pub enabled: bool,
}

// ── Parámetros de instalación ─────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct BlendYieldInstallParams {
    pub blend_vault: Address,
    pub developer_wallet: Address,
    pub accesly_wallet: Address,
    pub period_ledgers: u32,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_config(e: &Env, smart_account: &Address, context_rule_id: u32) -> BlendYieldConfig {
    let key = StorageKey::Config(smart_account.clone(), context_rule_id);
    match e.storage().persistent().get(&key) {
        Some(cfg) => {
            e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
            cfg
        }
        None => panic_with_error!(e, BlendYieldPolicyError::NotInstalled),
    }
}

fn save_config(e: &Env, smart_account: &Address, context_rule_id: u32, cfg: &BlendYieldConfig) {
    let key = StorageKey::Config(smart_account.clone(), context_rule_id);
    e.storage().persistent().set(&key, cfg);
    e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
}

fn get_canonical_accesly_wallet(e: &Env) -> Address {
    e.storage()
        .instance()
        .get(&InstanceKey::AcceslyWallet)
        .expect("accesly wallet not set")
}

/// Llama `blend_vault.get_position(smart_account)` y devuelve el yield_accrued.
fn get_yield_from_vault(e: &Env, vault: &Address, smart_account: &Address) -> i128 {
    // Definimos sólo el campo que nos interesa de UserPosition.
    // Si el struct de UserPosition en blend-vault cambia de orden, ajustar aquí.
    #[contracttype]
    struct UserPosition {
        pub shares: i128,
        pub current_value: i128,
        pub principal: i128,
        pub yield_accrued: i128,
    }

    let position = e.invoke_contract::<UserPosition>(
        vault,
        &Symbol::new(e, "get_position"),
        soroban_sdk::vec![e, smart_account.clone().into_val(e)],
    );
    position.yield_accrued
}

// ── Contrato ──────────────────────────────────────────────────────────────────

#[contract]
pub struct BlendYieldPolicy;

#[contractimpl]
impl Policy for BlendYieldPolicy {
    type AccountParams = BlendYieldInstallParams;

    /// Valida on-chain que la distribución 60/30/10 sea legítima.
    ///
    /// Checks:
    /// 1. Policy habilitada.
    /// 2. Período semanal mínimo cumplido.
    /// 3. Contexto es `CallContract(blend_vault)` + función `distribute_yield`.
    /// 4. Args contienen el developer_wallet y accesly_wallet correctos.
    /// 5. El vault tiene yield acumulado > 0 para este Smart Account.
    fn enforce(
        e: &Env,
        context: Context,
        _authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        // Bind enforce to the SA's auth flow — prevents direct external calls.
        smart_account.require_auth();

        let mut cfg = load_config(e, &smart_account, context_rule.id);

        // 1. Habilitado
        if !cfg.enabled {
            panic_with_error!(e, BlendYieldPolicyError::Disabled);
        }

        // 2. Período mínimo — saturating_add prevents u32 wrap-around
        let current = e.ledger().sequence();
        if cfg.last_distribution > 0
            && current < cfg.last_distribution.saturating_add(cfg.period_ledgers)
        {
            panic_with_error!(e, BlendYieldPolicyError::PeriodNotElapsed);
        }

        // 3. Validar contexto: debe ser un llamado a contrato (fail closed)
        let (contract, fn_name, args) = match context {
            Context::Contract(ContractContext { contract, fn_name, args }) => (contract, fn_name, args),
            _ => panic_with_error!(e, BlendYieldPolicyError::InvalidContext),
        };

        if contract != cfg.blend_vault {
            panic_with_error!(e, BlendYieldPolicyError::UnauthorizedVault);
        }
        if fn_name != Symbol::new(e, "distribute_yield") {
            panic_with_error!(e, BlendYieldPolicyError::UnauthorizedFunction);
        }

        // 4. Validar args: distribute_yield(smart_account, developer_wallet, accesly_wallet)
        // args[0] = smart_account — must match the account being authorized
        let account_arg = args.get(0).and_then(|v| Address::try_from_val(e, &v).ok());
        if account_arg.map_or(true, |a| a != smart_account) {
            panic_with_error!(e, BlendYieldPolicyError::WrongSmartAccount);
        }

        let developer_arg = args.get(1).and_then(|v| Address::try_from_val(e, &v).ok());
        let accesly_arg   = args.get(2).and_then(|v| Address::try_from_val(e, &v).ok());

        let developer_ok = developer_arg.map_or(false, |a| a == cfg.developer_wallet);
        let accesly_ok   = accesly_arg.map_or(false, |a| a == cfg.accesly_wallet);

        if !developer_ok || !accesly_ok {
            panic_with_error!(e, BlendYieldPolicyError::WrongRecipients);
        }

        // 5. Verificar que haya yield disponible
        let yield_amount = get_yield_from_vault(e, &cfg.blend_vault, &smart_account);
        if yield_amount <= 0 {
            panic_with_error!(e, BlendYieldPolicyError::NoYieldAvailable);
        }

        // Actualizar timestamp de distribución
        cfg.last_distribution = current;
        save_config(e, &smart_account, context_rule.id, &cfg);
    }

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();

        // Validate accesly_wallet against the canonical address stored at deploy time.
        if install_params.accesly_wallet != get_canonical_accesly_wallet(e) {
            panic_with_error!(e, BlendYieldPolicyError::InvalidAcceslyWallet);
        }

        let key = StorageKey::Config(smart_account.clone(), context_rule.id);
        if e.storage().persistent().has(&key) {
            panic_with_error!(e, BlendYieldPolicyError::AlreadyInstalled);
        }
        let cfg = BlendYieldConfig {
            blend_vault: install_params.blend_vault,
            developer_wallet: install_params.developer_wallet,
            accesly_wallet: install_params.accesly_wallet,
            period_ledgers: install_params.period_ledgers,
            last_distribution: 0,
            enabled: true,
        };
        save_config(e, &smart_account, context_rule.id, &cfg);
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        let key = StorageKey::Config(smart_account.clone(), context_rule.id);
        if !e.storage().persistent().has(&key) {
            panic_with_error!(e, BlendYieldPolicyError::NotInstalled);
        }
        e.storage().persistent().remove(&key);
    }
}

#[contractimpl]
impl BlendYieldPolicy {
    /// Guarda la wallet canónica de Accesly en instance storage.
    /// Llamado una sola vez al desplegar el contrato.
    pub fn __constructor(e: &Env, accesly_wallet: Address) {
        if e.storage().instance().has(&InstanceKey::AcceslyWallet) {
            panic_with_error!(e, BlendYieldPolicyError::AlreadyInitialized);
        }
        e.storage().instance().set(&InstanceKey::AcceslyWallet, &accesly_wallet);
    }

    /// Habilita o deshabilita la distribución.
    /// Requiere autorización del Smart Account (context rule admin-cfg con biométrico).
    pub fn set_enabled(
        e: Env,
        context_rule_id: u32,
        smart_account: Address,
        enabled: bool,
    ) {
        smart_account.require_auth();
        let mut cfg = load_config(&e, &smart_account, context_rule_id);
        cfg.enabled = enabled;
        save_config(&e, &smart_account, context_rule_id, &cfg);
    }

    /// Consulta la configuración de la policy para un Smart Account.
    pub fn get_config(e: Env, context_rule_id: u32, smart_account: Address) -> BlendYieldConfig {
        load_config(&e, &smart_account, context_rule_id)
    }

    /// Ledgers restantes hasta la próxima distribución permitida (0 = ya disponible).
    pub fn ledgers_until_next(e: Env, context_rule_id: u32, smart_account: Address) -> u32 {
        let cfg = load_config(&e, &smart_account, context_rule_id);
        let current = e.ledger().sequence();
        if cfg.last_distribution == 0 {
            return 0;
        }
        let next = cfg.last_distribution.saturating_add(cfg.period_ledgers);
        if current >= next { 0 } else { next - current }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;

    use soroban_sdk::{
        auth::{Context, ContractContext},
        contract, contractimpl,
        testutils::{Address as _, Ledger},
        Address, Env, IntoVal, String, Symbol, Vec,
    };
    use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

    use super::*;

    // ── Mock Blend Vault ──────────────────────────────────────────────────────
    // Simula blend_vault.get_position(account) → UserPosition

    #[contracttype]
    #[derive(Clone)]
    enum MockKey { YieldAccrued }

    #[contract]
    struct MockBlendVault;

    #[contractimpl]
    impl MockBlendVault {
        /// Configura cuánto yield_accrued devolverá get_position
        pub fn set_yield(e: Env, yield_amount: i128) {
            e.storage().instance().set(&MockKey::YieldAccrued, &yield_amount);
        }

        /// Implementa el ABI que espera blend-yield-policy
        pub fn get_position(e: Env, _account: Address) -> MockUserPosition {
            let y: i128 = e.storage().instance().get(&MockKey::YieldAccrued).unwrap_or(0);
            MockUserPosition { shares: 0, current_value: y, principal: 0, yield_accrued: y }
        }
    }

    #[contracttype]
    #[derive(Clone)]
    pub struct MockUserPosition {
        pub shares: i128,
        pub current_value: i128,
        pub principal: i128,
        pub yield_accrued: i128,
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_rule(e: &Env, vault: &Address) -> ContextRule {
        ContextRule {
            id: 9,
            context_type: ContextRuleType::CallContract(vault.clone()),
            name: String::from_str(e, "yield-blend"),
            signers: Vec::new(e),
            signer_ids: Vec::new(e),
            policies: Vec::new(e),
            policy_ids: Vec::new(e),
            valid_until: None,
        }
    }

    fn make_params(vault: &Address, dev: &Address, accesly: &Address) -> BlendYieldInstallParams {
        BlendYieldInstallParams {
            blend_vault: vault.clone(),
            developer_wallet: dev.clone(),
            accesly_wallet: accesly.clone(),
            period_ledgers: WEEK_IN_LEDGERS,
        }
    }

    fn distribute_ctx(e: &Env, vault: &Address, smart_account: &Address, dev: &Address, accesly: &Address) -> Context {
        let mut args = soroban_sdk::Vec::new(e);
        args.push_back(smart_account.clone().into_val(e));
        args.push_back(dev.clone().into_val(e));
        args.push_back(accesly.clone().into_val(e));
        Context::Contract(ContractContext {
            contract: vault.clone(),
            fn_name: Symbol::new(e, "distribute_yield"),
            args,
        })
    }

    // ── install ───────────────────────────────────────────────────────────────

    #[test]
    fn install_success() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);
        e.mock_all_auths();

        e.as_contract(&policy, || {
            BlendYieldPolicy::install(&e, make_params(&vault, &dev, &accesly), rule.clone(), account.clone());
            let cfg = BlendYieldPolicy::get_config(e.clone(), rule.id, account.clone());
            assert!(cfg.enabled);
            assert_eq!(cfg.last_distribution, 0);
            assert_eq!(cfg.developer_wallet, dev);
            assert_eq!(cfg.accesly_wallet, accesly);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #9001)")]
    fn install_twice_fails() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);

        e.mock_all_auths();
        e.as_contract(&policy, || {
            BlendYieldPolicy::install(&e, make_params(&vault, &dev, &accesly), rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&policy, || {
            BlendYieldPolicy::install(&e, make_params(&vault, &dev, &accesly), rule.clone(), account.clone());
        });
    }

    // ── enforce: happy path ───────────────────────────────────────────────────

    #[test]
    fn enforce_valid_passes() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 1000);

        MockBlendVaultClient::new(&e, &vault).set_yield(&1_000_000i128);

        e.as_contract(&policy, || {
            BlendYieldPolicy::install(&e, make_params(&vault, &dev, &accesly), rule.clone(), account.clone());
        });

        e.as_contract(&policy, || {
            BlendYieldPolicy::enforce(
                &e,
                distribute_ctx(&e, &vault, &account, &dev, &accesly),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
            let cfg = BlendYieldPolicy::get_config(e.clone(), rule.id, account.clone());
            assert_eq!(cfg.last_distribution, 1000);
        });
    }

    // ── enforce: errores ──────────────────────────────────────────────────────

    #[test]
    #[should_panic(expected = "Error(Contract, #9002)")]
    fn enforce_disabled_fails() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);

        MockBlendVaultClient::new(&e, &vault).set_yield(&1_000_000i128);

        e.mock_all_auths();
        e.as_contract(&policy, || {
            BlendYieldPolicy::install(&e, make_params(&vault, &dev, &accesly), rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&policy, || {
            BlendYieldPolicy::set_enabled(e.clone(), rule.id, account.clone(), false);
        });

        e.as_contract(&policy, || {
            BlendYieldPolicy::enforce(
                &e,
                distribute_ctx(&e, &vault, &account, &dev, &accesly),
                Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #9003)")]
    fn enforce_period_not_elapsed_fails() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 1000);

        MockBlendVaultClient::new(&e, &vault).set_yield(&1_000_000i128);

        e.as_contract(&policy, || {
            BlendYieldPolicy::install(&e, make_params(&vault, &dev, &accesly), rule.clone(), account.clone());
        });

        e.as_contract(&policy, || {
            BlendYieldPolicy::enforce(
                &e, distribute_ctx(&e, &vault, &account, &dev, &accesly),
                Vec::new(&e), rule.clone(), account.clone(),
            );
        });

        // Segunda llamada inmediata: debe fallar con PeriodNotElapsed
        e.as_contract(&policy, || {
            BlendYieldPolicy::enforce(
                &e, distribute_ctx(&e, &vault, &account, &dev, &accesly),
                Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #9005)")]
    fn enforce_wrong_vault_fails() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let wrong_vault = Address::generate(&e);
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);
        e.mock_all_auths();

        MockBlendVaultClient::new(&e, &vault).set_yield(&1_000_000i128);

        e.as_contract(&policy, || {
            BlendYieldPolicy::install(&e, make_params(&vault, &dev, &accesly), rule.clone(), account.clone());
        });

        e.as_contract(&policy, || {
            BlendYieldPolicy::enforce(
                &e,
                distribute_ctx(&e, &wrong_vault, &account, &dev, &accesly),
                Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #9004)")]
    fn enforce_wrong_function_fails() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);
        e.mock_all_auths();

        MockBlendVaultClient::new(&e, &vault).set_yield(&1_000_000i128);

        e.as_contract(&policy, || {
            BlendYieldPolicy::install(&e, make_params(&vault, &dev, &accesly), rule.clone(), account.clone());
        });

        e.as_contract(&policy, || {
            let bad_ctx = Context::Contract(ContractContext {
                contract: vault.clone(),
                fn_name: Symbol::new(&e, "redeem"),
                args: soroban_sdk::Vec::new(&e),
            });
            BlendYieldPolicy::enforce(&e, bad_ctx, Vec::new(&e), rule.clone(), account.clone());
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #9006)")]
    fn enforce_wrong_recipients_fails() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let wrong_dev = Address::generate(&e); // dev incorrecto
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);
        e.mock_all_auths();

        MockBlendVaultClient::new(&e, &vault).set_yield(&1_000_000i128);

        e.as_contract(&policy, || {
            BlendYieldPolicy::install(&e, make_params(&vault, &dev, &accesly), rule.clone(), account.clone());
        });

        e.as_contract(&policy, || {
            BlendYieldPolicy::enforce(
                &e,
                distribute_ctx(&e, &vault, &account, &wrong_dev, &accesly),
                Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #9007)")]
    fn enforce_no_yield_fails() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);
        e.mock_all_auths();

        // yield = 0
        MockBlendVaultClient::new(&e, &vault).set_yield(&0i128);

        e.as_contract(&policy, || {
            BlendYieldPolicy::install(&e, make_params(&vault, &dev, &accesly), rule.clone(), account.clone());
        });

        e.as_contract(&policy, || {
            BlendYieldPolicy::enforce(
                &e,
                distribute_ctx(&e, &vault, &account, &dev, &accesly),
                Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    // ── ledgers_until_next ────────────────────────────────────────────────────

    #[test]
    fn ledgers_until_next_zero_on_first() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);
        e.mock_all_auths();

        e.as_contract(&policy, || {
            BlendYieldPolicy::install(&e, make_params(&vault, &dev, &accesly), rule.clone(), account.clone());
            assert_eq!(
                BlendYieldPolicy::ledgers_until_next(e.clone(), rule.id, account.clone()),
                0
            );
        });
    }

    // ── uninstall ─────────────────────────────────────────────────────────────

    #[test]
    fn uninstall_success() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);

        e.mock_all_auths();
        e.as_contract(&policy, || {
            BlendYieldPolicy::install(&e, make_params(&vault, &dev, &accesly), rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&policy, || {
            BlendYieldPolicy::uninstall(&e, rule.clone(), account.clone());
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #9000)")]
    fn uninstall_not_installed_fails() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let accesly = Address::generate(&e);
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let account = Address::generate(&e);
        let rule = make_rule(&e, &vault);
        e.mock_all_auths();

        e.as_contract(&policy, || {
            BlendYieldPolicy::uninstall(&e, rule.clone(), account.clone());
        });
    }

    // ── seguridad: enforce sin auth del SA ────────────────────────────────────

    #[test]
    #[should_panic]
    fn enforce_unauthorized_fails() {
        let e = Env::default();
        // NO mock_all_auths — enforce must fail at smart_account.require_auth().
        let vault = e.register(MockBlendVault, ());
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);
        e.ledger().with_mut(|l| l.sequence_number = 1000);

        MockBlendVaultClient::new(&e, &vault).set_yield(&1_000_000i128);

        // Insert config directly — bypasses install() which calls require_auth.
        e.as_contract(&policy, || {
            let cfg = BlendYieldConfig {
                blend_vault: vault.clone(),
                developer_wallet: dev.clone(),
                accesly_wallet: accesly.clone(),
                period_ledgers: WEEK_IN_LEDGERS,
                last_distribution: 0,
                enabled: true,
            };
            save_config(&e, &account, rule.id, &cfg);
        });

        // Enforce without any auth mock — smart_account.require_auth() must fail.
        e.as_contract(&policy, || {
            BlendYieldPolicy::enforce(
                &e,
                distribute_ctx(&e, &vault, &account, &dev, &accesly),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }

    // ── seguridad: accesly_wallet inválida en install ─────────────────────────

    #[test]
    #[should_panic(expected = "Error(Contract, #9010)")]
    fn install_invalid_accesly_wallet_fails() {
        let e = Env::default();
        let vault = e.register(MockBlendVault, ());
        let account = Address::generate(&e);
        let dev = Address::generate(&e);
        let accesly = Address::generate(&e);
        let wrong_accesly = Address::generate(&e); // distinta de la canónica
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));
        let rule = make_rule(&e, &vault);
        e.mock_all_auths();

        e.as_contract(&policy, || {
            // wrong_accesly != canonical accesly → debe fallar con InvalidAcceslyWallet
            BlendYieldPolicy::install(
                &e,
                make_params(&vault, &dev, &wrong_accesly),
                rule.clone(),
                account.clone(),
            );
        });
    }

    // ── constructor re-call guard ─────────────────────────────────────────────

    #[test]
    #[should_panic(expected = "Error(Contract, #9011)")]
    fn constructor_twice_fails() {
        let e = Env::default();
        let accesly = Address::generate(&e);
        let attacker = Address::generate(&e);
        // First call happens via e.register (constructor runs at deploy time).
        let policy = e.register(BlendYieldPolicy, (accesly.clone(),));

        // Second call must fail — attacker cannot overwrite canonical accesly_wallet.
        e.as_contract(&policy, || {
            BlendYieldPolicy::__constructor(&e, attacker);
        });
    }
}
