//! # Accesly — Yield Distribution Policy (CETES 50/50)
//!
//! Política de distribución automática de yield CETES.
//!
//! Regla 5 (Issue 1.9): sin firma del usuario, solo yield, semanal.
//! - El principal es intocable: la política solo autoriza llamadas al
//!   método de harvest/claim del contrato CETES configurado.
//! - Máximo 50% del yield va a la wallet de Accesly (configurable en BPS).
//! - Periodo mínimo entre distribuciones: `period_ledgers` (~120960 = 1 semana).
//! - Desactivable por el Smart Account con biométrico (regla admin-cfg).
//!
//! Sobre la división 50/50:
//!   Esta política valida que la llamada sea al contrato CETES correcto y a la
//!   función de harvest. La división del yield la construye el relayer/SDK en
//!   la transacción: incluye la llamada harvest + transfer del 50% a Accesly.
//!   La política valida el contrato, función, timing y estado enabled — el
//!   enforcement del split exacto requiere conocer el ABI del contrato CETES
//!   de Etherfuse (se completa cuando el contrato esté disponible en testnet).
use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contractimpl, contracttype, panic_with_error,
    contracterror, Address, Bytes, Env, Symbol, Vec,
};
use stellar_accounts::{
    policies::Policy,
    smart_account::{ContextRule, Signer},
};

// ── Constantes ────────────────────────────────────────────────────────────────

const DAY_IN_LEDGERS: u32 = 17_280;
const EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const TTL_THRESHOLD: u32 = EXTEND_AMOUNT - DAY_IN_LEDGERS;

/// Semana en ledgers (~7 días a ~5s por ledger).
pub const WEEK_IN_LEDGERS: u32 = 7 * DAY_IN_LEDGERS;

/// BPS máximo que puede ir a Accesly (50% = 5000 bps).
pub const MAX_ACCESLY_BPS: u32 = 5_000;

// ── Errores ──────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum YieldDistError {
    /// Política no instalada para esta cuenta y context rule.
    NotInstalled = 7000,
    /// Ya existe configuración para esta cuenta y context rule.
    AlreadyInstalled = 7001,
    /// La distribución automática está desactivada.
    Disabled = 7002,
    /// Período mínimo entre distribuciones no cumplido.
    PeriodNotElapsed = 7003,
    /// La función llamada no es la de harvest autorizada.
    UnauthorizedFunction = 7004,
    /// El contrato llamado no es el CETES autorizado.
    UnauthorizedContract = 7005,
    /// BPS de Accesly supera el máximo permitido (5000).
    BpsExceedsMax = 7006,
}

// ── Storage ──────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
enum StorageKey {
    YieldConfig(Address, u32), // (smart_account, context_rule_id)
}

/// Configuración + estado de la distribución de yield para un Smart Account.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct YieldConfig {
    /// Dirección del contrato CETES/Etherfuse.
    pub cetes_contract: Address,
    /// Nombre de la función de harvest (e.g. Symbol::new("harvest")).
    pub harvest_fn: Symbol,
    /// Wallet de Accesly que recibe su parte del yield.
    pub accesly_wallet: Address,
    /// Ledgers mínimos entre distribuciones (default: WEEK_IN_LEDGERS).
    pub period_ledgers: u32,
    /// Porcentaje del yield en BPS que va a Accesly (máx 5000 = 50%).
    pub accesly_bps: u32,
    /// Último ledger en que se distribuyó. 0 = nunca.
    pub last_distribution: u32,
    /// Si está en false, la política rechaza cualquier distribución.
    pub enabled: bool,
}

// ── Parámetros de instalación ─────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct YieldInstallParams {
    pub cetes_contract: Address,
    pub harvest_fn: Symbol,
    pub accesly_wallet: Address,
    pub period_ledgers: u32,
    pub accesly_bps: u32,
}

// ── Helpers de storage ────────────────────────────────────────────────────────

fn load_config(e: &Env, smart_account: &Address, context_rule_id: u32) -> YieldConfig {
    let key = StorageKey::YieldConfig(smart_account.clone(), context_rule_id);
    match e.storage().persistent().get::<StorageKey, YieldConfig>(&key) {
        Some(cfg) => {
            e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
            cfg
        }
        None => panic_with_error!(e, YieldDistError::NotInstalled),
    }
}

fn save_config(e: &Env, smart_account: &Address, context_rule_id: u32, cfg: &YieldConfig) {
    let key = StorageKey::YieldConfig(smart_account.clone(), context_rule_id);
    e.storage().persistent().set(&key, cfg);
    e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
}

// ── Contrato ──────────────────────────────────────────────────────────────────

#[contract]
pub struct YieldDistributionPolicy;

#[contractimpl]
impl Policy for YieldDistributionPolicy {
    type AccountParams = YieldInstallParams;

    /// Valida que la distribución de yield sea legítima.
    ///
    /// Checks:
    /// 1. Política habilitada.
    /// 2. Período mínimo cumplido.
    /// 3. Contrato objetivo es el CETES configurado.
    /// 4. Función llamada es la de harvest configurada.
    fn enforce(
        e: &Env,
        context: Context,
        _authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        let mut cfg = load_config(e, &smart_account, context_rule.id);

        // 1. Habilitado
        if !cfg.enabled {
            panic_with_error!(e, YieldDistError::Disabled);
        }

        // 2. Período mínimo
        let current = e.ledger().sequence();
        if cfg.last_distribution > 0
            && current < cfg.last_distribution + cfg.period_ledgers
        {
            panic_with_error!(e, YieldDistError::PeriodNotElapsed);
        }

        // 3. Validar contrato y función del contexto
        if let Context::Contract(ContractContext { contract, fn_name, .. }) = &context {
            if contract != &cfg.cetes_contract {
                panic_with_error!(e, YieldDistError::UnauthorizedContract);
            }
            if fn_name != &cfg.harvest_fn {
                panic_with_error!(e, YieldDistError::UnauthorizedFunction);
            }
        }

        // 4. Actualizar timestamp de última distribución
        cfg.last_distribution = current;
        save_config(e, &smart_account, context_rule.id, &cfg);
    }

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        let key = StorageKey::YieldConfig(smart_account.clone(), context_rule.id);
        if e.storage().persistent().has(&key) {
            panic_with_error!(e, YieldDistError::AlreadyInstalled);
        }
        if install_params.accesly_bps > MAX_ACCESLY_BPS {
            panic_with_error!(e, YieldDistError::BpsExceedsMax);
        }
        let cfg = YieldConfig {
            cetes_contract: install_params.cetes_contract,
            harvest_fn: install_params.harvest_fn,
            accesly_wallet: install_params.accesly_wallet,
            period_ledgers: install_params.period_ledgers,
            accesly_bps: install_params.accesly_bps,
            last_distribution: 0,
            enabled: true,
        };
        save_config(e, &smart_account, context_rule.id, &cfg);
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        let key = StorageKey::YieldConfig(smart_account.clone(), context_rule.id);
        if !e.storage().persistent().has(&key) {
            panic_with_error!(e, YieldDistError::NotInstalled);
        }
        e.storage().persistent().remove(&key);
    }
}

#[contractimpl]
impl YieldDistributionPolicy {
    /// Activa o desactiva la distribución automática.
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

    /// Consulta la configuración actual de yield para un Smart Account.
    pub fn get_config(
        e: Env,
        context_rule_id: u32,
        smart_account: Address,
    ) -> YieldConfig {
        load_config(&e, &smart_account, context_rule_id)
    }

    /// Calcula cuántos ledgers faltan para la próxima distribución permitida.
    /// Devuelve 0 si ya es posible distribuir.
    pub fn ledgers_until_next(
        e: Env,
        context_rule_id: u32,
        smart_account: Address,
    ) -> u32 {
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
        contract,
        testutils::{Address as _, Ledger},
        Address, Env, IntoVal, String, Vec,
    };
    use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

    use super::*;

    #[contract]
    struct MockContract;

    fn make_rule(e: &Env) -> ContextRule {
        ContextRule {
            id: 4,
            context_type: ContextRuleType::Default,
            name: String::from_str(e, "yield-auto"),
            signers: Vec::new(e),
            signer_ids: Vec::new(e),
            policies: Vec::new(e),
            policy_ids: Vec::new(e),
            valid_until: None,
        }
    }

    fn make_params(e: &Env, cetes: &Address, accesly: &Address) -> YieldInstallParams {
        YieldInstallParams {
            cetes_contract: cetes.clone(),
            harvest_fn: Symbol::new(e, "harvest"),
            accesly_wallet: accesly.clone(),
            period_ledgers: WEEK_IN_LEDGERS,
            accesly_bps: 5000,
        }
    }

    fn harvest_ctx(e: &Env, cetes: &Address) -> Context {
        Context::Contract(ContractContext {
            contract: cetes.clone(),
            fn_name: Symbol::new(e, "harvest"),
            args: soroban_sdk::Vec::new(e),
        })
    }

    // ── install ───────────────────────────────────────────────────────────────

    #[test]
    fn install_success() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
            let cfg = YieldDistributionPolicy::get_config(e.clone(), rule.id, account.clone());
            assert_eq!(cfg.cetes_contract, cetes);
            assert_eq!(cfg.accesly_bps, 5000);
            assert!(cfg.enabled);
            assert_eq!(cfg.last_distribution, 0);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #7001)")]
    fn install_twice_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #7006)")]
    fn install_bps_exceeds_max_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            let mut params = make_params(&e, &cetes, &accesly);
            params.accesly_bps = 5001;
            YieldDistributionPolicy::install(&e, params, rule.clone(), account.clone());
        });
    }

    // ── uninstall ─────────────────────────────────────────────────────────────

    #[test]
    fn uninstall_success() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
            YieldDistributionPolicy::uninstall(&e, rule.clone(), account.clone());
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #7000)")]
    fn uninstall_not_installed_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            YieldDistributionPolicy::uninstall(&e, rule.clone(), account.clone());
        });
    }

    // ── set_enabled ───────────────────────────────────────────────────────────

    #[test]
    fn set_enabled_false_then_true() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            YieldDistributionPolicy::set_enabled(e.clone(), rule.id, account.clone(), false);
            let cfg = YieldDistributionPolicy::get_config(e.clone(), rule.id, account.clone());
            assert!(!cfg.enabled);
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            YieldDistributionPolicy::set_enabled(e.clone(), rule.id, account.clone(), true);
            let cfg = YieldDistributionPolicy::get_config(e.clone(), rule.id, account.clone());
            assert!(cfg.enabled);
        });
    }

    // ── enforce ───────────────────────────────────────────────────────────────

    #[test]
    fn enforce_valid_passes_and_updates_timestamp() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 1000);

        e.as_contract(&addr, || {
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
            YieldDistributionPolicy::enforce(
                &e, harvest_ctx(&e, &cetes), Vec::new(&e), rule.clone(), account.clone(),
            );
            let cfg = YieldDistributionPolicy::get_config(e.clone(), rule.id, account.clone());
            assert_eq!(cfg.last_distribution, 1000);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #7002)")]
    fn enforce_disabled_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
            YieldDistributionPolicy::set_enabled(e.clone(), rule.id, account.clone(), false);
            YieldDistributionPolicy::enforce(
                &e, harvest_ctx(&e, &cetes), Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #7003)")]
    fn enforce_period_not_elapsed_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 1000);

        e.as_contract(&addr, || {
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
            // Primera distribución: ok
            YieldDistributionPolicy::enforce(
                &e, harvest_ctx(&e, &cetes), Vec::new(&e), rule.clone(), account.clone(),
            );
            // Segunda inmediata: falla
            YieldDistributionPolicy::enforce(
                &e, harvest_ctx(&e, &cetes), Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #7005)")]
    fn enforce_wrong_contract_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let wrong = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
            YieldDistributionPolicy::enforce(
                &e, harvest_ctx(&e, &wrong), Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #7004)")]
    fn enforce_wrong_function_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
            let bad_ctx = Context::Contract(ContractContext {
                contract: cetes.clone(),
                fn_name: Symbol::new(&e, "transfer"),
                args: soroban_sdk::Vec::new(&e),
            });
            YieldDistributionPolicy::enforce(&e, bad_ctx, Vec::new(&e), rule.clone(), account.clone());
        });
    }

    #[test]
    fn enforce_second_ok_after_period_elapsed() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 1000);

        e.as_contract(&addr, || {
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
            YieldDistributionPolicy::enforce(
                &e, harvest_ctx(&e, &cetes), Vec::new(&e), rule.clone(), account.clone(),
            );
        });

        e.ledger().with_mut(|l| l.sequence_number = 1000 + WEEK_IN_LEDGERS);

        e.as_contract(&addr, || {
            YieldDistributionPolicy::enforce(
                &e, harvest_ctx(&e, &cetes), Vec::new(&e), rule.clone(), account.clone(),
            );
            let cfg = YieldDistributionPolicy::get_config(e.clone(), rule.id, account.clone());
            assert_eq!(cfg.last_distribution, 1000 + WEEK_IN_LEDGERS);
        });
    }

    // ── ledgers_until_next ────────────────────────────────────────────────────

    #[test]
    fn ledgers_until_next_zero_on_first() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
            // last_distribution = 0, so always available
            let remaining = YieldDistributionPolicy::ledgers_until_next(e.clone(), rule.id, account.clone());
            assert_eq!(remaining, 0);
        });
    }

    #[test]
    fn ledgers_until_next_nonzero_after_distribution() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let cetes = Address::generate(&e);
        let accesly = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 1000);

        e.as_contract(&addr, || {
            YieldDistributionPolicy::install(&e, make_params(&e, &cetes, &accesly), rule.clone(), account.clone());
            YieldDistributionPolicy::enforce(
                &e, harvest_ctx(&e, &cetes), Vec::new(&e), rule.clone(), account.clone(),
            );
            let remaining = YieldDistributionPolicy::ledgers_until_next(e.clone(), rule.id, account.clone());
            assert_eq!(remaining, WEEK_IN_LEDGERS);
        });
    }
}
