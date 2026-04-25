//! # Accesly — Blend Rule Policy
//!
//! Política que restringe una context rule a operar únicamente contra
//! un pool Blend específico, con tipos de request y monto por operación
//! configurados en el momento de instalación.
//!
//! Flujo:
//!   1. Smart Account instala la policy con `pool`, `allowed_request_types`
//!      y `max_amount_per_request` (0 = sin límite).
//!   2. `enforce` valida que cada llamada `submit` / `submit_with_allowance`
//!      vaya al pool autorizado, que el `from` sea el smart account y que
//!      cada request use un tipo permitido dentro del límite de monto.
use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contracterror, contractimpl, contracttype, panic_with_error,
    Address, Env, Symbol, TryFromVal, Vec,
};
use stellar_accounts::{
    policies::Policy,
    smart_account::{ContextRule, Signer},
};

// ── Request types (espejo del enum RequestType de Blend v2) ──────────────────

pub const REQUEST_SUPPLY: u32 = 0;
pub const REQUEST_WITHDRAW: u32 = 1;
pub const REQUEST_SUPPLY_COLLATERAL: u32 = 2;
pub const REQUEST_WITHDRAW_COLLATERAL: u32 = 3;
pub const REQUEST_BORROW: u32 = 4;
pub const REQUEST_REPAY: u32 = 5;

// ── TTL ───────────────────────────────────────────────────────────────────────

const DAY_IN_LEDGERS: u32 = 17280;
const EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const TTL_THRESHOLD: u32 = EXTEND_AMOUNT - DAY_IN_LEDGERS;

// ── Errores ───────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum BlendRuleError {
    NotInstalled = 6000,
    AlreadyInstalled = 6001,
    /// La llamada va a un pool distinto al autorizado.
    UnauthorizedPool = 6002,
    /// Función no permitida (solo submit/submit_with_allowance).
    UnauthorizedFunction = 6003,
    /// El tipo de request no está en la lista de permitidos.
    UnauthorizedRequestType = 6004,
    /// El monto del request supera el límite configurado.
    AmountExceeded = 6005,
    /// Los argumentos de la llamada no tienen el formato esperado.
    InvalidArgs = 6006,
    /// El campo `from` no es el smart account que instaló la policy.
    WrongFrom = 6007,
}

// ── Tipos de storage ──────────────────────────────────────────────────────────

/// Refleja el struct Request del pool Blend v2 para deserialización XDR.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub request_type: u32,
    pub address: Address,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct BlendRuleConfig {
    pub pool: Address,
    pub allowed_request_types: Vec<u32>,
    pub max_amount_per_request: i128,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct BlendRuleInstallParams {
    pub pool: Address,
    pub allowed_request_types: Vec<u32>,
    pub max_amount_per_request: i128,
}

#[contracttype]
enum StorageKey {
    Config(Address, u32),
}

// ── Helpers de storage ────────────────────────────────────────────────────────

fn load_config(e: &Env, smart_account: &Address, rule_id: u32) -> BlendRuleConfig {
    let key = StorageKey::Config(smart_account.clone(), rule_id);
    match e.storage().persistent().get::<StorageKey, BlendRuleConfig>(&key) {
        Some(cfg) => {
            e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
            cfg
        }
        None => panic_with_error!(e, BlendRuleError::NotInstalled),
    }
}

fn save_config(e: &Env, smart_account: &Address, rule_id: u32, cfg: &BlendRuleConfig) {
    let key = StorageKey::Config(smart_account.clone(), rule_id);
    e.storage().persistent().set(&key, cfg);
    e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
}

fn remove_config(e: &Env, smart_account: &Address, rule_id: u32) {
    e.storage().persistent().remove(&StorageKey::Config(smart_account.clone(), rule_id));
}

// ── Contrato ──────────────────────────────────────────────────────────────────

#[contract]
pub struct BlendRulePolicy;

#[contractimpl]
impl Policy for BlendRulePolicy {
    type AccountParams = BlendRuleInstallParams;

    fn enforce(
        e: &Env,
        context: Context,
        _authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        let cfg = load_config(e, &smart_account, context_rule.id);

        let (contract, fn_name, args) = match context {
            Context::Contract(ContractContext { contract, fn_name, args }) => {
                (contract, fn_name, args)
            }
            _ => panic_with_error!(e, BlendRuleError::UnauthorizedFunction),
        };

        if contract != cfg.pool {
            panic_with_error!(e, BlendRuleError::UnauthorizedPool);
        }

        let submit = Symbol::new(e, "submit");
        let submit_allowance = Symbol::new(e, "submit_with_allowance");
        if fn_name != submit && fn_name != submit_allowance {
            panic_with_error!(e, BlendRuleError::UnauthorizedFunction);
        }

        // submit(from, spender, to, requests) — args[0] debe ser el smart account
        let from = args
            .get(0)
            .and_then(|v| Address::try_from_val(e, &v).ok())
            .unwrap_or_else(|| panic_with_error!(e, BlendRuleError::InvalidArgs));
        if from != smart_account {
            panic_with_error!(e, BlendRuleError::WrongFrom);
        }

        // args[3] = requests: Vec<Request>
        let requests = args
            .get(3)
            .and_then(|v| Vec::<Request>::try_from_val(e, &v).ok())
            .unwrap_or_else(|| panic_with_error!(e, BlendRuleError::InvalidArgs));

        for req in requests.iter() {
            if !cfg.allowed_request_types.contains(&req.request_type) {
                panic_with_error!(e, BlendRuleError::UnauthorizedRequestType);
            }
            if cfg.max_amount_per_request > 0 && req.amount > cfg.max_amount_per_request {
                panic_with_error!(e, BlendRuleError::AmountExceeded);
            }
        }
    }

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        let key = StorageKey::Config(smart_account.clone(), context_rule.id);
        if e.storage().persistent().has(&key) {
            panic_with_error!(e, BlendRuleError::AlreadyInstalled);
        }
        save_config(e, &smart_account, context_rule.id, &BlendRuleConfig {
            pool: install_params.pool,
            allowed_request_types: install_params.allowed_request_types,
            max_amount_per_request: install_params.max_amount_per_request,
        });
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        let key = StorageKey::Config(smart_account.clone(), context_rule.id);
        if !e.storage().persistent().has(&key) {
            panic_with_error!(e, BlendRuleError::NotInstalled);
        }
        remove_config(e, &smart_account, context_rule.id);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;

    use soroban_sdk::{
        auth::{Context, ContractContext},
        contract, symbol_short,
        testutils::Address as _,
        Address, Env, IntoVal, String, Vec,
    };
    use stellar_accounts::smart_account::{ContextRule, ContextRuleType};

    use super::*;

    #[contract]
    struct MockContract;

    fn make_rule(e: &Env) -> ContextRule {
        ContextRule {
            id: 1,
            context_type: ContextRuleType::Default,
            name: String::from_str(e, "blend"),
            signers: Vec::new(e),
            signer_ids: Vec::new(e),
            policies: Vec::new(e),
            policy_ids: Vec::new(e),
            valid_until: None,
        }
    }

    fn default_types(e: &Env) -> Vec<u32> {
        let mut v = Vec::new(e);
        v.push_back(REQUEST_SUPPLY);
        v.push_back(REQUEST_WITHDRAW);
        v.push_back(REQUEST_SUPPLY_COLLATERAL);
        v.push_back(REQUEST_WITHDRAW_COLLATERAL);
        v.push_back(REQUEST_REPAY);
        v
    }

    fn submit_ctx(
        e: &Env,
        pool: &Address,
        from: &Address,
        requests: Vec<Request>,
    ) -> Context {
        let mut args = Vec::new(e);
        args.push_back(from.clone().into_val(e));
        args.push_back(from.clone().into_val(e)); // spender
        args.push_back(from.clone().into_val(e)); // to
        args.push_back(requests.into_val(e));
        Context::Contract(ContractContext {
            contract: pool.clone(),
            fn_name: Symbol::new(e, "submit"),
            args,
        })
    }

    fn make_request(e: &Env, request_type: u32, amount: i128) -> Request {
        Request {
            request_type,
            address: Address::generate(e),
            amount,
        }
    }

    // ── install ───────────────────────────────────────────────────────────────

    #[test]
    fn install_stores_config() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let pool = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            let params = BlendRuleInstallParams {
                pool: pool.clone(),
                allowed_request_types: default_types(&e),
                max_amount_per_request: 0,
            };
            BlendRulePolicy::install(&e, params, rule.clone(), account.clone());
            let cfg = load_config(&e, &account, rule.id);
            assert_eq!(cfg.pool, pool);
            assert_eq!(cfg.max_amount_per_request, 0);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #6001)")]
    fn install_twice_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let pool = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            BlendRulePolicy::install(&e, BlendRuleInstallParams {
                pool: pool.clone(),
                allowed_request_types: default_types(&e),
                max_amount_per_request: 0,
            }, rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            BlendRulePolicy::install(&e, BlendRuleInstallParams {
                pool: pool.clone(),
                allowed_request_types: default_types(&e),
                max_amount_per_request: 0,
            }, rule.clone(), account.clone());
        });
    }

    // ── uninstall ─────────────────────────────────────────────────────────────

    #[test]
    fn uninstall_removes_config() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let pool = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            BlendRulePolicy::install(&e, BlendRuleInstallParams {
                pool: pool.clone(),
                allowed_request_types: default_types(&e),
                max_amount_per_request: 0,
            }, rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            BlendRulePolicy::uninstall(&e, rule.clone(), account.clone());
            assert!(!e.storage().persistent().has(&StorageKey::Config(account.clone(), rule.id)));
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #6000)")]
    fn uninstall_not_installed_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            BlendRulePolicy::uninstall(&e, rule.clone(), account.clone());
        });
    }

    // ── enforce ───────────────────────────────────────────────────────────────

    #[test]
    fn enforce_valid_supply_passes() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let pool = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            BlendRulePolicy::install(&e, BlendRuleInstallParams {
                pool: pool.clone(),
                allowed_request_types: default_types(&e),
                max_amount_per_request: 0,
            }, rule.clone(), account.clone());

            let mut reqs = Vec::new(&e);
            reqs.push_back(make_request(&e, REQUEST_SUPPLY, 1_000_000));
            BlendRulePolicy::enforce(
                &e,
                submit_ctx(&e, &pool, &account, reqs),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #6002)")]
    fn enforce_unauthorized_pool_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let pool = Address::generate(&e);
        let other_pool = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            BlendRulePolicy::install(&e, BlendRuleInstallParams {
                pool: pool.clone(),
                allowed_request_types: default_types(&e),
                max_amount_per_request: 0,
            }, rule.clone(), account.clone());

            let mut reqs = Vec::new(&e);
            reqs.push_back(make_request(&e, REQUEST_SUPPLY, 1_000_000));
            BlendRulePolicy::enforce(
                &e,
                submit_ctx(&e, &other_pool, &account, reqs),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #6004)")]
    fn enforce_borrow_not_allowed_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let pool = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            BlendRulePolicy::install(&e, BlendRuleInstallParams {
                pool: pool.clone(),
                allowed_request_types: default_types(&e), // no incluye BORROW
                max_amount_per_request: 0,
            }, rule.clone(), account.clone());

            let mut reqs = Vec::new(&e);
            reqs.push_back(make_request(&e, REQUEST_BORROW, 1_000_000));
            BlendRulePolicy::enforce(
                &e,
                submit_ctx(&e, &pool, &account, reqs),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #6005)")]
    fn enforce_amount_exceeded_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let pool = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            BlendRulePolicy::install(&e, BlendRuleInstallParams {
                pool: pool.clone(),
                allowed_request_types: default_types(&e),
                max_amount_per_request: 500_000,
            }, rule.clone(), account.clone());

            let mut reqs = Vec::new(&e);
            reqs.push_back(make_request(&e, REQUEST_SUPPLY, 1_000_000)); // > 500_000
            BlendRulePolicy::enforce(
                &e,
                submit_ctx(&e, &pool, &account, reqs),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #6007)")]
    fn enforce_wrong_from_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let attacker = Address::generate(&e);
        let pool = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            BlendRulePolicy::install(&e, BlendRuleInstallParams {
                pool: pool.clone(),
                allowed_request_types: default_types(&e),
                max_amount_per_request: 0,
            }, rule.clone(), account.clone());

            let mut reqs = Vec::new(&e);
            reqs.push_back(make_request(&e, REQUEST_SUPPLY, 1_000_000));
            // from = attacker, pero smart_account = account → debe fallar
            BlendRulePolicy::enforce(
                &e,
                submit_ctx(&e, &pool, &attacker, reqs),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #6003)")]
    fn enforce_invalid_function_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let pool = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            BlendRulePolicy::install(&e, BlendRuleInstallParams {
                pool: pool.clone(),
                allowed_request_types: default_types(&e),
                max_amount_per_request: 0,
            }, rule.clone(), account.clone());

            let ctx = Context::Contract(ContractContext {
                contract: pool.clone(),
                fn_name: symbol_short!("withdraw"),
                args: Vec::new(&e),
            });
            BlendRulePolicy::enforce(&e, ctx, Vec::new(&e), rule.clone(), account.clone());
        });
    }

    #[test]
    fn enforce_no_limit_passes_large_amount() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let pool = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            BlendRulePolicy::install(&e, BlendRuleInstallParams {
                pool: pool.clone(),
                allowed_request_types: default_types(&e),
                max_amount_per_request: 0, // sin límite
            }, rule.clone(), account.clone());

            let mut reqs = Vec::new(&e);
            reqs.push_back(make_request(&e, REQUEST_SUPPLY, i128::MAX));
            BlendRulePolicy::enforce(
                &e,
                submit_ctx(&e, &pool, &account, reqs),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }
}
