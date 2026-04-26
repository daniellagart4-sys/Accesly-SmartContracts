//! # Accesly — Upgrade Rule Policy
//!
//! Política que restringe una context rule a autorizar únicamente llamadas
//! `upgrade(new_wasm_hash)` sobre un contrato objetivo específico.
//!
//! Uso típico: un relayer/backend ejecuta upgrades aprobados por el timelock
//! usando una session key que solo puede firmar upgrades del smart account.
use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contracterror, contractimpl, contracttype, panic_with_error,
    Address, Env, Symbol, Vec,
};
use stellar_accounts::{
    policies::Policy,
    smart_account::{ContextRule, Signer},
};

// ── TTL ───────────────────────────────────────────────────────────────────────

const DAY_IN_LEDGERS: u32 = 17280;
const EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const TTL_THRESHOLD: u32 = EXTEND_AMOUNT - DAY_IN_LEDGERS;

// ── Errores ───────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum UpgradeRuleError {
    NotInstalled = 6100,
    AlreadyInstalled = 6101,
    /// El contrato objetivo no es el autorizado.
    UnauthorizedTarget = 6102,
    /// La función no es `upgrade`.
    InvalidFunction = 6103,
}

// ── Tipos de storage ──────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct UpgradeRuleConfig {
    pub target_contract: Address,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct UpgradeRuleInstallParams {
    pub target_contract: Address,
}

#[contracttype]
enum StorageKey {
    Config(Address, u32),
}

// ── Helpers de storage ────────────────────────────────────────────────────────

fn load_config(e: &Env, smart_account: &Address, rule_id: u32) -> UpgradeRuleConfig {
    let key = StorageKey::Config(smart_account.clone(), rule_id);
    match e.storage().persistent().get::<StorageKey, UpgradeRuleConfig>(&key) {
        Some(cfg) => cfg,
        None => panic_with_error!(e, UpgradeRuleError::NotInstalled),
    }
}

fn save_config(e: &Env, smart_account: &Address, rule_id: u32, cfg: &UpgradeRuleConfig) {
    let key = StorageKey::Config(smart_account.clone(), rule_id);
    e.storage().persistent().set(&key, cfg);
    e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
}

fn remove_config(e: &Env, smart_account: &Address, rule_id: u32) {
    e.storage().persistent().remove(&StorageKey::Config(smart_account.clone(), rule_id));
}

// ── Contrato ──────────────────────────────────────────────────────────────────

#[contract]
pub struct UpgradeRulePolicy;

#[contractimpl]
impl Policy for UpgradeRulePolicy {
    type AccountParams = UpgradeRuleInstallParams;

    fn enforce(
        e: &Env,
        context: Context,
        _authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        let cfg = load_config(e, &smart_account, context_rule.id);

        let (contract, fn_name) = match context {
            Context::Contract(ContractContext { contract, fn_name, .. }) => (contract, fn_name),
            _ => panic_with_error!(e, UpgradeRuleError::InvalidFunction),
        };

        if contract != cfg.target_contract {
            panic_with_error!(e, UpgradeRuleError::UnauthorizedTarget);
        }

        if fn_name != Symbol::new(e, "upgrade") {
            panic_with_error!(e, UpgradeRuleError::InvalidFunction);
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
            panic_with_error!(e, UpgradeRuleError::AlreadyInstalled);
        }
        save_config(e, &smart_account, context_rule.id, &UpgradeRuleConfig {
            target_contract: install_params.target_contract,
        });
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        let key = StorageKey::Config(smart_account.clone(), context_rule.id);
        if !e.storage().persistent().has(&key) {
            panic_with_error!(e, UpgradeRuleError::NotInstalled);
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
        Address, BytesN, Env, IntoVal, String, Vec,
    };
    use stellar_accounts::smart_account::{ContextRule, ContextRuleType};

    use super::*;

    #[contract]
    struct MockContract;

    fn make_rule(e: &Env) -> ContextRule {
        ContextRule {
            id: 1,
            context_type: ContextRuleType::Default,
            name: String::from_str(e, "upgrade"),
            signers: Vec::new(e),
            signer_ids: Vec::new(e),
            policies: Vec::new(e),
            policy_ids: Vec::new(e),
            valid_until: None,
        }
    }

    fn upgrade_ctx(e: &Env, target: &Address) -> Context {
        let mut args = Vec::new(e);
        args.push_back(BytesN::from_array(e, &[0u8; 32]).into_val(e));
        Context::Contract(ContractContext {
            contract: target.clone(),
            fn_name: Symbol::new(e, "upgrade"),
            args,
        })
    }

    // ── install ───────────────────────────────────────────────────────────────

    #[test]
    fn install_stores_config() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let target = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            UpgradeRulePolicy::install(&e, UpgradeRuleInstallParams {
                target_contract: target.clone(),
            }, rule.clone(), account.clone());
            let cfg = load_config(&e, &account, rule.id);
            assert_eq!(cfg.target_contract, target);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #6101)")]
    fn install_twice_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let target = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            UpgradeRulePolicy::install(&e, UpgradeRuleInstallParams {
                target_contract: target.clone(),
            }, rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            UpgradeRulePolicy::install(&e, UpgradeRuleInstallParams {
                target_contract: target.clone(),
            }, rule.clone(), account.clone());
        });
    }

    // ── uninstall ─────────────────────────────────────────────────────────────

    #[test]
    fn uninstall_removes_config() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let target = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            UpgradeRulePolicy::install(&e, UpgradeRuleInstallParams {
                target_contract: target.clone(),
            }, rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            UpgradeRulePolicy::uninstall(&e, rule.clone(), account.clone());
            assert!(!e.storage().persistent().has(&StorageKey::Config(account.clone(), rule.id)));
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #6100)")]
    fn uninstall_not_installed_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            UpgradeRulePolicy::uninstall(&e, rule.clone(), account.clone());
        });
    }

    // ── enforce ───────────────────────────────────────────────────────────────

    #[test]
    fn enforce_upgrade_authorized_target_passes() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let target = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            UpgradeRulePolicy::install(&e, UpgradeRuleInstallParams {
                target_contract: target.clone(),
            }, rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            UpgradeRulePolicy::enforce(
                &e,
                upgrade_ctx(&e, &target),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #6102)")]
    fn enforce_wrong_target_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let target = Address::generate(&e);
        let other = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            UpgradeRulePolicy::install(&e, UpgradeRuleInstallParams {
                target_contract: target.clone(),
            }, rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            UpgradeRulePolicy::enforce(
                &e,
                upgrade_ctx(&e, &other),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #6103)")]
    fn enforce_wrong_function_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let target = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            UpgradeRulePolicy::install(&e, UpgradeRuleInstallParams {
                target_contract: target.clone(),
            }, rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            let ctx = Context::Contract(ContractContext {
                contract: target.clone(),
                fn_name: symbol_short!("set_admin"),
                args: Vec::new(&e),
            });
            UpgradeRulePolicy::enforce(&e, ctx, Vec::new(&e), rule.clone(), account.clone());
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #6103)")]
    fn enforce_non_contract_context_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let target = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            UpgradeRulePolicy::install(&e, UpgradeRuleInstallParams {
                target_contract: target.clone(),
            }, rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            UpgradeRulePolicy::enforce(
                &e,
                Context::CreateContractHostFn(soroban_sdk::auth::CreateContractHostFnContext {
                    executable: soroban_sdk::auth::ContractExecutable::Wasm(
                        BytesN::from_array(&e, &[0u8; 32])
                    ),
                    salt: BytesN::from_array(&e, &[0u8; 32]),
                }),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }

    #[test]
    #[should_panic]
    fn enforce_unauthorized_fails() {
        let e = Env::default();
        // NO mock_all_auths — enforce must fail at smart_account.require_auth().
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let target = Address::generate(&e);
        let rule = make_rule(&e);

        // Insert config directly — bypasses install() which calls require_auth.
        e.as_contract(&addr, || {
            save_config(&e, &account, rule.id, &UpgradeRuleConfig { target_contract: target.clone() });
        });

        e.as_contract(&addr, || {
            UpgradeRulePolicy::enforce(
                &e,
                upgrade_ctx(&e, &target),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }
}
