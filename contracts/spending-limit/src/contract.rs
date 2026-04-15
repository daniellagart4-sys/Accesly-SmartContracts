//! # Accesly — Spending Limit Policy
//!
//! Política compartida de tope de gasto. Un deploy, estado aislado por
//! (smart_account, context_rule_id). Bloquea transferencias que excedan
//! el límite configurado en la ventana de tiempo.
//!
//! Parámetros de instalación:
//! - spending_limit: monto máximo acumulado en el período (en stroops)
//! - period_ledgers: duración de la ventana (17280 = ~1 día)
use soroban_sdk::{auth::Context, contract, contractimpl, Address, Env, Vec};
use stellar_accounts::{
    policies::{spending_limit, Policy},
    smart_account::{ContextRule, Signer},
};

#[contract]
pub struct SpendingLimitPolicy;

#[contractimpl]
impl Policy for SpendingLimitPolicy {
    type AccountParams = spending_limit::SpendingLimitAccountParams;

    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::enforce(e, &context, &authenticated_signers, &context_rule, &smart_account)
    }

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::install(e, &install_params, &context_rule, &smart_account)
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        spending_limit::uninstall(e, &context_rule, &smart_account)
    }
}

#[contractimpl]
impl SpendingLimitPolicy {
    /// Consulta el estado actual del límite para una cuenta y regla.
    pub fn get_data(
        e: Env,
        context_rule_id: u32,
        smart_account: Address,
    ) -> spending_limit::SpendingLimitData {
        spending_limit::get_spending_limit_data(&e, context_rule_id, &smart_account)
    }

    /// Actualiza el monto del límite (requiere auth del Smart Account).
    pub fn set_limit(
        e: Env,
        new_limit: i128,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::set_spending_limit(&e, new_limit, &context_rule, &smart_account)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;

    use soroban_sdk::{
        auth::{Context, ContractContext},
        contract, symbol_short,
        testutils::{Address as _, Ledger},
        Address, Env, IntoVal, String, Vec,
    };
    use stellar_accounts::{
        policies::spending_limit::SpendingLimitAccountParams,
        smart_account::{ContextRule, ContextRuleType, Signer},
    };

    use super::*;

    #[contract]
    struct MockContract;

    fn make_rule(e: &Env) -> ContextRule {
        ContextRule {
            id: 0,
            context_type: ContextRuleType::CallContract(Address::generate(e)),
            name: String::from_str(e, "biometric-tx"),
            signers: {
                let mut s = Vec::new(e);
                s.push_back(Signer::Delegated(Address::generate(e)));
                s
            },
            signer_ids: Vec::new(e),
            policies: Vec::new(e),
            policy_ids: Vec::new(e),
            valid_until: None,
        }
    }

    fn transfer_ctx(e: &Env, amount: i128) -> Context {
        let mut args = soroban_sdk::Vec::new(e);
        args.push_back(Address::generate(e).into_val(e));
        args.push_back(Address::generate(e).into_val(e));
        args.push_back(amount.into_val(e));
        Context::Contract(ContractContext {
            contract: Address::generate(e),
            fn_name: symbol_short!("transfer"),
            args,
        })
    }

    // ── install / get_data ────────────────────────────────────────────────────

    #[test]
    fn install_and_get_data() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            SpendingLimitPolicy::install(
                &e,
                SpendingLimitAccountParams { spending_limit: 1_000_000, period_ledgers: 100 },
                rule.clone(), account.clone(),
            );
            let data = SpendingLimitPolicy::get_data(e.clone(), rule.id, account.clone());
            assert_eq!(data.spending_limit, 1_000_000);
            assert_eq!(data.period_ledgers, 100);
            assert_eq!(data.cached_total_spent, 0);
        });
    }

    // ── enforce dentro del límite ─────────────────────────────────────────────

    #[test]
    fn enforce_within_limit_passes() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            SpendingLimitPolicy::install(
                &e,
                SpendingLimitAccountParams { spending_limit: 1_000_000, period_ledgers: 100 },
                rule.clone(), account.clone(),
            );
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            SpendingLimitPolicy::enforce(
                &e, transfer_ctx(&e, 500_000), rule.signers.clone(), rule.clone(), account.clone(),
            );
            let data = SpendingLimitPolicy::get_data(e.clone(), rule.id, account.clone());
            assert_eq!(data.cached_total_spent, 500_000);
        });
    }

    // ── enforce excede el límite ──────────────────────────────────────────────

    #[test]
    #[should_panic]
    fn enforce_exceeds_limit_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            SpendingLimitPolicy::install(
                &e,
                SpendingLimitAccountParams { spending_limit: 1_000_000, period_ledgers: 100 },
                rule.clone(), account.clone(),
            );
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            SpendingLimitPolicy::enforce(
                &e, transfer_ctx(&e, 2_000_000), rule.signers.clone(), rule.clone(), account.clone(),
            );
        });
    }

    // ── set_limit ─────────────────────────────────────────────────────────────

    #[test]
    fn set_limit_updates_value() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            SpendingLimitPolicy::install(
                &e,
                SpendingLimitAccountParams { spending_limit: 1_000_000, period_ledgers: 100 },
                rule.clone(), account.clone(),
            );
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            SpendingLimitPolicy::set_limit(e.clone(), 2_000_000, rule.clone(), account.clone());
            let data = SpendingLimitPolicy::get_data(e.clone(), rule.id, account.clone());
            assert_eq!(data.spending_limit, 2_000_000);
        });
    }

    // ── uninstall ─────────────────────────────────────────────────────────────

    #[test]
    fn uninstall_success() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            SpendingLimitPolicy::install(
                &e,
                SpendingLimitAccountParams { spending_limit: 1_000_000, period_ledgers: 100 },
                rule.clone(), account.clone(),
            );
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            SpendingLimitPolicy::uninstall(&e, rule.clone(), account.clone());
        });
    }

    // ── rolling window ────────────────────────────────────────────────────────

    #[test]
    fn rolling_window_resets_after_period() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 1000);
        e.as_contract(&addr, || {
            SpendingLimitPolicy::install(
                &e,
                SpendingLimitAccountParams { spending_limit: 1_000_000, period_ledgers: 100 },
                rule.clone(), account.clone(),
            );
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            SpendingLimitPolicy::enforce(
                &e, transfer_ctx(&e, 900_000), rule.signers.clone(), rule.clone(), account.clone(),
            );
        });

        e.ledger().with_mut(|l| l.sequence_number = 1100);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            SpendingLimitPolicy::enforce(
                &e, transfer_ctx(&e, 900_000), rule.signers.clone(), rule.clone(), account.clone(),
            );
            let data = SpendingLimitPolicy::get_data(e.clone(), rule.id, account.clone());
            assert_eq!(data.cached_total_spent, 900_000);
        });
    }
}
