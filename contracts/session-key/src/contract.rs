//! # Accesly — Session Key Policy
//!
//! Política de sesiones temporales. La session key (ed25519) es generada en
//! el SDK al inicio de la sesión biométrica. Después opera sin biométrico.
//!
//! Diseño:
//! - La session key se registra como signer External en una nueva context rule.
//! - Esta política se instala en esa misma context rule.
//! - `enforce` valida que la sesión no haya expirado y que el gasto acumulado
//!   no supere `max_amount` (0 = sin límite).
//! - Revocable con `revoke()` (requiere auth del Smart Account).
//!
//! El ed25519-verifier es quien verifica la firma criptográfica.
//! Esta política solo impone las restricciones temporales y de monto.
use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contractimpl, contracttype, panic_with_error,
    contracterror, Address, Env, Symbol, TryFromVal, Vec,
};
use stellar_accounts::{
    policies::Policy,
    smart_account::{ContextRule, Signer},
};

// ── Constantes de TTL ────────────────────────────────────────────────────────

const DAY_IN_LEDGERS: u32 = 17280;
const EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const TTL_THRESHOLD: u32 = EXTEND_AMOUNT - DAY_IN_LEDGERS;

/// Duración máxima de una sesión: 30 días en ledgers.
pub const MAX_SESSION_DURATION: u32 = 30 * DAY_IN_LEDGERS;

// ── Errores ──────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum SessionKeyError {
    /// Sesión no encontrada para esta cuenta y context rule.
    NotInstalled = 5000,
    /// La sesión ha expirado.
    Expired = 5001,
    /// Se superó el monto máximo de la sesión.
    AmountExceeded = 5002,
    /// Ya existe una sesión para esta context rule.
    AlreadyInstalled = 5003,
    /// Llamada no-transfer rechazada cuando hay límite de monto activo.
    NonTransferNotAllowed = 5004,
    /// Monto de transferencia negativo o cero — rechazado para evitar bypass del cap.
    InvalidAmount = 5006,
    /// La duración de la sesión supera el máximo permitido (30 días).
    SessionTooLong = 5005,
}

// ── Storage ──────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
enum StorageKey {
    Session(Address, u32), // (smart_account, context_rule_id)
}

/// Estado interno de una sesión activa.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SessionData {
    /// Ledger sequence en que expira la sesión.
    pub expires_at: u32,
    /// Gasto máximo acumulado (0 = ilimitado).
    pub max_amount: i128,
    /// Gasto acumulado hasta ahora.
    pub spent: i128,
}

// ── Parámetros de instalación ─────────────────────────────────────────────────

/// Parámetros que el Smart Account envía al instalar la política.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SessionKeyInstallParams {
    /// Ledger sequence de expiración.
    pub expires_at: u32,
    /// Monto máximo acumulado en stroops (0 = sin límite).
    pub max_amount: i128,
}

// ── Helpers de storage ────────────────────────────────────────────────────────

fn storage_key(smart_account: &Address, context_rule_id: u32) -> StorageKey {
    StorageKey::Session(smart_account.clone(), context_rule_id)
}

fn load_session(e: &Env, smart_account: &Address, context_rule_id: u32) -> SessionData {
    let key = storage_key(smart_account, context_rule_id);
    match e.storage().persistent().get::<StorageKey, SessionData>(&key) {
        Some(data) => {
            e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
            data
        }
        None => panic_with_error!(e, SessionKeyError::NotInstalled),
    }
}

fn load_session_no_extend(e: &Env, smart_account: &Address, context_rule_id: u32) -> SessionData {
    let key = storage_key(smart_account, context_rule_id);
    match e.storage().persistent().get::<StorageKey, SessionData>(&key) {
        Some(data) => data,
        None => panic_with_error!(e, SessionKeyError::NotInstalled),
    }
}

fn save_session(e: &Env, smart_account: &Address, context_rule_id: u32, data: &SessionData) {
    let key = storage_key(smart_account, context_rule_id);
    e.storage().persistent().set(&key, data);
    e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
}

fn remove_session(e: &Env, smart_account: &Address, context_rule_id: u32) {
    let key = storage_key(smart_account, context_rule_id);
    e.storage().persistent().remove(&key);
}

// ── Extrae el monto de una transferencia de token (SEP-41) ────────────────────

/// Intenta obtener el monto de una llamada `transfer(from, to, amount)`.
/// Devuelve None si el contexto no es una transferencia estándar.
fn extract_transfer_amount(e: &Env, context: &Context) -> Option<i128> {
    if let Context::Contract(ContractContext { fn_name, args, .. }) = context {
        if fn_name == &Symbol::new(e, "transfer") {
            if let Some(amount_val) = args.get(2) {
                if let Ok(amount) = i128::try_from_val(e, &amount_val) {
                    return Some(amount);
                }
            }
        }
    }
    None
}

// ── Contrato ──────────────────────────────────────────────────────────────────

#[contract]
pub struct SessionKeyPolicy;

#[contractimpl]
impl Policy for SessionKeyPolicy {
    type AccountParams = SessionKeyInstallParams;

    /// Verifica que la sesión esté activa y que el gasto no supere el límite.
    fn enforce(
        e: &Env,
        context: Context,
        _authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        // Bind enforce to the SA's auth flow — prevents direct external calls.
        smart_account.require_auth();

        let mut data = load_session(e, &smart_account, context_rule.id);

        // 1. Verificar que la sesión no haya expirado
        if e.ledger().sequence() >= data.expires_at {
            panic_with_error!(e, SessionKeyError::Expired);
        }

        // 2. Si hay límite de monto, verificar y acumular
        // When max_amount > 0, only transfer() is allowed to prevent approve/allowance bypass.
        if data.max_amount > 0 {
            match extract_transfer_amount(e, &context) {
                Some(amount) => {
                    if amount <= 0 {
                        panic_with_error!(e, SessionKeyError::InvalidAmount);
                    }
                    let new_spent = data.spent.checked_add(amount)
                        .unwrap_or_else(|| panic_with_error!(e, SessionKeyError::AmountExceeded));
                    if new_spent > data.max_amount {
                        panic_with_error!(e, SessionKeyError::AmountExceeded);
                    }
                    data.spent = new_spent;
                    save_session(e, &smart_account, context_rule.id, &data);
                }
                None => {
                    // Reject approve/allowance and any non-transfer call to prevent
                    // unlimited drain via spending cap bypass.
                    panic_with_error!(e, SessionKeyError::NonTransferNotAllowed);
                }
            }
        }
    }

    /// Inicializa la sesión con los parámetros dados.
    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        let key = storage_key(&smart_account, context_rule.id);
        if e.storage().persistent().has(&key) {
            panic_with_error!(e, SessionKeyError::AlreadyInstalled);
        }
        if install_params.max_amount < 0 {
            panic_with_error!(e, SessionKeyError::InvalidAmount);
        }
        let current = e.ledger().sequence();
        if install_params.expires_at <= current {
            panic_with_error!(e, SessionKeyError::SessionTooLong);
        }
        if install_params.expires_at - current > MAX_SESSION_DURATION {
            panic_with_error!(e, SessionKeyError::SessionTooLong);
        }
        let data = SessionData {
            expires_at: install_params.expires_at,
            max_amount: install_params.max_amount,
            spent: 0,
        };
        save_session(e, &smart_account, context_rule.id, &data);
    }

    /// Elimina los datos de la sesión.
    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        let key = storage_key(&smart_account, context_rule.id);
        if !e.storage().persistent().has(&key) {
            panic_with_error!(e, SessionKeyError::NotInstalled);
        }
        remove_session(e, &smart_account, context_rule.id);
    }
}

#[contractimpl]
impl SessionKeyPolicy {
    /// Revoca la sesión inmediatamente poniendo `expires_at = 0`.
    /// Requiere autorización del Smart Account.
    pub fn revoke(e: Env, context_rule_id: u32, smart_account: Address) {
        smart_account.require_auth();
        let mut data = load_session(&e, &smart_account, context_rule_id);
        data.expires_at = 0;
        save_session(&e, &smart_account, context_rule_id, &data);
    }

    /// Consulta el estado de la sesión.
    pub fn get_session(
        e: Env,
        context_rule_id: u32,
        smart_account: Address,
    ) -> SessionData {
        load_session_no_extend(&e, &smart_account, context_rule_id)
    }

    /// Comprueba si la sesión sigue activa.
    pub fn is_active(e: Env, context_rule_id: u32, smart_account: Address) -> bool {
        let key = storage_key(&smart_account, context_rule_id);
        if let Some(data) = e.storage().persistent().get::<StorageKey, SessionData>(&key) {
            e.ledger().sequence() < data.expires_at
        } else {
            false
        }
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
    use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

    use super::*;

    #[contract]
    struct MockContract;

    fn make_rule(e: &Env) -> ContextRule {
        ContextRule {
            id: 1,
            context_type: ContextRuleType::Default,
            name: String::from_str(e, "session"),
            signers: Vec::new(e),
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

    fn non_transfer_ctx(e: &Env) -> Context {
        Context::Contract(ContractContext {
            contract: Address::generate(e),
            fn_name: symbol_short!("approve"),
            args: soroban_sdk::Vec::new(e),
        })
    }

    // ── install ───────────────────────────────────────────────────────────────

    #[test]
    fn install_stores_session() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 1000, max_amount: 500_000 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
            let data = SessionKeyPolicy::get_session(e.clone(), rule.id, account.clone());
            assert_eq!(data.expires_at, 1000);
            assert_eq!(data.max_amount, 500_000);
            assert_eq!(data.spent, 0);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #5003)")]
    fn install_twice_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 1000, max_amount: 0 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 1000, max_amount: 0 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #5006)")]
    fn install_negative_max_amount_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 1000, max_amount: -1 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });
    }

    // ── uninstall ─────────────────────────────────────────────────────────────

    #[test]
    fn uninstall_removes_session() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 1000, max_amount: 0 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            SessionKeyPolicy::uninstall(&e, rule.clone(), account.clone());
            assert!(!SessionKeyPolicy::is_active(e.clone(), rule.id, account.clone()));
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #5000)")]
    fn uninstall_not_installed_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            SessionKeyPolicy::uninstall(&e, rule.clone(), account.clone());
        });
    }

    // ── is_active ─────────────────────────────────────────────────────────────

    #[test]
    fn is_active_true_before_expiry() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 100);

        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 200, max_amount: 0 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
            assert!(SessionKeyPolicy::is_active(e.clone(), rule.id, account.clone()));
        });
    }

    #[test]
    fn is_active_false_after_expiry() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 50, max_amount: 0 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });

        e.ledger().with_mut(|l| l.sequence_number = 50);
        e.as_contract(&addr, || {
            assert!(!SessionKeyPolicy::is_active(e.clone(), rule.id, account.clone()));
        });
    }

    // ── revoke ────────────────────────────────────────────────────────────────

    #[test]
    fn revoke_deactivates_session() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.ledger().with_mut(|l| l.sequence_number = 100);

        e.mock_all_auths();
        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 1000, max_amount: 0 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
            assert!(SessionKeyPolicy::is_active(e.clone(), rule.id, account.clone()));
        });

        e.mock_all_auths();
        e.as_contract(&addr, || {
            SessionKeyPolicy::revoke(e.clone(), rule.id, account.clone());
            assert!(!SessionKeyPolicy::is_active(e.clone(), rule.id, account.clone()));
        });
    }

    // ── enforce ───────────────────────────────────────────────────────────────

    #[test]
    fn enforce_valid_session_no_limit_passes() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 100);

        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 500, max_amount: 0 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });

        e.as_contract(&addr, || {
            // sin límite de monto, cualquier contexto pasa
            SessionKeyPolicy::enforce(
                &e, transfer_ctx(&e, 1_000_000), Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    #[test]
    fn enforce_accumulates_spent_and_passes_within_limit() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 100);

        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 500, max_amount: 1_000_000 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });

        e.as_contract(&addr, || {
            SessionKeyPolicy::enforce(
                &e, transfer_ctx(&e, 400_000), Vec::new(&e), rule.clone(), account.clone(),
            );
        });

        e.as_contract(&addr, || {
            SessionKeyPolicy::enforce(
                &e, transfer_ctx(&e, 400_000), Vec::new(&e), rule.clone(), account.clone(),
            );
            let data = SessionKeyPolicy::get_session(e.clone(), rule.id, account.clone());
            assert_eq!(data.spent, 800_000);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #5001)")]
    fn enforce_expired_session_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();

        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 50, max_amount: 0 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });

        e.ledger().with_mut(|l| l.sequence_number = 100);

        e.as_contract(&addr, || {
            SessionKeyPolicy::enforce(
                &e, non_transfer_ctx(&e), Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #5002)")]
    fn enforce_exceeds_amount_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 100);

        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 500, max_amount: 100_000 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });

        e.as_contract(&addr, || {
            SessionKeyPolicy::enforce(
                &e, transfer_ctx(&e, 200_000), Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    #[test]
    fn enforce_non_transfer_no_limit_passes() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 100);

        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 500, max_amount: 0 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });

        e.as_contract(&addr, || {
            // Without a spending cap, non-transfer calls are allowed.
            SessionKeyPolicy::enforce(
                &e, non_transfer_ctx(&e), Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #5004)")]
    fn enforce_non_transfer_with_limit_rejected() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 100);

        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 500, max_amount: 100_000 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });

        e.as_contract(&addr, || {
            // approve() with a spending cap must be rejected to prevent allowance bypass.
            SessionKeyPolicy::enforce(
                &e, non_transfer_ctx(&e), Vec::new(&e), rule.clone(), account.clone(),
            );
        });
    }

    // ── seguridad: enforce sin auth del SA ────────────────────────────────────

    #[test]
    #[should_panic]
    fn enforce_unauthorized_fails() {
        let e = Env::default();
        // NO mock_all_auths — enforce must fail at smart_account.require_auth().
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.ledger().with_mut(|l| l.sequence_number = 100);

        // Insert session data directly — bypasses install() which calls require_auth.
        e.as_contract(&addr, || {
            let data = SessionData { expires_at: 500, max_amount: 100_000, spent: 0 };
            save_session(&e, &account, rule.id, &data);
        });

        // Enforce without auth mock — smart_account.require_auth() must fail.
        e.as_contract(&addr, || {
            SessionKeyPolicy::enforce(
                &e,
                transfer_ctx(&e, 50_000),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }

    // ── seguridad: monto negativo no reduce spent ─────────────────────────────

    #[test]
    #[should_panic(expected = "Error(Contract, #5006)")]
    fn enforce_negative_amount_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 100);

        e.as_contract(&addr, || {
            let params = SessionKeyInstallParams { expires_at: 500, max_amount: 1_000_000 };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });

        e.as_contract(&addr, || {
            // Negative amount must be rejected to prevent spending cap bypass.
            SessionKeyPolicy::enforce(
                &e,
                transfer_ctx(&e, -100_000),
                Vec::new(&e),
                rule.clone(),
                account.clone(),
            );
        });
    }

    // ── cuentas independientes ────────────────────────────────────────────────

    #[test]
    fn two_accounts_independent() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let acct1 = Address::generate(&e);
        let acct2 = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 100);

        e.as_contract(&addr, || {
            SessionKeyPolicy::install(
                &e,
                SessionKeyInstallParams { expires_at: 200, max_amount: 500_000 },
                rule.clone(), acct1.clone(),
            );
            SessionKeyPolicy::install(
                &e,
                SessionKeyInstallParams { expires_at: 300, max_amount: 1_000_000 },
                rule.clone(), acct2.clone(),
            );
        });

        e.as_contract(&addr, || {
            SessionKeyPolicy::enforce(
                &e, transfer_ctx(&e, 400_000), Vec::new(&e), rule.clone(), acct1.clone(),
            );

            let d1 = SessionKeyPolicy::get_session(e.clone(), rule.id, acct1.clone());
            let d2 = SessionKeyPolicy::get_session(e.clone(), rule.id, acct2.clone());
            assert_eq!(d1.spent, 400_000);
            assert_eq!(d2.spent, 0); // acct2 no tocada
        });
    }

    // ── duración máxima de sesión ─────────────────────────────────────────────

    #[test]
    #[should_panic(expected = "Error(Contract, #5005)")]
    fn install_session_too_long_fails() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 100);

        e.as_contract(&addr, || {
            // expires_at - current > MAX_SESSION_DURATION → must fail
            let params = SessionKeyInstallParams {
                expires_at: 100 + MAX_SESSION_DURATION + 1,
                max_amount: 0,
            };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
        });
    }

    #[test]
    fn install_session_at_max_duration_passes() {
        let e = Env::default();
        let addr = e.register(MockContract, ());
        let account = Address::generate(&e);
        let rule = make_rule(&e);
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 100);

        e.as_contract(&addr, || {
            // expires_at - current == MAX_SESSION_DURATION → must pass
            let params = SessionKeyInstallParams {
                expires_at: 100 + MAX_SESSION_DURATION,
                max_amount: 0,
            };
            SessionKeyPolicy::install(&e, params, rule.clone(), account.clone());
            let data = SessionKeyPolicy::get_session(e.clone(), rule.id, account.clone());
            assert_eq!(data.expires_at, 100 + MAX_SESSION_DURATION);
        });
    }
}
