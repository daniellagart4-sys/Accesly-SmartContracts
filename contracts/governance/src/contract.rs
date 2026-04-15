//! # Accesly — Timelock Controller (48h)
//!
//! Guard para upgrades y cambios críticos en los Smart Accounts.
//! Delay mínimo: 34560 ledgers ≈ 48 horas (a ~5s por ledger).
//!
//! Roles:
//! - **Admin**: puede gestionar roles y cambiar el delay.
//!   Por defecto, el contrato mismo es admin (self-administration).
//! - **Proposer**: propone operaciones (también recibe canceller automáticamente).
//! - **Executor**: ejecuta operaciones listas.
//! - **Canceller**: cancela operaciones pendientes.
//!
//! Flujo de upgrade de Smart Account:
//!   1. Proposer llama `schedule()` con target = smart_account, fn = "upgrade".
//!   2. Espera 34560 ledgers (~48h).
//!   3. Executor llama `execute()`.
//!   4. Smart Account llama `upgrade()` autorizado por este timelock.
use soroban_sdk::{
    auth::{Context, ContractContext, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    panic_with_error, symbol_short, Address, BytesN, Env, IntoVal, Symbol, Val, Vec,
};
use stellar_access::access_control::{
    ensure_role, get_role_member_count, grant_role_no_auth, set_admin, AccessControl,
};
use stellar_governance::timelock::{
    cancel_operation, execute_operation, schedule_operation, set_execute_operation,
    set_min_delay as timelock_set_min_delay, Operation, OperationState, TimelockError, Timelock,
};
use stellar_macros::{only_admin, only_role};

// ── Constantes ────────────────────────────────────────────────────────────────

/// 48 horas a ~5 segundos por ledger = 34 560 ledgers.
pub const DELAY_48H: u32 = 34_560;

const PROPOSER_ROLE: Symbol = symbol_short!("proposer");
const EXECUTOR_ROLE: Symbol = symbol_short!("executor");
const CANCELLER_ROLE: Symbol = symbol_short!("canceller");

// ── Error interno ─────────────────────────────────────────────────────────────

#[contracterror]
#[repr(u32)]
enum ControllerError {
    LengthMismatch = 0,
}

// ── Metadata de operación (para self-admin via CustomAccountInterface) ────────

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct OperationMeta {
    pub predecessor: BytesN<32>,
    pub salt: BytesN<32>,
    pub executor: Option<Address>,
}

// ── Contrato ──────────────────────────────────────────────────────────────────

#[contract]
pub struct TimelockController;

#[contractimpl]
impl TimelockController {
    /// Inicializa el timelock con delay mínimo de 48h.
    ///
    /// # Arguments
    /// * `proposers`  — Addresses que pueden proponer operaciones.
    /// * `executors`  — Addresses que pueden ejecutar operaciones listas.
    /// * `admin`      — Admin externo opcional para setup inicial.
    ///   Si es `None`, el propio contrato es admin (self-administration).
    pub fn __constructor(
        e: &Env,
        proposers: Vec<Address>,
        executors: Vec<Address>,
        admin: Option<Address>,
    ) {
        let admin_addr = admin.unwrap_or_else(|| e.current_contract_address());
        set_admin(e, &admin_addr);

        for proposer in proposers.iter() {
            grant_role_no_auth(e, &proposer, &PROPOSER_ROLE, &admin_addr);
            grant_role_no_auth(e, &proposer, &CANCELLER_ROLE, &admin_addr);
        }
        for executor in executors.iter() {
            grant_role_no_auth(e, &executor, &EXECUTOR_ROLE, &admin_addr);
        }

        timelock_set_min_delay(e, DELAY_48H);
    }
}

// ── CustomAccountInterface: self-administration ───────────────────────────────

#[contractimpl]
impl CustomAccountInterface for TimelockController {
    type Error = TimelockError;
    type Signature = Vec<OperationMeta>;

    fn __check_auth(
        e: Env,
        _signature_payload: Hash<32>,
        context_meta: Vec<OperationMeta>,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        if auth_contexts.len() != context_meta.len() {
            panic_with_error!(&e, ControllerError::LengthMismatch);
        }

        for (context, meta) in auth_contexts.iter().zip(context_meta) {
            match context.clone() {
                Context::Contract(ContractContext { contract, fn_name, args }) => {
                    if contract != e.current_contract_address() {
                        panic_with_error!(&e, TimelockError::Unauthorized)
                    }

                    if get_role_member_count(&e, &EXECUTOR_ROLE) != 0 {
                        let args_for_auth = (
                            Symbol::new(&e, "execute_op"),
                            contract.clone(),
                            fn_name.clone(),
                            args.clone(),
                            meta.predecessor.clone(),
                            meta.salt.clone(),
                        ).into_val(&e);

                        let executor = meta.executor.expect("executor must be present");
                        ensure_role(&e, &EXECUTOR_ROLE, &executor);
                        executor.require_auth_for_args(args_for_auth);
                    }

                    let op = Operation {
                        target: contract,
                        function: fn_name,
                        args,
                        predecessor: meta.predecessor,
                        salt: meta.salt,
                    };
                    set_execute_operation(&e, &op);
                }
                _ => panic_with_error!(&e, TimelockError::Unauthorized),
            }
        }
        Ok(())
    }
}

// ── Timelock trait ────────────────────────────────────────────────────────────

#[contractimpl(contracttrait)]
impl Timelock for TimelockController {
    #[allow(clippy::too_many_arguments)]
    #[only_role(proposer, "proposer")]
    fn schedule(
        e: &Env,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
        predecessor: BytesN<32>,
        salt: BytesN<32>,
        delay: u32,
        proposer: Address,
    ) -> BytesN<32> {
        let operation = Operation { target, function, args, predecessor, salt };
        schedule_operation(e, &operation, delay)
    }

    fn execute(
        e: &Env,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
        predecessor: BytesN<32>,
        salt: BytesN<32>,
        executor: Option<Address>,
    ) -> Val {
        if get_role_member_count(e, &EXECUTOR_ROLE) != 0 {
            let executor = executor.expect("executor must be present");
            ensure_role(e, &EXECUTOR_ROLE, &executor);
            executor.require_auth();
        }
        let operation = Operation { target, function, args, predecessor, salt };
        execute_operation(e, &operation)
    }

    #[only_role(canceller, "canceller")]
    fn cancel(e: &Env, operation_id: BytesN<32>, canceller: Address) {
        cancel_operation(e, &operation_id);
    }

    #[only_admin]
    fn update_delay(e: &Env, new_delay: u32, _operator: Address) {
        timelock_set_min_delay(e, new_delay);
    }
}

// ── AccessControl ─────────────────────────────────────────────────────────────

#[contractimpl(contracttrait)]
impl AccessControl for TimelockController {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;

    use soroban_sdk::{
        contract, contractimpl, symbol_short,
        testutils::{Address as _, Ledger},
        Address, BytesN, Env, IntoVal, Symbol, Vec,
    };
    use stellar_governance::timelock::{get_min_delay, get_operation_state, OperationState};

    use super::*;

    // Contrato dummy que sirve como target del timelock
    #[contract]
    struct TargetContract;

    #[contractimpl]
    impl TargetContract {
        pub fn ping(_e: &Env) -> u32 { 42 }
    }

    fn empty(e: &Env) -> BytesN<32> {
        BytesN::from_array(e, &[0u8; 32])
    }

    fn deploy(e: &Env) -> (Address, Address, Address) {
        let proposer = Address::generate(e);
        let executor = Address::generate(e);
        let mut proposers = Vec::new(e);
        proposers.push_back(proposer.clone());
        let mut executors = Vec::new(e);
        executors.push_back(executor.clone());
        let addr = e.register(TimelockController, (&proposers, &executors, &None::<Address>));
        (addr, proposer, executor)
    }

    // ── constructor ───────────────────────────────────────────────────────────

    #[test]
    fn constructor_sets_48h_delay() {
        let e = Env::default();
        let (addr, _, _) = deploy(&e);
        e.as_contract(&addr, || {
            assert_eq!(get_min_delay(&e), DELAY_48H);
        });
    }

    // ── schedule ──────────────────────────────────────────────────────────────

    #[test]
    fn schedule_creates_pending_operation() {
        let e = Env::default();
        let (addr, proposer, _) = deploy(&e);
        let target = e.register(TargetContract, ());
        e.mock_all_auths();

        let client = TimelockControllerClient::new(&e, &addr);
        let op_id = client.schedule(
            &target,
            &Symbol::new(&e, "ping"),
            &Vec::new(&e),
            &empty(&e),
            &empty(&e),
            &DELAY_48H,
            &proposer,
        );

        e.as_contract(&addr, || {
            assert_eq!(get_operation_state(&e, &op_id), OperationState::Waiting);
        });
    }

    // ── execute before delay ──────────────────────────────────────────────────

    #[test]
    #[should_panic]
    fn execute_before_delay_fails() {
        let e = Env::default();
        let (addr, proposer, executor) = deploy(&e);
        let target = e.register(TargetContract, ());
        e.mock_all_auths();

        let client = TimelockControllerClient::new(&e, &addr);
        client.schedule(
            &target,
            &Symbol::new(&e, "ping"),
            &Vec::new(&e),
            &empty(&e),
            &empty(&e),
            &DELAY_48H,
            &proposer,
        );

        // Intenta ejecutar antes de que pase el delay
        client.execute(
            &target,
            &Symbol::new(&e, "ping"),
            &Vec::new(&e),
            &empty(&e),
            &empty(&e),
            &Some(executor),
        );
    }

    // ── execute after delay ───────────────────────────────────────────────────

    #[test]
    fn execute_after_delay_succeeds() {
        let e = Env::default();
        let (addr, proposer, executor) = deploy(&e);
        let target = e.register(TargetContract, ());
        e.mock_all_auths();
        e.ledger().with_mut(|l| l.sequence_number = 100);

        let client = TimelockControllerClient::new(&e, &addr);
        client.schedule(
            &target,
            &Symbol::new(&e, "ping"),
            &Vec::new(&e),
            &empty(&e),
            &empty(&e),
            &DELAY_48H,
            &proposer,
        );

        e.ledger().with_mut(|l| l.sequence_number = 100 + DELAY_48H);

        client.execute(
            &target,
            &Symbol::new(&e, "ping"),
            &Vec::new(&e),
            &empty(&e),
            &empty(&e),
            &Some(executor),
        );
    }

    // ── cancel ────────────────────────────────────────────────────────────────

    #[test]
    fn cancel_removes_operation() {
        let e = Env::default();
        let (addr, proposer, _) = deploy(&e);
        let target = e.register(TargetContract, ());
        e.mock_all_auths();

        let client = TimelockControllerClient::new(&e, &addr);
        let op_id = client.schedule(
            &target,
            &Symbol::new(&e, "ping"),
            &Vec::new(&e),
            &empty(&e),
            &empty(&e),
            &DELAY_48H,
            &proposer,
        );

        client.cancel(&op_id, &proposer); // proposer también es canceller

        e.as_contract(&addr, || {
            assert_eq!(get_operation_state(&e, &op_id), OperationState::Unset);
        });
    }

    // ── update_delay ──────────────────────────────────────────────────────────

    #[test]
    fn update_delay_changes_min_delay() {
        let e = Env::default();
        let (addr, _, _) = deploy(&e);
        e.mock_all_auths();

        let client = TimelockControllerClient::new(&e, &addr);
        // El timelock es su propio admin, así que usamos mock_all_auths
        client.update_delay(&1000u32, &addr);

        e.as_contract(&addr, || {
            assert_eq!(get_min_delay(&e), 1000);
        });
    }
}
