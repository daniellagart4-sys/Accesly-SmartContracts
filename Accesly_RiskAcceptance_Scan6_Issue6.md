# Riesgos Aceptados — Scan 6 (2026-04-27): Findings 4 y 5

**Commit escaneado:** `ba27f89`
**Fecha de decisión:** 2026-04-27
**Aprobado por:** daniellagart4-sys (Accesly Core)
**Revisión programada:** Antes del despliegue a Stellar Mainnet

---

## Finding 4 — MEDIUM: Unvalidated verifier/policy addresses in `setup_context_rules`

**Archivo:** `contracts/smart-account/src/context_rules.rs`

### Descripción

`setup_context_rules` acepta las direcciones de verifiers y policies como parámetros
sin validación on-chain de que son los contratos canónicos de Accesly.

### Por qué se acepta

1. **Modelo de seguridad intencional.** La composabilidad del Smart Account requiere
   que el SDK (off-chain) provea las direcciones correctas. El contrato confía en el
   deployer, igual que cualquier wallet factory de la industria.

2. **Restricción post-deploy.** `setup_context_rules` solo es invocable desde
   `__constructor`, que ahora tiene init guard (`AlreadyInitialized = 9001`). Un
   atacante no puede llamarla post-deploy para sustituir verifiers.

3. **Solución real requiere un registry on-chain.** Implementar un registro de
   contratos canónicos requeriría un contrato adicional y cambiaría la arquitectura
   de deploy. Pendiente para Fase 2 si se determina necesario en auditoría externa.

4. **Mitigación procedimental.** El SDK de Accesly hardcodea las direcciones de
   verifiers y policies por red (testnet/mainnet) y las verifica antes del deploy.
   El deployer (Accesly Core) es la única parte que puede crear Smart Accounts.

---

## Finding 5 — MEDIUM: Admin seizure en `zk-email-verifier/__constructor`

**Archivo:** `contracts/zk-email-verifier/src/contract.rs`

### Descripción

El scanner advierte que si `__constructor` no se invoca atómicamente con el deploy,
un atacante podría llamarlo primero y apropiarse del admin.

### Por qué se acepta

1. **Soroban garantiza atomicidad.** En el protocolo Stellar/Soroban, `__constructor`
   es ejecutado por el host durante `InvokeHostFunction` de tipo `CreateContract` y
   **no puede ser invocado de nuevo** como función normal post-deploy. La garantía es
   a nivel de protocolo, no de código.

2. **Init guard ya existe.** El contrato ya tiene el guard `AlreadyInitialized = 100`
   como defensa en profundidad, por si alguna versión futura del SDK lo expusiera.

3. **`admin.require_auth()` descartado.** Agregar require_auth al admin en el
   constructor complicaría el flujo de deploy (el admin puede ser un contrato
   multisig que no puede firmar en el mismo ledger) sin añadir seguridad real dado
   el punto 1.
