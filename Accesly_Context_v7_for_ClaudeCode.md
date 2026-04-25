# Accesly — Contexto completo v6

## Qué es Accesly

Accesly es infraestructura de autenticación no-custodial para Stellar/Soroban. Es un paquete npm (`@accesly/sdk`) que permite a developers integrar wallets Stellar en sus apps con social login, biométricos, recovery con ZK email, fee abstraction, y yield automático. El usuario final no sabe que usa blockchain.

El target son developers y empresas emergentes (especialmente en el corredor México) que quieren ofrecer wallets Stellar sin ser expertos en blockchain. El usuario final ve "Continuar con Google" y tiene una wallet con USDC, CETES, onramp/offramp con SPEI.

## Posición competitiva

No competimos con Crossmint (horizontal, 50+ chains, minting). Somos verticales y profundos en Stellar + corredor México. Diferenciador principal: yield automático donde el SDK le paga al developer por tener usuarios (Blend 60/30/10).

## Arquitectura MPC (Shamir 2-of-3)

La llave maestra (keypair ed25519) se genera en el dispositivo del usuario (client-side). NUNCA en el servidor. El SDK la divide con Shamir Secret Sharing en 3 fragmentos:

- F1: vive en el dispositivo, protegido por passkey/biométrico en el Secure Enclave
- F2: se envía cifrado al backend, almacenado en DynamoDB cifrado con AWS KMS
- F3: se envía cifrado al backend, almacenado en DynamoDB cifrado con PBKDF2 del email

Cualquier combinación de 2 fragmentos reconstruye la llave. La reconstrucción siempre ocurre client-side. La llave maestra NUNCA existe en el servidor, ni durante la creación ni durante la firma. El backend solo recibe la pubkey (para registrar el signer en el Smart Account) y los fragmentos cifrados (para almacenar).

Para firmar una transacción: biométrico desbloquea F1 → SDK solicita F2 al backend → backend envía F2 re-cifrado con llave de sesión efímera → SDK reconstruye → firma XDR → destruye llave de memoria.

## Recovery con ZK Email (MVP, no futuro)

No hay OTPs. La verificación de identidad para recovery es 100% on-chain via stellar-zk-email de OZ.

Flujo:
1. Usuario perdió teléfono, abre app en dispositivo nuevo
2. SES envía email al usuario (no OTP, email con contenido para ZK proof)
3. SDK extrae headers DKIM del email, genera ZK proof de propiedad del email
4. SDK envía ZK proof al Smart Account on-chain
5. Smart Account verifica via stellar-zk-email (contrato compartido)
6. Smart Account emite evento "recovery autorizado"
7. Backend observa autorización on-chain (NO valida identidad)
8. Backend entrega F2+F3 cifrados al dispositivo nuevo
9. SDK reconstruye llave (Shamir F2+F3), genera nuevo F1 con biométrico nuevo
10. Actualiza signer on-chain, invalida F1 anterior

El backend no intermedia la verificación de identidad. El contrato la valida directamente on-chain. Esto es lo que hace al sistema genuinamente no-custodial.

## Hooks del SDK

Dos hooks separados:

`useAcceslyAuth()` — para login/registro/recover. Funciona SIN usuario autenticado (pantalla de login):
- registerWithGoogle(), registerWithApple(), registerWithEmail(email)
- login(), logout(), recover()
- isAuthenticated, user, isLoading

`useAccesly()` — para todo lo demás. REQUIERE usuario autenticado:
- accesly.wallet: balances(), address(), history()
- accesly.tx: sendPayment(to, amount, asset), swap(from, to, amount), invokeContract(contractId, functionName, args)
- accesly.session: create(scope, duration), revoke()
- accesly.settings: limits(), signers(), devices(), addDevice(), removeDevice()
- accesly.kyc: start(), status()
- accesly.yield: invest(amount), redeem(amount), yieldBalance()
- (Fase 11 agrega: depositToBlend, withdrawFromBlend, blendBalance, yieldHistory)
- (Fase 12 agrega: accesly.bridge namespace)

invokeContract() valida contra lista de contratos permitidos (context rule 8). Si está en lista: session key. Si no: biométrico completo.

## Context Rules (9 reglas on-chain)

| Regla | Nombre | Cuándo | Signer | Policy |
|-------|--------|--------|--------|--------|
| 0 | biometric-tx | Transferencias normales | ed25519 | spending_limit |
| 1 | admin-cfg | Cambiar signers/rules/upgrade | ed25519 estricto | — |
| 2 | zk-recovery | Recovery | zk_email | — |
| 3 | sep10-auth | SEP-10 challenge | secp256r1 passkey | — |
| 4 | yield-auto | Distribución CETES 50/50 | — (sin firma) | yield_policy |
| +N | session-key | Pagos pequeños | session ed25519 | session_key |
| +N | allowlist-tx | Contratos terceros permitidos | session key | — |
| +N | blend-rule | Operaciones Blend DeFi (session key) | session key | blend_rule_policy |
| 9 | yield-blend (Fase 11) | Distribución Blend 60/30/10 | — (sin firma) | blend_yield |

## Smart Contracts (12 contratos en Soroban)

Repo: https://github.com/daniellagart4-sys/Accesly-SmartContracts.git

Estructura en contracts/:
- smart-account/ — AcceslySmartAccount con CustomAccountInterface, context_rules.rs (5 reglas base), trustlines.rs
- ed25519-verifier/ — Compartido, valida firmas de llave reconstruida
- secp256r1-verifier/ — WebAuthn/passkey para SEP-10
- spending-limit/ — Delega a OZ spending_limit
- session-key/ — Policy custom con SessionKeyInstallParams
- yield-distribution/ — CETES 50/50, valida transfer() SEP-41, max_amount_per_transfer configurable
- governance/ — TimelockController 48h (34560 ledgers), CustomAccountInterface para self-admin
- zk-email-verifier/ — DKIM registry + Verifier trait
- blend-vault/ — SEP-56 Vault con Blend backend, total_assets() override (Fase 11)
- blend-yield-policy/ — Policy 60/30/10 (Fase 11)
- blend-rule/ — Policy para session keys de Blend: restricta pool autorizado, request types permitidos y monto máximo por request
- upgrade-rule/ — Policy para session keys de upgrade: solo permite upgrade() sobre un contrato objetivo específico

Dependencias: OZ Stellar Contracts v0.7.1, soroban-sdk 25.3.0. Dependencias via path local a oz-reference clonado:
stellar-accounts = { path = "../oz-reference/packages/accounts", version = "=0.7.1" }

4 limitaciones técnicas confirmadas:
1. Blend sin SDK Rust → invoke_contract manual (structs BlendPositions/BlendReserveData verificados contra Blend v2; REQUEST_SUPPLY_COLLATERAL=2, REQUEST_WITHDRAW_COLLATERAL=3)
2. total_assets() override necesario porque USDC va a Blend
3. Porcentajes 60/30/10 hardcodeados (upgrade requiere timelock 48h)
4. CETES+Blend coexisten sin conflicto (storage/rules separados)

## Backend AWS (8 Lambdas, 7 tablas DynamoDB)

Lambdas:
- createWallet — recibe del SDK: pubkey + F2 cifrado + F3 cifrado. No genera llave. Almacena, despliega Smart Account, configura policies y trustlines. Relayer paga XLM
- getFragment2 — valida JWT (+MFA si appId lo requiere), entrega F2 re-cifrado con llave de sesión
- sep30Handler — SEP-30, entrega F2+F3 tras autorización on-chain de ZK email
- manageTTL — cron 24h, extiende TTL de Smart Accounts
- etherfuseKYC — KYC con Etherfuse
- etherfuseOrder — onramp/offramp SPEI
- etherfuseWebhook — webhooks de Etherfuse
- distributeYield — cron semanal, dispara distribución CETES 50/50 via policy on-chain
- sendDeveloperWebhook — webhooks a developers

Tablas DynamoDB:
- user_fragments (F2, cifrado KMS)
- email_fragments (F3, cifrado PBKDF2)
- user_kyc_status
- app_configs (config por appId: assets, fees, CORS, redirect URIs, branding, MFA, blend_config)
- yield_positions (principal, yield, source cetes/blend)
- audit_logs (todas las acciones por appId, filtrable)
- developer_accounts (datos del developer)
- developer_apps (apps por developer, appId, API key hash)

Servicios AWS: Cognito (Google/Apple OAuth + MFA configurable), KMS, SES (solo notificaciones, no OTPs), API Gateway (Cognito Authorizer, CORS por appId, rate limiting), CloudWatch + X-Ray, WAF + VPC + IAM least privilege.

## Etherfuse — Integraciones

- KYC unificado (hosted o programmatic)
- Onramp MXN→USDC vía SPEI
- Offramp USDC→MXN vía SPEI
- CETES Stablebonds (inversión + redención + rebase semanal)
- MXNe (Sovereign Coin, stablecoin peso, yield nativo por CETES)
- Etherfuse FX (conversión USD↔MXN, 90% menos que bancos)

## Yield — Modelo de distribución

CETES (MVP): 50% usuario / 50% Accesly. Rebase semanal de Etherfuse. Lambda distributeYield detecta y dispara via policy on-chain. Sin firma del usuario.

Blend (Fase 11, post-MVP): 60% usuario / 30% developer (por appId) / 10% Accesly. Via Vault SEP-56. Porcentajes hardcodeados. Semanal. Sin firma del usuario.

USDC y MXNe no conflictan: USDC→Blend (DeFi), MXNe→yield nativo (CETES). No mezclar.

## Modelo de negocio

Accesly paga upfront (Relayer absorbe costo de wallet). Cobra al developer via x402 después de tier gratuito:
- Wallets: 100 gratis/mes, después base + trustlines (0.20 + 0.05/trustline extra)
- Transacciones: 1,000 gratis/mes, después 0.01 USDC
- Queries: 10,000 gratis/mes, después 0.001 USDC
- KYC: 50 gratis/mes, después 0.10 USDC
- Recovery: siempre gratis

Costo real por wallet: ~1.6 XLM (1 trustline) a ~3.1 XLM (4 trustlines). Al precio actual de XLM (~$0.15), eso es $0.24 a $0.47 USD. AWS es despreciable (<$0.00001).

Revenue: x402 + CETES 50% + Blend 10% (post-MVP). El yield de CETES/Blend recupera el costo de wallet rápido.

Política de refund x402: no se cobra si la transacción falla por error del Relayer o Stellar. Solo se cobra en éxito.

## Fee Abstraction

OZ Relayer Service hospedado. Channels plugin para procesamiento paralelo. Dos opciones por appId:
- Developer paga: Relayer absorbe XLM, usuario no paga nada
- Usuario paga con token: swap automático USDC/EURC a XLM vía SDEX

Fund account se repone automáticamente swapeando USDC de x402 a XLM. Alertas 20%/5%.

## Dashboard de developers

App Next.js, Cognito Pool separado. El developer:
- Crea apps, recibe appId + API key
- Configura: assets, fees, redirect URIs, webhooks, branding (colores, logo, botón, dark mode), MFA
- Ve métricas: wallets, tx, queries, KYCs, billing x402
- Ve audit logs filtrables (quién hizo qué y cuándo)
- Rota API keys si se comprometen
- Configura webhooks (qué eventos recibir, HMAC para autenticidad)
- Sandbox con testnet + docs embebidas

## Dashboard interno de Accesly

Panel de control del negocio (no visible para developers):
- Métricas ecosistema: developers, apps, wallets, transacciones
- Revenue y finanzas: x402, CETES 50%, Blend 10%, costos AWS/Relayer, margen neto
- Salud infraestructura: fund account, uptime, TTL contratos, latencias, error rates
- Seguridad: intentos recovery, cambios signer, upgrades timelock, KMS audit, WAF
- Etherfuse/Blend/yield: volúmenes, KYCs, TVL, APY, yield Accesly
- Verificación periódica: rotación KMS, Cognito, credenciales, DKIM, stellar.toml

## Branding configurable del SDK

El developer configura desde el dashboard:
- Color primario y fondo del botón/modal de login
- Logo URL
- Texto del botón ("Continuar con Google" / texto custom)
- Estilo: filled, outlined, text-only
- Bordes redondeados
- Fuente
- Dark mode: auto/light/dark

El SDK aplica estos estilos automáticamente. Si no hay branding, usa default de Accesly.

## MFA configurable

Por appId: obligatorio, opcional, o desactivado. Métodos: TOTP (Google Authenticator) y/o passkey como segundo factor. Cognito lo gestiona. El SDK lo aplica automáticamente según config del appId.

## SEP-10 y SEP-30

SEP-10 cliente: autenticación ante servicios externos (Etherfuse, anchors). SDK firma challenge client-side.
SEP-10 servidor: dApps verifican usuarios de Accesly.
SEP-30: recovery server, endpoints estándar, integra ZK email on-chain.
stellar.toml publicado con info org, contratos, endpoints, signing key, assets.

## Axelar cross-chain (Fase 12, post-MVP)

Integración con Axelar Gateway, ITS, TokenManager ya desplegados en Stellar. No se agregan smart contracts propios. Trustlines para tokens bridgeados. Lambda axelarBridge. Hook accesly.bridge. WalletConnect para firma en chain origen (MetaMask). Monitoreo cross-chain. Swap USDC nativo ↔ bridgeado.

## Landing + docs + legal (Fase 9)

accesly.com: landing page con pitch + docs públicas integradas (sin login) + TOS developers + TOS usuarios (template) + política de privacidad. La documentación cubre: guía inicio rápido, referencia useAcceslyAuth + useAccesly, guías de branding/MFA/webhooks/yield/Blend.

## Pipelines de seguridad (8 pipelines)

1. Smart Contracts (cada PR): WASM build, tests, Security Detector, dependency audit, ZK fuzzing
2. Backend (cada PR): SAST, IAM policy check, KMS key policy, secret scanning
3. SDK (cada PR): npm audit, bundle size, memory destruction verification
4. IaC scanning: S3/SG/VPC/DynamoDB/KMS/Cognito/WAF validation, drift detection
5. DAST (periódico staging): inyección, auth rota, CORS, rate limiting, webhook validation
6. Secrets y rotación (continuo): Dependabot, credential expiry, CloudWatch log scanning
7. Container scanning (futuro): Docker images
8. Branch protection: PR required, reviews, signed commits, no force push


## Roadmap completo (105 issues, 12 fases)

Fase 1: Smart Contracts (15 issues) — Soroban + OZ v0.7.1 + CI/CD seguridad
Fase 2: Backend AWS (23 issues) — Lambdas, DynamoDB, Cognito, KMS, webhooks, abuse protection
Fase 3: SDK npm (8 issues) — useAcceslyAuth + useAccesly + branding configurable
Fase 4: Relayer + x402 (6 issues) — Fee abstraction, pago por uso, refund policy
Fase 5: Etherfuse (6 issues) — KYC, onramp, offramp, CETES, MXNe, FX
Fase 6: Testing + SEPs (6 issues) — SEP-10, SEP-30, Stellar Wallet Kit, auditoría
Fase 7: Dashboard developers (12 issues) — appId generation, métricas, audit logs, API key rotation, webhooks config, branding
Fase 8: Dashboard Accesly (6 issues) — Visibilidad interna: ecosistema, revenue, salud, seguridad, yield, rotación
Fase 9: Landing + docs + legal (4 issues) — accesly.com, docs públicas, TOS, privacidad
Fase 10: Mainnet (4 issues) — Deploy producción
Fase 11: Blend post-MVP (9 issues) — Vault SEP-56, yield 60/30/10, tests, activación en dashboards/docs
Fase 12: Axelar post-MVP (6 issues) — ITS, GMP, WalletConnect, monitoreo cross-chain

Issues preparatorias de Blend en fases anteriores: 2.6 (blend_config en app_configs), 2.7 (source field en yield_positions), 2.8 (eventos Blend en audit_logs), 2.17 (eventos Blend en webhooks), 3.2 (Provider carga blend_config), 3.5 (yield namespace preparado), 6.4 (tests Blend listados), 7.8 (UI Blend preparada), 8.2/8.5 (métricas Blend), 9.2 (guía Blend en docs).

## Decisiones clave de arquitectura

- Generación de llave client-side (NUNCA en el servidor)
- ZK email es MVP (no futuro) — elimina OTPs, sendOTP, validateOTP
- Hook único useAccesly con namespaces + hook separado useAcceslyAuth
- Blend porcentajes hardcodeados (seguridad > flexibilidad)
- OZ v0.7.1 (no 0.7.0 — OZ publicó patch)
- MFA configurable por appId (no obligatorio para todos)
- Branding configurable desde dashboard (no CSS del developer)
- Redirect URIs fluyen: dashboard → createApp → developer_apps → app_configs → Cognito

## Costo por wallet

| Trustlines | XLM total | USD (~$0.15/XLM) |
|---|---|---|
| 1 (solo USDC) | ~1.6 XLM | ~$0.24 |
| 2 (USDC + MXNe) | ~2.1 XLM | ~$0.32 |
| 3 (USDC + MXNe + CETES) | ~2.6 XLM | ~$0.39 |
| 4 (USDC + EURC + CETES + MXNe) | ~3.1 XLM | ~$0.47 |

Trustlines de issuers:
- USDC: Circle (testnet)
- EURC: Circle
- CETES: Etherfuse
- MXNe: Bitso/Etherfuse

