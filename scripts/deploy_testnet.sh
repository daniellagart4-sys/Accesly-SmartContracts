#!/usr/bin/env bash
# =============================================================================
# Accesly — Deploy a Testnet
# =============================================================================
# Requisitos:
#   - stellar CLI instalado (>= 22.x)
#   - cargo ya corrido: cargo build --target wasm32v1-none --release
#
# Uso:
#   chmod +x scripts/deploy_testnet.sh
#   ./scripts/deploy_testnet.sh
#
# Al final escribe scripts/deployed_addresses.env con todas las addresses.
# =============================================================================

set -euo pipefail

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Config ────────────────────────────────────────────────────────────────────
NETWORK="testnet"
ACCOUNT="accesly"
WASM_DIR="target/wasm32v1-none/release"
OUT_FILE="scripts/deployed_addresses.env"

# Blend Testnet V2 (fijo — no cambiar)
BLEND_POOL="CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF"
USDC_SAC="CAQCFVLOBK5GIULPNZRGATJJMIZL5BSP7X5YJVMGCPTUEPFM4AVSRCJU"

# CETES SAC en testnet
CETES_CONTRACT="CC72F57YTPX76HAA64JQOEGHQAPSADQWSY5DWVBR66JINPFDLNCQYHIC"

# ── 1. Wallet Accesly ─────────────────────────────────────────────────────────
info "Comprobando identidad '$ACCOUNT'..."
if ! stellar keys address "$ACCOUNT" &>/dev/null; then
    info "Generando keypair '$ACCOUNT'..."
    stellar keys generate "$ACCOUNT" --network "$NETWORK"
else
    info "Identidad '$ACCOUNT' ya existe."
fi

ACCESLY_ADDR=$(stellar keys address "$ACCOUNT")
info "Address Accesly: $ACCESLY_ADDR"

# ── 2. Fondear con Friendbot ──────────────────────────────────────────────────
info "Fondeando con Friendbot..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://friendbot.stellar.org?addr=${ACCESLY_ADDR}")

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "400" ]; then
    # 400 = ya tiene fondos (cuenta ya existe), ambos son OK
    info "Cuenta lista (HTTP $HTTP_CODE)."
else
    error "Friendbot falló con HTTP $HTTP_CODE"
fi

# ── 3. Detectar USDC_RESERVE_INDEX en Blend pool ─────────────────────────────
info "Consultando reserve list en Blend TestnetV2..."
RESERVE_LIST_RAW=$(stellar contract invoke \
    --id "$BLEND_POOL" \
    --source-account "$ACCOUNT" \
    --network "$NETWORK" \
    -- get_reserve_list 2>&1) || true

# Buscar la posición de USDC_SAC en la lista devuelta
# La respuesta es un array JSON como: ["CABC...", "CDEF...", ...]
USDC_RESERVE_INDEX=""
if echo "$RESERVE_LIST_RAW" | grep -q "$USDC_SAC"; then
    # Extraer el array y encontrar el índice
    RESERVE_JSON=$(echo "$RESERVE_LIST_RAW" | grep -oE '\[.*\]' | head -1)
    IDX=0
    while IFS= read -r ADDR; do
        ADDR_CLEAN=$(echo "$ADDR" | tr -d '", []')
        if [ "$ADDR_CLEAN" = "$USDC_SAC" ]; then
            USDC_RESERVE_INDEX=$IDX
            break
        fi
        IDX=$((IDX + 1))
    done < <(echo "$RESERVE_JSON" | tr ',' '\n')
fi

if [ -z "$USDC_RESERVE_INDEX" ]; then
    warn "No se pudo detectar USDC_RESERVE_INDEX automáticamente."
    warn "Respuesta del pool: $RESERVE_LIST_RAW"
    error "Verifica manualmente el índice USDC en el pool y pasa USDC_RESERVE_INDEX=<n> como variable de entorno."
fi

info "USDC_RESERVE_INDEX detectado: $USDC_RESERVE_INDEX"

# ── Helper: deploy sin constructor ────────────────────────────────────────────
deploy_no_ctor() {
    local alias=$1
    local wasm=$2
    info "Desplegando $alias..."
    stellar contract deploy \
        --wasm "$WASM_DIR/$wasm" \
        --source-account "$ACCOUNT" \
        --network "$NETWORK" \
        --alias "$alias" \
        --ignore-checks
}

# ── Helper: leer address de alias ─────────────────────────────────────────────
addr_of() {
    stellar contract alias show "$1" --network "$NETWORK" 2>/dev/null \
        | grep -oE 'C[A-Z0-9]{55}' | head -1
}

# ── 3. Ed25519 Verifier (sin constructor) ─────────────────────────────────────
deploy_no_ctor "accesly-ed25519-verifier" "accesly_ed25519_verifier.wasm"
ED25519_VERIFIER=$(addr_of "accesly-ed25519-verifier")
info "ed25519-verifier → $ED25519_VERIFIER"

# ── 4. Secp256r1 Verifier (sin constructor) ───────────────────────────────────
deploy_no_ctor "accesly-secp256r1-verifier" "accesly_secp256r1_verifier.wasm"
SECP256R1_VERIFIER=$(addr_of "accesly-secp256r1-verifier")
info "secp256r1-verifier → $SECP256R1_VERIFIER"

# ── 5. ZK Email Verifier (admin = Accesly wallet) ─────────────────────────────
info "Desplegando accesly-zk-email-verifier..."
stellar contract deploy \
    --wasm "$WASM_DIR/accesly_zk_email_verifier.wasm" \
    --source-account "$ACCOUNT" \
    --network "$NETWORK" \
    --alias "accesly-zk-email-verifier" \
    --ignore-checks \
    -- \
    --admin "$ACCESLY_ADDR"
ZK_EMAIL_VERIFIER=$(addr_of "accesly-zk-email-verifier")
info "zk-email-verifier → $ZK_EMAIL_VERIFIER"

# ── 6. Spending Limit Policy (sin constructor) ────────────────────────────────
deploy_no_ctor "accesly-spending-limit" "accesly_spending_limit.wasm"
SPENDING_LIMIT=$(addr_of "accesly-spending-limit")
info "spending-limit → $SPENDING_LIMIT"

# ── 7. Session Key Policy (sin constructor) ───────────────────────────────────
deploy_no_ctor "accesly-session-key" "accesly_session_key.wasm"
SESSION_KEY=$(addr_of "accesly-session-key")
info "session-key → $SESSION_KEY"

# ── 8. Yield Distribution Policy (sin constructor) ────────────────────────────
deploy_no_ctor "accesly-yield-distribution" "accesly_yield_distribution.wasm"
YIELD_DISTRIBUTION=$(addr_of "accesly-yield-distribution")
info "yield-distribution → $YIELD_DISTRIBUTION"

# ── 9. Governance (proposers=[Accesly], executors=[Accesly], admin=Accesly) ───
info "Desplegando accesly-governance..."
stellar contract deploy \
    --wasm "$WASM_DIR/accesly_governance.wasm" \
    --source-account "$ACCOUNT" \
    --network "$NETWORK" \
    --alias "accesly-governance" \
    --ignore-checks \
    -- \
    --proposers "[\"$ACCESLY_ADDR\"]" \
    --executors "[\"$ACCESLY_ADDR\"]" \
    --admin    "$ACCESLY_ADDR"
GOVERNANCE=$(addr_of "accesly-governance")
info "governance → $GOVERNANCE"

# ── 10. Blend Vault ────────────────────────────────────────────────────────────
info "Desplegando accesly-blend-vault..."
stellar contract deploy \
    --wasm "$WASM_DIR/accesly_blend_vault.wasm" \
    --source-account "$ACCOUNT" \
    --network "$NETWORK" \
    --alias "accesly-blend-vault" \
    --ignore-checks \
    -- \
    --usdc_address        "$USDC_SAC" \
    --blend_pool          "$BLEND_POOL" \
    --usdc_reserve_index  "$USDC_RESERVE_INDEX" \
    --name                "Accesly Blend USDC" \
    --symbol              "abUSDC"
BLEND_VAULT=$(addr_of "accesly-blend-vault")
info "blend-vault → $BLEND_VAULT"

# ── 11. Blend Yield Policy (sin constructor) ──────────────────────────────────
# El constructor no recibe args — el vault address se pasa en cada llamada enforce.
deploy_no_ctor "accesly-blend-yield-policy" "accesly_blend_yield_policy.wasm"
BLEND_YIELD_POLICY=$(addr_of "accesly-blend-yield-policy")
info "blend-yield-policy → $BLEND_YIELD_POLICY"

# ── 12. Smart Account (template — 1 deploy compartido) ────────────────────────
# NOTA: El Smart Account es un template que se instancia por usuario.
# Este deploy es el contrato base; cada usuario deploy su propia instancia
# con sus propias claves. Ver SDK para el flujo de deploy por usuario.
#
# Ejemplo mínimo con USDC trustline habilitada:
# trusted_assets se pasa como Vec<StellarAsset> serializado en XDR.
# Por ahora se despliega el WASM (upload) sin instanciar — cada instancia
# la crea el SDK del desarrollador con los parámetros del usuario final.
info "Subiendo WASM accesly-smart-account (sin instanciar)..."
stellar contract upload \
    --wasm "$WASM_DIR/accesly_smart_account.wasm" \
    --source-account "$ACCOUNT" \
    --network "$NETWORK"
SMART_ACCOUNT_HASH=$(stellar contract info hash \
    --wasm "$WASM_DIR/accesly_smart_account.wasm" \
    --network "$NETWORK" 2>/dev/null || echo "ver output arriba")
info "smart-account WASM hash → $SMART_ACCOUNT_HASH"

# ── 13. Guardar addresses ─────────────────────────────────────────────────────
mkdir -p scripts
cat > "$OUT_FILE" <<EOF
# Accesly — Testnet Deployed Addresses
# Generado: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Red: $NETWORK

ACCESLY_DEPLOYER=$ACCESLY_ADDR

# Verifiers
ED25519_VERIFIER=$ED25519_VERIFIER
SECP256R1_VERIFIER=$SECP256R1_VERIFIER
ZK_EMAIL_VERIFIER=$ZK_EMAIL_VERIFIER

# Policies
SPENDING_LIMIT_POLICY=$SPENDING_LIMIT
SESSION_KEY_POLICY=$SESSION_KEY
YIELD_DISTRIBUTION_POLICY=$YIELD_DISTRIBUTION
BLEND_YIELD_POLICY=$BLEND_YIELD_POLICY

# Core
GOVERNANCE=$GOVERNANCE
BLEND_VAULT=$BLEND_VAULT

# Blend Testnet (externos, no cambian)
BLEND_POOL=$BLEND_POOL
USDC_SAC=$USDC_SAC
USDC_RESERVE_INDEX=$USDC_RESERVE_INDEX
CETES_CONTRACT=$CETES_CONTRACT

# Smart Account WASM (instanciado por usuario via SDK)
SMART_ACCOUNT_WASM_HASH=$SMART_ACCOUNT_HASH
EOF

info "Addresses guardadas en $OUT_FILE"

# ── 14. Resumen ───────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Deploy completado exitosamente en $NETWORK${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo "  Deployer:              $ACCESLY_ADDR"
echo "  ed25519-verifier:      $ED25519_VERIFIER"
echo "  secp256r1-verifier:    $SECP256R1_VERIFIER"
echo "  zk-email-verifier:     $ZK_EMAIL_VERIFIER"
echo "  spending-limit:        $SPENDING_LIMIT"
echo "  session-key:           $SESSION_KEY"
echo "  yield-distribution:    $YIELD_DISTRIBUTION"
echo "  governance:            $GOVERNANCE"
echo "  blend-vault:           $BLEND_VAULT"
echo "  blend-yield-policy:    $BLEND_YIELD_POLICY"
echo "  smart-account hash:    $SMART_ACCOUNT_HASH"
echo "  CETES contract:        $CETES_CONTRACT"
echo "  USDC reserve index:    $USDC_RESERVE_INDEX (detectado automáticamente)"
echo ""
echo -e "${YELLOW}POST-DEPLOY (manual):${NC}"
echo "  1. USDC_RESERVE_INDEX=$USDC_RESERVE_INDEX — detectado y aplicado automáticamente."
echo "  2. Registrar DKIM keys en zk-email-verifier:"
echo "     stellar contract invoke --id $ZK_EMAIL_VERIFIER \\"
echo "       --source-account accesly --network testnet \\"
echo "       -- set_dkim_public_key_hash \\"
echo "       --domain_hash <sha256_del_dominio_hex> \\"
echo "       --public_key_hash <hash_de_la_clave_dkim_hex> \\"
echo "       --operator $ACCESLY_ADDR"
echo "  3. Configurar Lambda con BLEND_VAULT=$BLEND_VAULT"
echo "     y BLEND_YIELD_POLICY=$BLEND_YIELD_POLICY"
echo ""
