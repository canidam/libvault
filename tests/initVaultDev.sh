#!/bin/bash
# Initialize vault server in dev mode for development and testing

EXPECTED_VAULT_VERSION=1.6
# shellcheck disable=SC2164
SCRIPT_DIR=$(cd "$(dirname $0)"; pwd)

export ROOT_TOKEN=root-token
export VAULT_ADDR=http://localhost:8200

function die() {
  log "$*"; exit 1
}

function log() {
  echo "$(date '+%D %H:%M:%S') - $*"
}
# shellcheck disable=SC2164
log "Changing dir to $SCRIPT_DIR" && cd "$SCRIPT_DIR"

# Validate EXPECTED_VAULT_VERSION is installed
VAULT_VERSION=$(vault -v 2> /dev/null | cut -d' ' -f2 | grep -o '[[:digit:]].[[:digit:]]')
[ -z "${VAULT_VERSION}" ] && die "Vault wasn't found in PATH. Install Vault v${EXPECTED_VAULT_VERSION}.x to proceed"
[ "${VAULT_VERSION}" != "${EXPECTED_VAULT_VERSION}" ] && die "Vault version doesn't match the expected one. Install Vault v${EXPECTED_VAULT_VERSION}.x to proceed"

log "Starting Vault dev server, logs to ./vaultdev.log"
vault server -dev -dev-root-token-id ${ROOT_TOKEN} > ./vaultdev.log 2>&1 &
log "Vault started. to stop it, simply kill the process. Preparing data.."

# Create secrets, policies, etc..
sleep 1
# shellcheck disable=SC2129
vault kv put secret/data1 mysecret=supersecret >> ./vaultdev.log

# Policies
vault policy write admin vaultAdmin-policy.hcl >> ./vaultdev.log
vault policy write provisioner vaultProvisioner-policy.hcl >> ./vaultdev.log

# AppRole
vault auth enable approle >> ./vaultdev.log
vault write auth/approle/role/libvault policies=admin token_ttl=300s token_max_ttl=300m secret_id_num_uses=100 >> ./vaultdev.log

# TODO: create token other than root token

VAULT_ROLE_ID=$(vault read -field=role_id auth/approle/role/libvault/role-id)
VAULT_SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/libvault/secret-id)
VAULT_TOKEN=${ROOT_TOKEN}
export VAULT_ROLE_ID
export VAULT_SECRET_ID
export VAULT_TOKEN

# shellcheck disable=SC2164
log "Changing dir back" && cd -
log "Done"
