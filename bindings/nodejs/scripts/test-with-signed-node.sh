#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BINDING_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd -- "${BINDING_DIR}/../.." && pwd)"

ENTITLEMENTS_FILE="${REPO_ROOT}/shuru.entitlements"
NAPI_CLI="${BINDING_DIR}/node_modules/.bin/napi"
AVA_CLI="${BINDING_DIR}/node_modules/.bin/ava"
SIGNED_NODE_DIR="${BINDING_DIR}/.signed-node"
SIGNED_NODE_BIN="${SIGNED_NODE_DIR}/node"
SOURCE_NODE_BIN="${npm_node_execpath:-$(command -v node)}"

if [[ ! -f "${ENTITLEMENTS_FILE}" ]]; then
  echo "missing entitlements file: ${ENTITLEMENTS_FILE}" >&2
  exit 1
fi

if [[ ! -x "${SOURCE_NODE_BIN}" ]]; then
  echo "missing source node binary: ${SOURCE_NODE_BIN}" >&2
  exit 1
fi

if [[ ! -x "${NAPI_CLI}" ]]; then
  echo "missing napi CLI: ${NAPI_CLI}" >&2
  exit 1
fi

if [[ ! -x "${AVA_CLI}" ]]; then
  echo "missing ava CLI: ${AVA_CLI}" >&2
  exit 1
fi

mkdir -p "${SIGNED_NODE_DIR}"
cp -f "${SOURCE_NODE_BIN}" "${SIGNED_NODE_BIN}"
chmod +x "${SIGNED_NODE_BIN}"

codesign --entitlements "${ENTITLEMENTS_FILE}" --force -s - "${SIGNED_NODE_BIN}"

export PATH="${SIGNED_NODE_DIR}:${PATH}"
export NODE="${SIGNED_NODE_BIN}"
export npm_node_execpath="${SIGNED_NODE_BIN}"
export SHURU_NODEJS_TEST_NODE_BINARY="${SIGNED_NODE_BIN}"

"${NAPI_CLI}" build --platform
exec "${AVA_CLI}" "$@"
