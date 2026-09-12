#!/usr/bin/env bash
set -euo pipefail
# Identity is assigned by webpack; never overwrite it with an upstream key.
node "$(dirname "$0")/development-identity.mjs"
