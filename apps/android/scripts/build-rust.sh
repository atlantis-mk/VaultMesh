#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
android_dir="$(cd "$script_dir/.." && pwd)"
repo_dir="$(cd "$android_dir/../.." && pwd)"
profile="${1:-debug}"
if [[ "$profile" != "debug" && "$profile" != "release" ]]; then
  echo "usage: build-rust.sh [debug|release]" >&2
  exit 1
fi
output_dir="$android_dir/app/src/$profile/jniLibs"

: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK directory}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/28.2.13676358}"

if [[ "$(cargo ndk --version 2>/dev/null || true)" != "cargo-ndk 4.1.2" ]]; then
  echo "cargo-ndk 4.1.2 is required: cargo install cargo-ndk --version 4.1.2 --locked" >&2
  exit 1
fi

cd "$repo_dir"
if [[ "$profile" == "release" ]]; then
  cargo ndk \
    --platform 26 \
    --target arm64-v8a \
    --target x86_64 \
    --output-dir "$output_dir" \
    build --release --package vaultmesh-android-runtime
else
  cargo ndk \
    --platform 26 \
    --target arm64-v8a \
    --target x86_64 \
    --output-dir "$output_dir" \
    build --package vaultmesh-android-runtime
fi
