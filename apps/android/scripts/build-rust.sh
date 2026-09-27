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

# Release 覆盖全部发布 ABI；Debug 默认只构建真机 arm64 与模拟器 x86_64。
if [[ "$profile" == "release" ]]; then
  default_abis="armeabi-v7a arm64-v8a x86_64"
else
  default_abis="arm64-v8a x86_64"
fi
read -r -a abis <<<"${VAULTMESH_ANDROID_ABIS:-$default_abis}"
target_args=()
for abi in "${abis[@]}"; do
  case "$abi" in
    armeabi-v7a|arm64-v8a|x86_64) target_args+=(--target "$abi") ;;
    *) echo "unsupported Android ABI: $abi" >&2; exit 1 ;;
  esac
done

cd "$repo_dir"
cargo_args=(build --package vaultmesh-android-runtime)
if [[ "$profile" == "release" ]]; then
  cargo_args+=(--release)
fi
cargo ndk \
  --platform 26 \
  "${target_args[@]}" \
  --output-dir "$output_dir" \
  "${cargo_args[@]}"
