#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JNI_DIR="${ROOT_DIR}/../../apps/mobile/android/app/src/main/jniLibs"

command -v cargo >/dev/null
command -v cargo-ndk >/dev/null || {
  echo "cargo-ndk is required: cargo install cargo-ndk" >&2
  exit 1
}

mkdir -p "${JNI_DIR}"
rm -rf "${JNI_DIR}/arm64-v8a" "${JNI_DIR}/x86_64"

cargo ndk \
  -t arm64-v8a \
  -t x86_64 \
  -o "${JNI_DIR}" \
  build --release

for abi in arm64-v8a x86_64; do
  test -f "${JNI_DIR}/${abi}/libvextro_crypto_rs.so"
done

echo "Built Android libraries in ${JNI_DIR}"
