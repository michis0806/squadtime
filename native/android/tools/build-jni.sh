#!/usr/bin/env bash
set -euo pipefail
sdk_dir="$1"
repository_dir="$2"
output_dir="$3"
ndk_version=29.0.14206865
host_tag=darwin-x86_64
case "$(uname -s)" in
  Linux) host_tag=linux-x86_64 ;;
  Darwin) host_tag=darwin-x86_64 ;;
  *) echo 'Unsupported JNI build host' >&2; exit 1 ;;
esac
compiler="$sdk_dir/ndk/$ndk_version/toolchains/llvm/prebuilt/$host_tag/bin/aarch64-linux-android31-clang"
rust_dir="$repository_dir/.local/native/android/arm64-v8a"
test -f "$rust_dir/libsquadtime_mls_spike.so"
mkdir -p "$output_dir/arm64-v8a"
"$compiler" -std=c11 -O2 -fPIC -shared -Wall -Wextra -Werror \
  -Wl,--no-undefined -Wl,-z,max-page-size=16384 -Wl,-soname,libsquadtime_mls_jni.so \
  -I "$repository_dir/native/include" \
  "$repository_dir/native/android/pairing/src/main/cpp/mls_jni.c" \
  -L "$rust_dir" -lsquadtime_mls_spike \
  -o "$output_dir/arm64-v8a/libsquadtime_mls_jni.so"
