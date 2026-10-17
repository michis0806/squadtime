#!/bin/sh
set -eu
case "${PLATFORM_NAME:-}" in
  iphonesimulator) build_mode=apple-simulator ;;
  iphoneos) build_mode=apple-device ;;
  *) echo 'error: Rust MLS proof supports only iOS and iOS Simulator'; exit 1 ;;
esac
archive="${SRCROOT}/../../.local/native/apple/${PLATFORM_NAME}/libsquadtime_mls_spike.a"
if [ ! -f "$archive" ]; then
  echo "error: Missing Rust MLS archive. Run node scripts/build-native-mls.mjs ${build_mode} from the repository root."
  exit 1
fi
