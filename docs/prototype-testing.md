# Local device prototype testing

This guide covers the development-only iOS and Android prototype for one direct
test contact. Use synthetic nicknames and test devices on a private LAN. Do not
enter real family, child, or account data.

The prototype is not production onboarding or a general chat app. It does not
provide public signup, general messaging, introductions, Guardian approval,
identity or age checks, recovery, or a production account relationship. A QR
scan and key confirmation only bind the two devices for this local test. They do
not prove physical presence or real-world identity. The encrypted payload is a
fixed synthetic probe, not a user-authored message.

## Build prerequisites

Build the Rust MLS library for each platform. The script writes generated native
artifacts under ignored `.local/native/` paths; do not add those artifacts or
signing material to Git.

```sh
node scripts/build-native-mls.mjs apple-device
node scripts/build-native-mls.mjs android
```

The Apple device build requires macOS, Xcode, Rust targets, and the Apple
toolchain. The Android build requires Rust, an Android SDK/NDK, and the NDK
revision configured by the local build environment. The script reports a
missing toolchain if a prerequisite is unavailable.

### iOS

Generate the Xcode project:

```sh
xcodegen generate --spec native/apple/project.yml
```

Open `native/apple/SquadtimeAppleProof.xcodeproj` in Xcode, select the
`SquadtimePrototype` scheme and the intended iPhone, then configure a local
development signing team in Xcode if the device requires signing. Keep the
signing identity and provisioning data in the local Xcode environment; never
commit them. Build and install the app from Xcode. The generated app declares
camera permission and local-network access, including
`NSAllowsLocalNetworking`, for the explicitly approved local relay.

To prefill the editable relay field in a local build, pass
`SQUADTIME_PROTOTYPE_RELAY_ORIGIN=http://192.168.1.2:8789` to `xcodebuild`,
or set it in an ignored local signing/build configuration. The default is empty.
Keep the actual LAN address out of committed project settings. The user still
approves the displayed origin before the app connects.

### Android

Use an ARM64 device with Android 12 (API 31) or later. The current native-library build produces only `arm64-v8a`; an x86 emulator requires an additional native-library build.
Build with the relay host set to the Mac's private LAN IPv4 address, without a
scheme or port. For example, if the Mac's address is `192.168.1.2`:

```sh
cd native/android
./gradlew :prototype:assembleDebug -PprototypeRelayHost=192.168.1.2 --no-daemon
```

The address above is an example only. Substitute the current address of the Mac
running the relay. The generated network-security resource permits cleartext
HTTP only for that exact host. The same host also prefills the editable relay
field, using port `8789`; override the port with `-PprototypeRelayPort=8790`
if the relay uses another port. Without an explicit host, the default field is
empty. Saved addresses and unsaved edits take precedence over the build default.
Install the resulting debug APK using Android
Studio or `adb install prototype/build/outputs/apk/debug/prototype-debug.apk`.

## Start the disposable relay

From the repository root, start the memory-only relay on the Mac:

```sh
npm run prototype:relay
```

It listens on port `8789` on the Mac's network interfaces. From a device on the
same LAN, the example health URL is `http://192.168.1.2:8789/health`; replace the
address with the Mac's current private IPv4 address. A successful health reply
identifies `squadtime-local-prototype` version 1. The relay is unauthenticated,
untrusted, and disposable. It stores opaque public envelopes, including
encrypted MLS material, in memory for up to 30 minutes from the first invitation. It does not
persist sessions across relay restarts. Use only on a trusted private test LAN,
and stop it when testing is finished.

## Run one pairing

1. Start the relay and launch the prototype on both devices. Create a synthetic
   local profile on each.
2. On the first device, enter the relay origin, such as
   `http://192.168.1.2:8789`, and approve it. This explicitly authorizes requests
   to that origin on the device. On the second device, enter and approve the same
   origin. The Android build must also have been built with that exact host.
3. On the owner device, create a pairing code. On the joining device, scan the
   QR code. Review the nickname hint, relay origin, and complete device-key
   fingerprint, then confirm the intended test device. Keep both devices nearby
   for the QR exchange; scanning itself does not establish identity.
4. The joining device shows its request QR. Scan it on the owner device, compare
   the fingerprint, and explicitly confirm the test contact. The owner publishes
   its committed Welcome. Keep both apps in the foreground while they poll the
   relay (about every two seconds).
5. Once admission succeeds, the joining device displays **Encrypted test
   received** for the persisted fixed probe. It publishes a signed receipt; the
   owner displays completion after verifying that receipt against the scanned
   device key. This is a one-contact admission and encrypted-receive exercise,
   not general chat.
6. On the joining device, restart the app before acknowledging the test. Confirm
   the pending item is still in its encrypted inbox, then use **Acknowledge
   encrypted test**. The item should no longer be pending after acknowledgement.
   The owner and joining device retain their local keys and admission state
   across app restart.

The app stores the exact committed public outbox so retry can resume the same
exchange after a timeout or app restart. A relay restart loses its in-memory
records, so a retry may report a missing invitation or exchange item; the app
must retain its local keys and committed state rather than silently replacing
them. The relay session also expires after 30 minutes and invitations have a
short signed expiry. After expiry, use the app's explicit **Reset this
prototype** action on the device(s) and start a fresh synthetic pairing. Reset
deletes only this prototype's local profile, keys, contact metadata, and inbox;
there is no recovery path.

For manual code transfer, use the clearly labelled manual fallback and compare
the full fingerprint through a separate trusted channel. Pasting or forwarding
a code is not a proximity test. Never use real identities, public relay
endpoints, or production credentials for this prototype.

The build checks compile both prototype apps and their focused test targets. Runtime and optical QR validation must be recorded separately; compilation alone does not establish a successful two-device exchange.


## Try the foreground Bluetooth path

This is an optional experimental way to transfer the pairing codes. The same
local relay is still required for the MLS admission and encrypted test message;
Bluetooth does not make this prototype independent of the Mac or LAN.

1. Use synthetic profiles with the same approved relay. If both already have a
   completed test contact, explicitly reset the prototype before starting another
   one-contact test. Updating the app does not reset a contact.
2. On the inviting device, choose the Bluetooth advertising role. On the other
   device, choose the nearby-search role and select the intended test device.
   Bluetooth permission is requested only when using this feature. Denial or
   missing hardware support leaves QR available.
3. Keep both apps open. Compare the complete six-digit code on the two intended
   screens. Choose **Codes match** on both only when the codes match. A mismatch
   requires cancelling the attempt; do not keep accepting new codes blindly.
4. Review and explicitly confirm the received contact and relay on the joining
   device. Its committed request is then transferred back through the same
   authenticated Bluetooth channel. Review and confirm it on the inviting device.
5. Check the existing encrypted-test and signed-receipt completion states. Repeat
   with the Android and iOS roles reversed. Verify restart persistence separately.

Cancelling, switching apps, disconnecting or timing out ends the volatile Bluetooth
ceremony. Start a new attempt explicitly or use QR for the already committed native
exchange. The app must not silently replace native keys or reset an admission.
Discovery names, signal strength and matching codes do not prove legal identity,
age, Guardian approval or physical presence. See the exact wire contract and
review boundary in [bluetooth-prototype.md](bluetooth-prototype.md).
