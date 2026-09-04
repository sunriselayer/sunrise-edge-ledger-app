# Sunrise Edge Ledger App

Dedicated Ledger device application work for Sunrise Edge. This repository is
separate from the node so Ledger SDK, device targets, UI assets, Speculos, and
USB-facing development dependencies never enter protocol crates.

## Current status

This repository now contains the host-validated, allocation-free `no_std` core
and the separate `no_std`/`no_main` Ledger SDK device application. This is the
S4b device-app and emulation milestone, validated As-Is; it is not completion
of the wider S4 production signer work.

The implemented device path:

- builds with `ledger_device_sdk = "=1.37.0"` in a digest-pinned official
  builder image for Nano S+, Nano X, Stax, Flex, and Apex P;
- implements application CLA `E0` and INS `00` configuration, `02` verified
  public key, `04` bounded transaction signing, and `06` signing reset;
- derives only `m/44'/21333'/account'/0'/0'` with SLIP-0010 Ed25519, converts
  the SDK's raw `04 || X || Y` key exactly once to RFC 8032 compressed bytes,
  and compares that device-derived key to the signed sender before review;
- formats all 32 bounded clear-signing facts without app-side truncation or a
  blind-signing fallback, and signs only the session's captured path and exact
  buffered frame after approval; golden/pixel-level device UI fidelity remains
  deferred;
- has host-core conformance proving partial/pending signing-state wipes on
  command errors, policy or sender rejection, user rejection, signing failure,
  reset, and unexpected commands; Speculos additionally proves that a sender
  mismatch and an explicit reset do not poison a later valid signing session;
- leaves malformed APDU length (`6E03`), locked-device (`5515`), SDK fault
  (`E000`), in-review command rejection (`6901`), and BOLOS CLA `B0` behavior
  owned by the Ledger SDK/OS; the synchronous SDK review rejects an in-flight
  APDU before the application core can process or wipe it; and
- runs a fixed public development-seed Nano S+ Speculos/Ragger suite proving
  the exact six-byte configuration, exact SLIP-0010 public key, exact 64-byte
  signature for the 1,221-byte canonical-shape fixture after replacing its
  original sender with that derived key, pre-review sender-mismatch rejection
  for the byte-identical copied source fixture, explicit-reset recovery in the
  same emulator backend, and user rejection. Host conformance separately
  checks every one of the 32 rendered facts and adversarial APDU/policy bounds.

The normative protocol and APDU contract remains Sunrise Edge `SIGNING.md` at
source commit `1dd4d2d`. This repository changes no Sunrise Edge canonical
transaction/signature bytes or protocol activation.

Still deferred are S4c host USB/HID transport and CLI signer selection, plus
S4d golden/pixel UI snapshots, full device-level adversarial session reuse and
disconnect/device-reset evidence, physical-device HIL for every claimed model,
a pinned app/firmware compatibility matrix, two-clean-build reproducibility
evidence, Ledger release/submission, registered coin type, and replacement of
the CLI's development-only local signer. S4, production, and mainnet readiness
therefore remain incomplete. The current `21333` coin type is explicitly
provisional and unregistered.

## Layout

- `crates/sunrise-edge-ledger-core`: pure `no_std`, allocation-free APDU
  dispatch, independent canonical parsing, policy validation, and review model.
- `crates/sunrise-edge-ledger-app`: Ledger SDK derivation/signing, RFC 8032
  conversion, NBGL UI, status mapping, target entrypoint, and device assets.
- `tests/speculos`: fixed-seed Nano S+ device-binary tests.
- `assets/sunrise.svg`: original source artwork for generated device assets.
- `scripts/check.sh`: deterministic host formatting, clippy, unit/conformance,
  and diff checks.
- `scripts/build_device.sh`: digest-pinned Docker build for one or all targets.
- `scripts/check_speculos.sh`: digest-pinned Speculos/Ragger validation.

## Validate

```bash
./scripts/check.sh
```

```bash
./scripts/build_device.sh nanosplus
./scripts/build_device.sh all
./scripts/check_speculos.sh
```

The device and Speculos scripts require Docker. CI runs all three gates.

## License

Apache License 2.0. See [LICENSE](LICENSE).
