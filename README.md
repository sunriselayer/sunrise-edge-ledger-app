# Sunrise Edge Ledger App

Dedicated Ledger device application work for Sunrise Edge. This repository is
separate from the node so Ledger SDK, device targets, UI assets, Speculos, and
USB-facing development dependencies never enter protocol crates.

## Current status

The current slice is a host-validated, allocation-free `no_std` core only. It
implements the application-owned APDU state machine, strict independent
decoders for Hardware Signing Profile v1, the exact local-devnet transfer
allowlist, sender/public-key pre-review validation, and a signed-fields-only
review model.

It does **not** yet contain a Ledger SDK binary, SLIP-0010 key derivation,
Ed25519 signing, on-device UI, `cargo-ledger` build evidence, Speculos/Ragger
evidence, USB/HID integration, or physical-device evidence. S4b and S4 are not
complete, and this repository is not production or mainnet ready.

The normative protocol and APDU contract is the Sunrise Edge `SIGNING.md` at
source commit `1dd4d2d`. The conformance fixture is copied from
`crates/signing-view/tests/fixtures.rs` at that commit; runtime code has no
dependency on the Sunrise Edge workspace.

## Layout

- `crates/sunrise-edge-ledger-core`: pure `no_std`, allocation-free APDU,
  canonical parsing, policy, and review logic.
- `scripts/check.sh`: complete validation for the currently implemented slice.

## Validate

```bash
./scripts/check.sh
```

## Device integration inputs

The next slice will adapt this core to Ledger's official Rust boilerplate,
which was inspected at commit
`66cbb087aa6a1c0fd20853119f7814a27cf8c43a`. The current researched SDK input
is `ledger_device_sdk` 1.37.0. Neither is an active dependency yet; the device
slice must pin and build them in Ledger's builder image and re-check platform
status/APDU behavior before claiming evidence.

Sunrise Edge uses the development-only provisional path
`m/44'/21333'/account'/0'/0'`. `21333` is not a claimed SLIP-0044 registration.
Any production/mainnet path requires a separate registered allocation and
migration decision.

## License

Apache License 2.0. See [LICENSE](LICENSE).
