# Third-party notices

## Ledger Rust application boilerplate

The device package layout, Ledger metadata shape, entrypoint/event-loop
composition, and NBGL integration patterns were derived from
[`LedgerHQ/app-boilerplate-rust`](https://github.com/LedgerHQ/app-boilerplate-rust)
at commit `66cbb087aa6a1c0fd20853119f7814a27cf8c43a`.

Copyright 2023 Ledger SAS. Licensed under the Apache License, Version 2.0.
The upstream boilerplate's crab artwork is not included; Sunrise Edge uses
original project artwork from `assets/sunrise.svg`.

## Ledger device Rust SDK

The device crate depends on `ledger_device_sdk` version `1.37.0`, published by
Ledger SAS under the Apache License, Version 2.0. Its transitive license data
is preserved by `Cargo.lock` and the upstream package metadata.
