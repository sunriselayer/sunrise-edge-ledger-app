# AGENTS.md

This file applies to the entire repository.

## Mission

Implement the dedicated Sunrise Edge Ledger application without weakening the
canonical bytes, clear-signing policy, or fail-closed boundaries fixed by the
Sunrise Edge `SIGNING.md`.

## Non-negotiable rules

- Never reuse a Solana or Ethereum app for Sunrise signing.
- Keep protocol parsing independent of the node implementation; compatibility
  is proven with copied stable fixtures and differential evidence.
- No blind-signing, raw-argument, unknown-module, or best-effort display path.
- Every displayed value must come from the exact signed frame.
- Validate the derived RFC 8032 Ed25519 public key against the signed sender
  before any transaction review page.
- Keep all buffers and collections deterministically bounded. Reject unknown
  tags, versions, fields, flags, status words, and states.
- Wipe signing state after every failure, rejection, reset, completed signature,
  disconnect, timeout, or app restart.
- Do not claim S4b, S4, production, or mainnet readiness without the exact
  Speculos, physical-device, reproducible-build, compatibility, and release
  evidence required by the source roadmap.

## Rust

- Protocol-facing core code is `#![no_std]` and `#![forbid(unsafe_code)]`.
- New `unsafe` requires explicit user approval and a documented justification.
- Prefer explicit types at protocol/state boundaries; do not make the compiler
  infer large or ambiguous types.
- Do not use `unwrap`, `expect`, `panic!`, `todo!`, or `unimplemented!` in
  library paths. Focused tests may use assertions.
- Use typed errors and checked arithmetic for attacker-controlled lengths and
  counters.

## Workflow

Before handoff, run:

```bash
./scripts/check.sh
```

Update `README.md` when implementation evidence changes. Commit `Cargo.lock`.
Use normal merge commits; never squash or rebase reviewed protocol history.
