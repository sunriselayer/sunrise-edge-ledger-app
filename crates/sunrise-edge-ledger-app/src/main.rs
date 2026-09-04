//! Dedicated Ledger device application binary for Sunrise Edge.

#![no_std]
#![cfg_attr(
    any(
        target_os = "nanosplus",
        target_os = "nanox",
        target_os = "stax",
        target_os = "flex",
        target_os = "apex_p"
    ),
    no_main
)]
#![deny(unsafe_code)]

#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
extern crate alloc;

#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);

#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
ledger_device_sdk::define_comm!(COMM);

#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use ledger_device_sdk::io::init_comm;
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use ledger_device_sdk::nbgl::{NbglReviewStatus, StatusType};
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use sunrise_edge_ledger_app::app_ui::{
    ui_display_public_key, ui_display_transaction, ui_menu_main,
};
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use sunrise_edge_ledger_app::derivation::{DeviceDeriver, DeviceSigner};
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use sunrise_edge_ledger_app::status::AppSW;
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use sunrise_edge_ledger_core::apdu::{
    dispatch, ApduCommand, DispatchOutcome, ImmediateResponse, SigningSession, StatusWord,
};
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use sunrise_edge_ledger_core::policy::DEVNET_ASSET_TRANSFER_POLICY;

/// Strongly typed APDU header representation decoded by `ledger_device_sdk`.
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
#[derive(Clone, Copy, Debug)]
pub struct DeviceApduHeader {
    /// APDU class byte.
    pub cla: u8,
    /// APDU instruction byte.
    pub ins: u8,
    /// Parameter 1 byte.
    pub p1: u8,
    /// Parameter 2 byte.
    pub p2: u8,
}

#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
impl TryFrom<ledger_device_sdk::io::ApduHeader> for DeviceApduHeader {
    type Error = AppSW;

    fn try_from(h: ledger_device_sdk::io::ApduHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            cla: h.cla,
            ins: h.ins,
            p1: h.p1,
            p2: h.p2,
        })
    }
}

#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
#[allow(unsafe_code)]
#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    normal_main();
}

/// Normal main event loop on device targets.
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
pub fn normal_main() {
    let comm = init_comm(&COMM);

    let mut session: SigningSession = SigningSession::new();
    let mut deriver: DeviceDeriver = DeviceDeriver;
    let mut home = ui_menu_main(comm);
    home.show_and_return();

    loop {
        let command = comm.next_command();
        let header: DeviceApduHeader = match command.decode::<DeviceApduHeader>() {
            Ok(h) => h,
            Err(reply) => {
                session.reset();
                let _ = comm.send(&[], reply);
                continue;
            }
        };

        let outcome: DispatchOutcome = {
            let data: &[u8] = command.get_data();
            let apdu_cmd: ApduCommand<'_> = ApduCommand {
                cla: header.cla,
                ins: header.ins,
                p1: header.p1,
                p2: header.p2,
                data,
            };

            dispatch(
                &mut session,
                apdu_cmd,
                &mut deriver,
                &DEVNET_ASSET_TRANSFER_POLICY,
            )
        };
        drop(command);

        // `Comm::send` can report only response-buffer overflow. The payloads
        // below are bounded to 64 bytes; resetting on an error is defensive if
        // that invariant ever changes, not a claim of disconnect detection.
        let status_popup: Option<(StatusType, bool)> = match outcome {
            DispatchOutcome::Reply(reply) => {
                if reply.status == StatusWord::Success {
                    match reply.response {
                        ImmediateResponse::Empty => {
                            if comm.send(&[], AppSW::Ok).is_err() {
                                session.reset();
                            }
                        }
                        ImmediateResponse::Configuration(cfg_bytes) => {
                            if comm.send(&cfg_bytes, AppSW::Ok).is_err() {
                                session.reset();
                            }
                        }
                    }
                } else if comm.send(&[], AppSW::from(reply.status)).is_err() {
                    session.reset();
                }
                None
            }
            DispatchOutcome::ReviewPublicKey {
                path: _,
                public_key,
            } => match ui_display_public_key(comm, &public_key) {
                Ok(true) => {
                    if comm.send(&public_key, AppSW::Ok).is_err() {
                        session.reset();
                    }
                    Some((StatusType::Address, true))
                }
                Ok(false) => {
                    session.reset();
                    let _ = comm.send(&[], AppSW::Deny);
                    Some((StatusType::Address, false))
                }
                Err(status) => {
                    session.reset();
                    let _ = comm.send(&[], status);
                    Some((StatusType::Address, false))
                }
            },
            DispatchOutcome::ReviewTransaction(review) => {
                match ui_display_transaction(comm, &review) {
                    Ok(true) => {
                        let mut signer: DeviceSigner = DeviceSigner;
                        match session.approve_and_sign(&mut signer) {
                            Ok(signature) => {
                                if comm.send(&signature, AppSW::Ok).is_err() {
                                    session.reset();
                                }
                                Some((StatusType::Transaction, true))
                            }
                            Err(status) => {
                                let _ = comm.send(&[], AppSW::from(status));
                                Some((StatusType::Transaction, false))
                            }
                        }
                    }
                    Ok(false) => {
                        session.reject_review();
                        let _ = comm.send(&[], AppSW::Deny);
                        Some((StatusType::Transaction, false))
                    }
                    Err(status) => {
                        session.reject_review();
                        let _ = comm.send(&[], status);
                        Some((StatusType::Transaction, false))
                    }
                }
            }
        };

        if let Some((status_type, success)) = status_popup {
            NbglReviewStatus::new()
                .status_type(status_type)
                .show(comm, success);
            home.show_and_return();
        }
    }
}

#[cfg(not(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
)))]
extern crate std;

#[cfg(not(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
)))]
fn main() {}
