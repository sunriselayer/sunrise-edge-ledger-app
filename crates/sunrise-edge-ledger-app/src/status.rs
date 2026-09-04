//! Application status words matching Hardware Signing Profile v1.

use sunrise_edge_ledger_core::apdu::StatusWord;

/// Exact application status words returned on the APDU wire.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppSW {
    /// 0x9000: Success
    Ok = 0x9000,
    /// 0x6985: User rejected
    Deny = 0x6985,
    /// 0x6986: Invalid signing state
    InvalidState = 0x6986,
    /// 0x6A80: Invalid or unrecognized data
    InvalidData = 0x6A80,
    /// 0x6A84: Profile bound exceeded
    ProfileBoundExceeded = 0x6A84,
    /// 0x6A86: Invalid P1 or P2
    WrongP1P2 = 0x6A86,
    /// 0x6D00: Unsupported INS
    InsNotSupported = 0x6D00,
    /// 0x6E00: Unsupported CLA
    ClaNotSupported = 0x6E00,
    /// 0x6F00: Internal failure after state wipe
    InternalFailure = 0x6F00,
}

impl From<StatusWord> for AppSW {
    fn from(sw: StatusWord) -> Self {
        match sw {
            StatusWord::Success => Self::Ok,
            StatusWord::UserRejected => Self::Deny,
            StatusWord::InvalidState => Self::InvalidState,
            StatusWord::InvalidData => Self::InvalidData,
            StatusWord::ProfileBoundExceeded => Self::ProfileBoundExceeded,
            StatusWord::InvalidP1P2 => Self::WrongP1P2,
            StatusWord::UnsupportedIns => Self::InsNotSupported,
            StatusWord::UnsupportedCla => Self::ClaNotSupported,
            StatusWord::InternalFailure => Self::InternalFailure,
        }
    }
}

impl From<AppSW> for u16 {
    fn from(sw: AppSW) -> Self {
        sw as u16
    }
}

#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
impl From<AppSW> for ledger_device_sdk::io::Reply {
    fn from(sw: AppSW) -> Self {
        ledger_device_sdk::io::Reply(sw as u16)
    }
}
