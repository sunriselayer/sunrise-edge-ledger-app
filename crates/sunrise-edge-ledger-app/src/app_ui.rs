//! On-device NBGL user interface for home, address review, and transaction review.

#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use crate::review_ui::{format_review_facts, BoundedFactStr, ReviewFact};
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use crate::status::AppSW;
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use arrayvec::ArrayVec;
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use ledger_device_sdk::include_gif;
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use ledger_device_sdk::io::Comm;
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use ledger_device_sdk::nbgl::{
    Field, NbglAddressReview, NbglGlyph, NbglHomeAndSettings, NbglReview,
};
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
use sunrise_edge_ledger_core::review::ClearSigningReview;

/// Device-specific Sunrise glyph for Apex P.
#[cfg(target_os = "apex_p")]
pub const SUNRISE_GLYPH: NbglGlyph =
    NbglGlyph::from_include(include_gif!("glyphs/sunrise_48x48.png", NBGL));
/// Device-specific Sunrise glyph for Stax and Flex.
#[cfg(any(target_os = "stax", target_os = "flex"))]
pub const SUNRISE_GLYPH: NbglGlyph =
    NbglGlyph::from_include(include_gif!("glyphs/sunrise_64x64.gif", NBGL));
/// Device-specific Sunrise glyph for Nano S+ and Nano X.
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
pub const SUNRISE_GLYPH: NbglGlyph =
    NbglGlyph::from_include(include_gif!("icons/sunrise_14x14.gif", NBGL));

/// Displays the main menu / home screen.
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
pub fn ui_menu_main(_comm: &mut Comm) -> NbglHomeAndSettings {
    NbglHomeAndSettings::new().glyph(&SUNRISE_GLYPH).infos(
        "Sunrise Edge",
        env!("CARGO_PKG_VERSION"),
        "Sunrise Layer",
    )
}

/// Displays the on-device address confirmation screen for a derived public key.
///
/// Returns `Ok(true)` if the user approves, or `Ok(false)` if rejected.
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
pub fn ui_display_public_key(comm: &mut Comm, public_key: &[u8; 32]) -> Result<bool, AppSW> {
    let hex_addr: BoundedFactStr =
        BoundedFactStr::try_from_hex(public_key).map_err(|_| AppSW::InternalFailure)?;
    let address: &str = hex_addr.as_str().map_err(|_| AppSW::InternalFailure)?;
    let review = NbglAddressReview::new()
        .glyph(&SUNRISE_GLYPH)
        .review_title("Verify Sunrise address");
    Ok(review.show(comm, address))
}

/// Displays all and only 32 signed facts for clear-signing review on device.
///
/// Returns `Ok(true)` if the user approves, or `Ok(false)` if rejected.
#[cfg(any(
    target_os = "nanosplus",
    target_os = "nanox",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
))]
pub fn ui_display_transaction(comm: &mut Comm, review: &ClearSigningReview) -> Result<bool, AppSW> {
    let facts: [ReviewFact; 32] =
        format_review_facts(review).map_err(|_| AppSW::InternalFailure)?;
    let mut fields: ArrayVec<Field<'_>, 32> = ArrayVec::new();
    for fact in &facts {
        let value: &str = fact.value.as_str().map_err(|_| AppSW::InternalFailure)?;
        fields
            .try_push(Field {
                name: fact.name,
                value,
            })
            .map_err(|_| AppSW::InternalFailure)?;
    }

    let nbgl_review: NbglReview<'_> = NbglReview::new()
        .titles(
            "Review transaction\nSunrise Edge",
            "",
            "Sign transaction\nSunrise Edge",
        )
        .glyph(&SUNRISE_GLYPH);

    Ok(nbgl_review.show(comm, fields.as_slice()))
}
