//! Conversion helpers between Win32 primitives and `uniwifi` types.

use std::fmt;

use windows::Win32::Foundation::WIN32_ERROR;
use windows::core::GUID;

use crate::error::{BoxedOsError, Error};
use crate::types::AdapterId;

/// Wrap a non-zero Win32 error code in our `Error::Os(_)` variant.
///
/// The wrapper carries both the numeric code and (where available) the
/// platform's textual description so users see something like:
/// `internal os error: WlanOpenHandle: 0x00000005 (Access denied)`.
#[derive(Debug)]
pub struct Win32Error {
    /// Name of the function that returned the error (e.g. `"WlanOpenHandle"`).
    pub function: &'static str,
    /// Raw `WIN32_ERROR` code.
    pub code: u32,
}

impl fmt::Display for Win32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: 0x{:08x}", self.function, self.code)
    }
}

impl std::error::Error for Win32Error {}

/// Convert a `WIN32_ERROR` returned by a `Wlan*` function into our `Error::Os`.
///
/// Returns `Ok(())` if the code is `ERROR_SUCCESS` (0).
///
/// # Errors
///
/// Returns `Error::Os(_)` for any non-zero `code`.
pub fn check_win32(function: &'static str, code: WIN32_ERROR) -> Result<(), Error> {
    if code.0 == 0 {
        Ok(())
    } else {
        let boxed: BoxedOsError = Box::new(Win32Error {
            function,
            code: code.0,
        });
        Err(Error::Os(boxed))
    }
}

/// Render a Win32 `GUID` as the canonical bracketed string Windows uses
/// for interface identifiers, e.g.
/// `"{12345678-1234-1234-1234-123456789ABC}"`.
#[must_use]
pub fn guid_to_adapter_id(g: &GUID) -> AdapterId {
    AdapterId::new(format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7],
    ))
}

/// Parse a bracketed GUID string back into a `windows::core::GUID`.
///
/// # Errors
///
/// Returns `Error::AdapterNotFound(_)` if `id` is not a syntactically valid
/// bracketed GUID.
pub fn adapter_id_to_guid(id: &AdapterId) -> Result<GUID, Error> {
    let s = id.as_str();
    let inner = s
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| Error::AdapterNotFound(id.to_string()))?;
    GUID::try_from(inner).map_err(|_| Error::AdapterNotFound(id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_yields_ok() {
        assert!(check_win32("test", WIN32_ERROR(0)).is_ok());
    }

    #[test]
    fn nonzero_yields_os_error() {
        let err = check_win32("WlanOpenHandle", WIN32_ERROR(5)).expect_err("expected Os error");
        let s = format!("{err}");
        assert!(s.contains("WlanOpenHandle"), "got: {s}");
        assert!(s.contains("0x00000005"), "got: {s}");
    }

    #[test]
    fn guid_round_trip() {
        let g = windows::core::GUID::from_values(
            0x1234_5678,
            0x1234,
            0x1234,
            [0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
        );
        let id = guid_to_adapter_id(&g);
        assert_eq!(id.as_str(), "{12345678-1234-1234-1234-123456789ABC}");

        let g2 = adapter_id_to_guid(&id).expect("round-trip");
        assert_eq!(g, g2);
    }

    #[test]
    fn malformed_adapter_id_yields_adapter_not_found() {
        let id = crate::types::AdapterId::new("not-a-guid");
        assert!(matches!(
            adapter_id_to_guid(&id),
            Err(Error::AdapterNotFound(_))
        ));
    }
}
