use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Convert a Rust String to a heap-allocated C string.
/// The caller (Go side) must free this with `aleo_free_string`.
pub fn to_c_string(s: String) -> *mut c_char {
    CString::new(s)
        .unwrap_or_else(|_| CString::default())
        .into_raw()
}

/// Return an error JSON string as a C string.
pub fn error_result(msg: &str) -> *mut c_char {
    let json = serde_json::json!({"error": msg});
    to_c_string(json.to_string())
}

/// Read a C string into a Rust &str. Returns None on null / invalid UTF-8.
///
/// # Safety
/// `ptr` must be a valid, null-terminated C string or null.
pub unsafe fn read_c_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// Trait for parsing snarkVM types from string with uniform error mapping.
pub trait ParseAleo: Sized {
    fn parse_aleo(s: &str) -> Result<Self, String>;
}

impl<T> ParseAleo for T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    fn parse_aleo(s: &str) -> Result<Self, String> {
        s.parse().map_err(|e: T::Err| e.to_string())
    }
}

/// Wraps an FFI function body with panic::catch_unwind and the standard
/// Ok/Err/panic → C string mapping.
///
/// Usage:
/// ```ignore
/// ffi_catch!("context message",
///     let x = do_something()?;
///     Ok(x.to_string())
/// )
/// ```
macro_rules! ffi_catch {
    ($panic_msg:expr, $($body:tt)*) => {{
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<String, String> {
                $($body)*
            }));
        match result {
            Ok(Ok(s)) => $crate::helpers::to_c_string(s),
            Ok(Err(e)) => $crate::helpers::error_result(&e),
            Err(_) => $crate::helpers::error_result($panic_msg),
        }
    }};
}

pub(crate) use ffi_catch;

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    /// Call an FFI function that returns a C string, assert non-null, and return owned String.
    pub fn call_ffi(f: impl FnOnce() -> *mut c_char) -> String {
        let ptr = f();
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr).to_str().unwrap().to_owned() };
        crate::aleo_free_string(ptr);
        s
    }

    /// Create a CString from a &str (convenience helper).
    pub fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }
}
