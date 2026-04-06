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
    let escaped = msg.replace('\\', "\\\\").replace('"', "\\\"");
    to_c_string(format!("{{\"error\":\"{}\"}}", escaped))
}

/// Read a C string into a Rust &str. Returns None on null / invalid UTF-8.
///
/// # Safety
/// `ptr` must be a valid, null-terminated C string or null.
pub unsafe fn read_c_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok()
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
