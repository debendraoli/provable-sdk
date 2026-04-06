mod helpers;
mod account;
mod authorize;
mod crypto;
mod program;

// Re-export all FFI functions so they appear as symbols in the cdylib.
pub use account::*;
pub use authorize::*;
pub use crypto::*;
pub use program::*;

use std::ffi::CString;
use std::os::raw::c_char;

/// Free a C string that was allocated by this library.
#[no_mangle]
pub extern "C" fn aleo_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}
