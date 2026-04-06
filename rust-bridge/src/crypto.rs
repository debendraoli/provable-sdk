use std::os::raw::c_char;

use rand::thread_rng;
use snarkvm_console::{
    account::{Address, PrivateKey, Signature},
    network::MainnetV0,
};

use crate::helpers::{ffi_catch, read_c_str};

type N = MainnetV0;

/// Sign a message with a private key.
/// `msg_ptr` points to the raw bytes, `msg_len` is the byte count.
/// Returns the signature as a string.
#[unsafe(no_mangle)]
pub extern "C" fn aleo_sign_message(
    sk_ptr: *const c_char,
    msg_ptr: *const u8,
    msg_len: usize,
) -> *mut c_char {
    ffi_catch!("panic during message signing",
        let sk_str = unsafe { read_c_str(sk_ptr) }.ok_or("null private key pointer")?;
        let msg = if msg_ptr.is_null() || msg_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) }
        };
        let sk: PrivateKey<N> = sk_str.parse().map_err(|e: snarkvm_console::prelude::Error| e.to_string())?;
        let rng = &mut thread_rng();
        let sig = sk.sign_bytes(msg, rng).map_err(|e| e.to_string())?;
        Ok(sig.to_string())
    )
}

/// Verify a signature against an address and message.
/// Returns 1 for valid, 0 for invalid, -1 for error.
#[unsafe(no_mangle)]
pub extern "C" fn aleo_verify_signature(
    addr_ptr: *const c_char,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const c_char,
) -> i32 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let addr_str = unsafe { read_c_str(addr_ptr) }.ok_or("null address pointer")?;
        let sig_str = unsafe { read_c_str(sig_ptr) }.ok_or("null signature pointer")?;
        let msg = if msg_ptr.is_null() || msg_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) }
        };
        let addr: Address<N> = addr_str.parse().map_err(|e: snarkvm_console::prelude::Error| e.to_string())?;
        let sig: Signature<N> = sig_str.parse().map_err(|e: snarkvm_console::prelude::Error| e.to_string())?;
        Ok::<bool, String>(sig.verify_bytes(&addr, msg))
    }));
    match result {
        Ok(Ok(true)) => 1,
        Ok(Ok(false)) => 0,
        Ok(Err(_)) | Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::aleo_private_key_new;
    use std::ffi::CString;

    #[test]
    fn test_sign_and_verify() {
        let sk_ptr = aleo_private_key_new();
        let sk_str = unsafe { std::ffi::CStr::from_ptr(sk_ptr).to_str().unwrap().to_owned() };
        crate::aleo_free_string(sk_ptr);

        let csk = CString::new(sk_str.clone()).unwrap();

        // Derive address
        let addr_ptr = crate::account::aleo_private_key_to_address(csk.as_ptr());
        let addr_str = unsafe { std::ffi::CStr::from_ptr(addr_ptr).to_str().unwrap().to_owned() };
        crate::aleo_free_string(addr_ptr);

        let msg = b"test message";
        let sig_ptr = aleo_sign_message(csk.as_ptr(), msg.as_ptr(), msg.len());
        assert!(!sig_ptr.is_null());
        let sig_str = unsafe { std::ffi::CStr::from_ptr(sig_ptr).to_str().unwrap().to_owned() };
        assert!(!sig_str.contains("error"));
        crate::aleo_free_string(sig_ptr);

        let caddr = CString::new(addr_str).unwrap();
        let csig = CString::new(sig_str).unwrap();
        let result = aleo_verify_signature(caddr.as_ptr(), msg.as_ptr(), msg.len(), csig.as_ptr());
        assert_eq!(result, 1);
    }

    #[test]
    fn test_verify_wrong_message() {
        let sk_ptr = aleo_private_key_new();
        let sk_str = unsafe { std::ffi::CStr::from_ptr(sk_ptr).to_str().unwrap().to_owned() };
        crate::aleo_free_string(sk_ptr);

        let csk = CString::new(sk_str).unwrap();
        let addr_ptr = crate::account::aleo_private_key_to_address(csk.as_ptr());
        let addr_str = unsafe { std::ffi::CStr::from_ptr(addr_ptr).to_str().unwrap().to_owned() };
        crate::aleo_free_string(addr_ptr);

        let msg = b"correct";
        let sig_ptr = aleo_sign_message(csk.as_ptr(), msg.as_ptr(), msg.len());
        let sig_str = unsafe { std::ffi::CStr::from_ptr(sig_ptr).to_str().unwrap().to_owned() };
        crate::aleo_free_string(sig_ptr);

        let caddr = CString::new(addr_str).unwrap();
        let csig = CString::new(sig_str).unwrap();
        let wrong = b"wrong";
        let result = aleo_verify_signature(caddr.as_ptr(), wrong.as_ptr(), wrong.len(), csig.as_ptr());
        assert_eq!(result, 0);
    }

    #[test]
    fn test_sign_empty_message() {
        let sk_ptr = aleo_private_key_new();
        let sk_str = unsafe { std::ffi::CStr::from_ptr(sk_ptr).to_str().unwrap().to_owned() };
        crate::aleo_free_string(sk_ptr);

        let csk = CString::new(sk_str).unwrap();
        let sig_ptr = aleo_sign_message(csk.as_ptr(), std::ptr::null(), 0);
        let sig_str = unsafe { std::ffi::CStr::from_ptr(sig_ptr).to_str().unwrap().to_owned() };
        assert!(!sig_str.contains("error"), "sign empty failed: {}", sig_str);
        crate::aleo_free_string(sig_ptr);
    }
}
