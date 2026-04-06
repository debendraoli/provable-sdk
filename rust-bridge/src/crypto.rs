use std::os::raw::c_char;

use rand::thread_rng;
use snarkvm_console::{
    account::{Address, PrivateKey, Signature},
    network::MainnetV0,
};

use crate::helpers::{ffi_catch, read_c_str, ParseAleo};

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
        let sk = PrivateKey::<N>::parse_aleo(sk_str)?;
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
        let addr = Address::<N>::parse_aleo(addr_str)?;
        let sig = Signature::<N>::parse_aleo(sig_str)?;
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
    use crate::helpers::test_helpers::{c, call_ffi};

    #[test]
    fn test_sign_and_verify() {
        let sk_str = call_ffi(|| aleo_private_key_new());
        let csk = c(&sk_str);

        let addr_str = call_ffi(|| crate::account::aleo_private_key_to_address(csk.as_ptr()));
        let caddr = c(&addr_str);

        let msg = b"test message";
        let sig_str = call_ffi(|| aleo_sign_message(csk.as_ptr(), msg.as_ptr(), msg.len()));
        assert!(!sig_str.contains("error"));

        let csig = c(&sig_str);
        let result = aleo_verify_signature(caddr.as_ptr(), msg.as_ptr(), msg.len(), csig.as_ptr());
        assert_eq!(result, 1);
    }

    #[test]
    fn test_verify_wrong_message() {
        let sk_str = call_ffi(|| aleo_private_key_new());
        let csk = c(&sk_str);

        let addr_str = call_ffi(|| crate::account::aleo_private_key_to_address(csk.as_ptr()));
        let caddr = c(&addr_str);

        let msg = b"correct";
        let sig_str = call_ffi(|| aleo_sign_message(csk.as_ptr(), msg.as_ptr(), msg.len()));
        let csig = c(&sig_str);

        let wrong = b"wrong";
        let result = aleo_verify_signature(caddr.as_ptr(), wrong.as_ptr(), wrong.len(), csig.as_ptr());
        assert_eq!(result, 0);
    }

    #[test]
    fn test_sign_empty_message() {
        let sk_str = call_ffi(|| aleo_private_key_new());
        let csk = c(&sk_str);

        let sig_str = call_ffi(|| aleo_sign_message(csk.as_ptr(), std::ptr::null(), 0));
        assert!(!sig_str.contains("error"), "sign empty failed: {}", sig_str);
    }
}
