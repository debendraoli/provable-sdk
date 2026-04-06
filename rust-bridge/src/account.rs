use std::os::raw::c_char;

use rand::thread_rng;
use snarkvm_console::{
    account::{Address, PrivateKey, ViewKey},
    network::MainnetV0,
};

use crate::helpers::{ffi_catch, read_c_str};

type N = MainnetV0;

/// Generate a new random Aleo private key.
/// Returns the key as a string, e.g. "APrivateKey1zkp...".
/// On error returns `{"error":"..."}`.
#[no_mangle]
pub extern "C" fn aleo_private_key_new() -> *mut c_char {
    ffi_catch!("panic during key generation",
        let rng = &mut thread_rng();
        let sk = PrivateKey::<N>::new(rng).map_err(|e| e.to_string())?;
        Ok(sk.to_string())
    )
}

/// Derive the view key from a private key string.
#[no_mangle]
pub extern "C" fn aleo_private_key_to_view_key(sk_ptr: *const c_char) -> *mut c_char {
    ffi_catch!("panic during view key derivation",
        let sk_str = unsafe { read_c_str(sk_ptr) }.ok_or("null private key pointer")?;
        let sk: PrivateKey<N> = sk_str.parse().map_err(|e: snarkvm_console::prelude::Error| e.to_string())?;
        let vk = ViewKey::try_from(&sk).map_err(|e| e.to_string())?;
        Ok(vk.to_string())
    )
}

/// Derive the address from a private key string.
#[no_mangle]
pub extern "C" fn aleo_private_key_to_address(sk_ptr: *const c_char) -> *mut c_char {
    ffi_catch!("panic during address derivation",
        let sk_str = unsafe { read_c_str(sk_ptr) }.ok_or("null private key pointer")?;
        let sk: PrivateKey<N> = sk_str.parse().map_err(|e: snarkvm_console::prelude::Error| e.to_string())?;
        let addr = Address::try_from(&sk).map_err(|e| e.to_string())?;
        Ok(addr.to_string())
    )
}

/// Derive the address from a view key string.
#[no_mangle]
pub extern "C" fn aleo_view_key_to_address(vk_ptr: *const c_char) -> *mut c_char {
    ffi_catch!("panic during address derivation from view key",
        let vk_str = unsafe { read_c_str(vk_ptr) }.ok_or("null view key pointer")?;
        let vk: ViewKey<N> = vk_str.parse().map_err(|e: snarkvm_console::prelude::Error| e.to_string())?;
        let addr = Address::try_from(&vk).map_err(|e| e.to_string())?;
        Ok(addr.to_string())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_keygen_roundtrip() {
        let sk_ptr = aleo_private_key_new();
        assert!(!sk_ptr.is_null());
        let sk_str = unsafe { std::ffi::CStr::from_ptr(sk_ptr).to_str().unwrap().to_owned() };
        assert!(sk_str.starts_with("APrivateKey1"));
        crate::aleo_free_string(sk_ptr);

        let csk = CString::new(sk_str.clone()).unwrap();
        let vk_ptr = aleo_private_key_to_view_key(csk.as_ptr());
        assert!(!vk_ptr.is_null());
        let vk_str = unsafe { std::ffi::CStr::from_ptr(vk_ptr).to_str().unwrap().to_owned() };
        assert!(vk_str.starts_with("AViewKey1"));
        crate::aleo_free_string(vk_ptr);

        let addr_ptr = aleo_private_key_to_address(csk.as_ptr());
        assert!(!addr_ptr.is_null());
        let addr_str = unsafe { std::ffi::CStr::from_ptr(addr_ptr).to_str().unwrap().to_owned() };
        assert!(addr_str.starts_with("aleo1"));
        crate::aleo_free_string(addr_ptr);

        let cvk = CString::new(vk_str).unwrap();
        let addr2_ptr = aleo_view_key_to_address(cvk.as_ptr());
        assert!(!addr2_ptr.is_null());
        let addr2_str = unsafe { std::ffi::CStr::from_ptr(addr2_ptr).to_str().unwrap().to_owned() };
        assert_eq!(addr_str, addr2_str);
        crate::aleo_free_string(addr2_ptr);
    }

    #[test]
    fn test_null_private_key() {
        let ptr = aleo_private_key_to_view_key(std::ptr::null());
        assert!(!ptr.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(ptr).to_str().unwrap() };
        assert!(s.contains("error"));
        crate::aleo_free_string(ptr);
    }
}
