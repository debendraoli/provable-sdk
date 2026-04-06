use std::os::raw::c_char;

use rand::thread_rng;
use snarkvm_console::{
    account::{Address, ComputeKey, GraphKey, PrivateKey, ViewKey},
    network::MainnetV0,
};

use crate::helpers::{ParseAleo, ffi_catch, read_c_str};

type N = MainnetV0;

/// Generate a new random Aleo private key.
/// Returns the key as a string, e.g. "APrivateKey1zkp...".
/// On error returns `{"error":"..."}`.
#[unsafe(no_mangle)]
pub extern "C" fn aleo_private_key_new() -> *mut c_char {
    ffi_catch!("panic during key generation",
        let rng = &mut thread_rng();
        let sk = PrivateKey::<N>::new(rng).map_err(|e| e.to_string())?;
        Ok(sk.to_string())
    )
}

/// Derive all keys from a private key in a single FFI call.
/// Returns a JSON object: {"view_key":"...","address":"...","compute_key":"...","graph_key":"..."}
#[unsafe(no_mangle)]
pub extern "C" fn aleo_derive_all_keys(sk_ptr: *const c_char) -> *mut c_char {
    ffi_catch!("panic during key derivation",
        let sk_str = unsafe { read_c_str(sk_ptr) }.ok_or("null private key pointer")?;
        let sk = PrivateKey::<N>::parse_aleo(sk_str)?;
        let vk = ViewKey::try_from(&sk).map_err(|e| e.to_string())?;
        let addr = Address::try_from(&sk).map_err(|e| e.to_string())?;
        let ck = ComputeKey::try_from(&sk).map_err(|e| e.to_string())?;
        let gk = GraphKey::try_from(&vk).map_err(|e| e.to_string())?;
        let result = serde_json::json!({
            "view_key": vk.to_string(),
            "address": addr.to_string(),
            "compute_key": ck,
            "graph_key": gk.to_string(),
        });
        Ok(result.to_string())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::test_helpers::{c, call_ffi};

    #[test]
    fn test_keygen_and_derive_all() {
        let sk_str = call_ffi(|| aleo_private_key_new());
        assert!(sk_str.starts_with("APrivateKey1"));

        let csk = c(&sk_str);
        let keys_json = call_ffi(|| aleo_derive_all_keys(csk.as_ptr()));
        let keys: serde_json::Value = serde_json::from_str(&keys_json).unwrap();
        assert!(keys["view_key"].as_str().unwrap().starts_with("AViewKey1"));
        assert!(keys["address"].as_str().unwrap().starts_with("aleo1"));
        assert!(keys["graph_key"].as_str().unwrap().len() > 0);
    }

    #[test]
    fn test_null_private_key() {
        let s = call_ffi(|| aleo_derive_all_keys(std::ptr::null()));
        assert!(s.contains("error"));
    }
}
