use std::os::raw::c_char;

use snarkvm_console::network::MainnetV0;
use snarkvm_console::prelude::*;
use snarkvm_console::program::Literal;
use snarkvm_console::types::Field;

use crate::helpers::{ffi_catch, read_c_str};

type N = MainnetV0;

/// Parse a Literal from its string representation and convert to bits LE.
fn literal_to_bits(input: &str) -> Result<Vec<bool>, String> {
    let lit: Literal<N> = input
        .parse()
        .map_err(|e: snarkvm_console::prelude::Error| format!("parse literal: {e}"))?;
    Ok(lit.to_bits_le())
}

/// Parse a Literal from its string representation and convert to a field element.
fn literal_to_field(input: &str) -> Result<Field<N>, String> {
    let lit: Literal<N> = input
        .parse()
        .map_err(|e: snarkvm_console::prelude::Error| format!("parse literal: {e}"))?;
    match lit {
        Literal::Field(f) => Ok(f),
        other => {
            // For non-field types, hash to field via bits for Poseidon compatibility
            let bits = other.to_bits_le();
            Field::<N>::from_bits_le(&bits)
                .map_err(|e| format!("convert to field: {e}"))
        }
    }
}

/// BHP hash functions: take bits as input, return a field.
macro_rules! define_bhp_hash_ffi {
    ($fn_name:ident, $hasher:ident) => {
        #[no_mangle]
        pub extern "C" fn $fn_name(input_ptr: *const c_char) -> *mut c_char {
            ffi_catch!(
                concat!("panic during ", stringify!($hasher)),
                let input = unsafe { read_c_str(input_ptr) }.ok_or("null input")?;
                let bits = literal_to_bits(input)?;
                let result = N::$hasher(&bits)
                    .map_err(|e| format!("{}: {e}", stringify!($hasher)))?;
                Ok(result.to_string())
            )
        }
    };
}

/// Pedersen hash functions: take bits as input, return a field.
macro_rules! define_ped_hash_ffi {
    ($fn_name:ident, $hasher:ident) => {
        #[no_mangle]
        pub extern "C" fn $fn_name(input_ptr: *const c_char) -> *mut c_char {
            ffi_catch!(
                concat!("panic during ", stringify!($hasher)),
                let input = unsafe { read_c_str(input_ptr) }.ok_or("null input")?;
                let bits = literal_to_bits(input)?;
                let result = N::$hasher(&bits)
                    .map_err(|e| format!("{}: {e}", stringify!($hasher)))?;
                Ok(result.to_string())
            )
        }
    };
}

/// Poseidon hash functions: take fields as input, return a field.
macro_rules! define_psd_hash_ffi {
    ($fn_name:ident, $hasher:ident) => {
        #[no_mangle]
        pub extern "C" fn $fn_name(input_ptr: *const c_char) -> *mut c_char {
            ffi_catch!(
                concat!("panic during ", stringify!($hasher)),
                let input = unsafe { read_c_str(input_ptr) }.ok_or("null input")?;
                let field = literal_to_field(input)?;
                let result = N::$hasher(&[field])
                    .map_err(|e| format!("{}: {e}", stringify!($hasher)))?;
                Ok(result.to_string())
            )
        }
    };
}

define_bhp_hash_ffi!(aleo_hash_bhp256, hash_bhp256);
define_bhp_hash_ffi!(aleo_hash_bhp512, hash_bhp512);
define_bhp_hash_ffi!(aleo_hash_bhp768, hash_bhp768);
define_bhp_hash_ffi!(aleo_hash_bhp1024, hash_bhp1024);

define_ped_hash_ffi!(aleo_hash_ped64, hash_ped64);
define_ped_hash_ffi!(aleo_hash_ped128, hash_ped128);

define_psd_hash_ffi!(aleo_hash_psd2, hash_psd2);
define_psd_hash_ffi!(aleo_hash_psd4, hash_psd4);
define_psd_hash_ffi!(aleo_hash_psd8, hash_psd8);
