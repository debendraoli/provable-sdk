use std::os::raw::c_char;

use snarkvm_console::{
    network::MainnetV0,
    program::{Ciphertext, Record},
};
use snarkvm_console::account::ViewKey;
use snarkvm_synthesizer::Program;

use crate::helpers::{ffi_catch, read_c_str};

type N = MainnetV0;

/// Decrypt a record ciphertext with a view key.
/// Returns the plaintext record as a string.
#[no_mangle]
pub extern "C" fn aleo_decrypt_record(
    ciphertext_ptr: *const c_char,
    vk_ptr: *const c_char,
) -> *mut c_char {
    ffi_catch!("panic during record decryption",
        let ct_str = unsafe { read_c_str(ciphertext_ptr) }.ok_or("null ciphertext pointer")?;
        let vk_str = unsafe { read_c_str(vk_ptr) }.ok_or("null view key pointer")?;
        let ciphertext: Record<N, Ciphertext<N>> =
            ct_str.parse().map_err(|e: snarkvm_console::prelude::Error| e.to_string())?;
        let vk: ViewKey<N> = vk_str.parse().map_err(|e: snarkvm_console::prelude::Error| e.to_string())?;
        let plaintext = ciphertext.decrypt(&vk).map_err(|e| e.to_string())?;
        Ok(plaintext.to_string())
    )
}

/// Execute a program function offline (scaffold — not yet implemented).
#[no_mangle]
pub extern "C" fn aleo_execute_program(
    program_source_ptr: *const c_char,
    function_name_ptr: *const c_char,
    inputs_json_ptr: *const c_char,
    sk_ptr: *const c_char,
) -> *mut c_char {
    ffi_catch!("panic during program execution",
        let _program_source = unsafe { read_c_str(program_source_ptr) }.ok_or("null program source")?;
        let _function_name = unsafe { read_c_str(function_name_ptr) }.ok_or("null function name")?;
        let _inputs_json = unsafe { read_c_str(inputs_json_ptr) }.ok_or("null inputs json")?;
        let _sk_str = unsafe { read_c_str(sk_ptr) }.ok_or("null private key")?;
        Err("offline program execution not yet implemented; use network-based execution via the Go client".to_string())
    )
}

/// Parse an Aleo instructions program and return its program ID.
/// Returns the program ID on success or `{"error":"..."}`.
#[no_mangle]
pub extern "C" fn aleo_program_id(program_source_ptr: *const c_char) -> *mut c_char {
    ffi_catch!("panic during program parsing",
        let source = unsafe { read_c_str(program_source_ptr) }.ok_or("null program source")?;
        let program: Program<N> = source.parse().map_err(|e: snarkvm_console::prelude::Error| e.to_string())?;
        Ok(program.id().to_string())
    )
}
