use std::os::raw::c_char;

use rand::thread_rng;
use snarkvm_circuit_network::AleoV0;
use snarkvm_console::account::{PrivateKey, ViewKey};
use snarkvm_console::{
    network::MainnetV0,
    program::{Ciphertext, Record, Value},
};
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

/// Execute a program function offline (local synthesis + proving).
/// Returns JSON with the execution result.
#[no_mangle]
pub extern "C" fn aleo_execute_program(
    program_source_ptr: *const c_char,
    function_name_ptr: *const c_char,
    inputs_json_ptr: *const c_char,
    sk_ptr: *const c_char,
) -> *mut c_char {
    ffi_catch!("panic during program execution",
        let source = unsafe { read_c_str(program_source_ptr) }.ok_or("null program source")?;
        let fn_name = unsafe { read_c_str(function_name_ptr) }.ok_or("null function name")?;
        let inputs_str = unsafe { read_c_str(inputs_json_ptr) }.ok_or("null inputs json")?;
        let sk_str = unsafe { read_c_str(sk_ptr) }.ok_or("null private key")?;

        let private_key: PrivateKey<N> =
            sk_str.parse().map_err(|e: snarkvm_console::prelude::Error| e.to_string())?;

        let input_strings: Vec<String> =
            serde_json::from_str(inputs_str).map_err(|e| format!("parse inputs JSON: {e}"))?;
        let inputs: Vec<Value<N>> = input_strings
            .iter()
            .enumerate()
            .map(|(i, s)| s.parse::<Value<N>>().map_err(|e| format!("parse input #{i} '{s}': {e}")))
            .collect::<Result<Vec<_>, _>>()?;

        let program: Program<N> = source
            .parse()
            .map_err(|e: snarkvm_console::prelude::Error| format!("parse program: {e}"))?;

        let mut process = crate::authorize::get_or_init_process()?.clone();
        process.add_program(&program)
            .map_err(|e| format!("add program: {e}"))?;

        let mut rng = thread_rng();
        let authorization = process
            .authorize::<AleoV0, _>(
                &private_key,
                program.id(),
                fn_name,
                inputs.into_iter(),
                &mut rng,
            )
            .map_err(|e| format!("authorize: {e}"))?;

        let (response, _trace) = process
            .execute::<AleoV0, _>(authorization, &mut rng)
            .map_err(|e| format!("execute: {e}"))?;

        let outputs: Vec<String> = response.outputs().iter().map(|v| v.to_string()).collect();
        let json = serde_json::to_string(&outputs)
            .map_err(|e| format!("serialize outputs: {e}"))?;
        Ok(json)
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
