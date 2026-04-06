use std::os::raw::c_char;

use rand::thread_rng;
use snarkvm_circuit_network::AleoV0;
use snarkvm_console::network::MainnetV0;
use snarkvm_console::prelude::ToBytes;
use snarkvm_console::program::Value;
use snarkvm_synthesizer::{Authorization, Process, Program};

use crate::helpers::{ffi_catch, read_c_str};

type N = MainnetV0;

/// Build a snarkVM Authorization via Process::authorize (no proof generation).
///
/// # Parameters
/// - `private_key_ptr`: Aleo private key string.
/// - `program_source_ptr`: Aleo instructions source of the target program.
/// - `function_name_ptr`: Function name to authorize.
/// - `inputs_json_ptr`: JSON array of input strings, e.g. `["1u32","aleo1..."]`.
/// - `imports_json_ptr`: JSON array of import program sources (in dependency order,
///   excluding `credits.aleo`). Each element is the raw Aleo instructions string.
///
/// # Returns
/// JSON-serialized Authorization on success, or `{"error":"..."}` on failure.
#[no_mangle]
pub extern "C" fn aleo_authorize(
    private_key_ptr: *const c_char,
    program_source_ptr: *const c_char,
    function_name_ptr: *const c_char,
    inputs_json_ptr: *const c_char,
    imports_json_ptr: *const c_char,
) -> *mut c_char {
    ffi_catch!("panic during authorization",
        let sk_str = unsafe { read_c_str(private_key_ptr) }.ok_or("null private key")?;
        let source = unsafe { read_c_str(program_source_ptr) }.ok_or("null program source")?;
        let fn_name = unsafe { read_c_str(function_name_ptr) }.ok_or("null function name")?;
        let inputs_str = unsafe { read_c_str(inputs_json_ptr) }.ok_or("null inputs json")?;
        let imports_str = unsafe { read_c_str(imports_json_ptr) }.ok_or("null imports json")?;

        // Parse private key.
        let private_key: snarkvm_console::account::PrivateKey<N> =
            sk_str.parse().map_err(|e: snarkvm_console::prelude::Error| e.to_string())?;

        // Parse inputs from JSON array of strings.
        let input_strings: Vec<String> =
            serde_json::from_str(inputs_str).map_err(|e| format!("parse inputs JSON: {e}"))?;
        let inputs: Vec<Value<N>> = input_strings
            .iter()
            .enumerate()
            .map(|(i, s)| s.parse::<Value<N>>().map_err(|e| format!("parse input #{i} '{s}': {e}")))
            .collect::<Result<Vec<_>, _>>()?;

        // Parse import sources from JSON array of strings.
        let import_sources: Vec<String> =
            serde_json::from_str(imports_str).map_err(|e| format!("parse imports JSON: {e}"))?;

        // Initialize the process (loads credits.aleo + universal SRS).
        let mut process = Process::<N>::load().map_err(|e| format!("load process: {e}"))?;

        // Add each import program in dependency order.
        for (i, imp_src) in import_sources.iter().enumerate() {
            let imp_program: Program<N> = imp_src
                .parse()
                .map_err(|e: snarkvm_console::prelude::Error| format!("parse import #{i}: {e}"))?;
            process
                .add_program(&imp_program)
                .map_err(|e| format!("add import '{}': {e}", imp_program.id()))?;
        }

        // Parse and add the target program.
        let program: Program<N> = source
            .parse()
            .map_err(|e: snarkvm_console::prelude::Error| format!("parse program: {e}"))?;
        process
            .add_program(&program)
            .map_err(|e| format!("add program '{}': {e}", program.id()))?;

        // Build the authorization.
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

        // Serialize to JSON.
        let json = serde_json::to_string(&authorization)
            .map_err(|e| format!("serialize authorization: {e}"))?;

        Ok(json)
    )
}

/// Serialize a ProvingRequest to little-endian bytes (matching the Provable SDK wire format).
///
/// The binary format is:
///   authorization.to_bytes_le() || has_fee_flag:u8 || [fee_authorization.to_bytes_le()] || broadcast:u8
///
/// # Parameters
/// - `auth_json_ptr`: JSON-serialized Authorization (from `aleo_authorize`).
/// - `fee_auth_json_ptr`: JSON-serialized fee Authorization, or null/empty for none.
/// - `broadcast`: whether the prover should broadcast the transaction.
///
/// # Returns
/// Base64-encoded LE bytes on success, or `{"error":"..."}` on failure.
#[no_mangle]
pub extern "C" fn aleo_proving_request_to_bytes(
    auth_json_ptr: *const c_char,
    fee_auth_json_ptr: *const c_char,
    broadcast: bool,
) -> *mut c_char {
    ffi_catch!("panic during proving request serialization",
        use std::io::Write;
        use base64::{Engine, engine::general_purpose::STANDARD};

        let auth_str = unsafe { read_c_str(auth_json_ptr) }.ok_or("null authorization json")?;

        // Parse authorization from JSON.
        let authorization: Authorization<N> =
            serde_json::from_str(auth_str).map_err(|e| format!("parse authorization: {e}"))?;

        // Parse optional fee authorization.
        let fee_authorization: Option<Authorization<N>> = {
            let fee_str = unsafe { read_c_str(fee_auth_json_ptr) };
            match fee_str {
                Some(s) if !s.is_empty() => {
                    Some(serde_json::from_str(s).map_err(|e| format!("parse fee authorization: {e}"))?)
                }
                _ => None,
            }
        };

        // Write in the same binary format as ProvingRequestNative::write_le:
        //   authorization || has_fee:bool || [fee_authorization] || broadcast:bool
        let mut bytes = Vec::new();
        authorization.write_le(&mut bytes)
            .map_err(|e| format!("serialize authorization bytes: {e}"))?;

        match &fee_authorization {
            Some(fa) => {
                bytes.write_all(&[1u8]).map_err(|e| format!("write fee flag: {e}"))?;
                fa.write_le(&mut bytes)
                    .map_err(|e| format!("serialize fee authorization bytes: {e}"))?;
            }
            None => {
                bytes.write_all(&[0u8]).map_err(|e| format!("write fee flag: {e}"))?;
            }
        }

        bytes.write_all(&[broadcast as u8]).map_err(|e| format!("write broadcast flag: {e}"))?;

        Ok(STANDARD.encode(&bytes))
    )
}
