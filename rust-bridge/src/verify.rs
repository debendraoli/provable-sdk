use std::os::raw::c_char;

use snarkvm_console::network::MainnetV0;
use snarkvm_synthesizer::Process;

use crate::helpers::{ffi_catch, read_c_str};

type N = MainnetV0;

/// Verify an execution proof offline.
/// `execution_json_ptr` is the JSON-serialized Execution.
/// Returns "true" on success, or `{"error":"..."}` on failure.
#[no_mangle]
pub extern "C" fn aleo_verify_execution(execution_json_ptr: *const c_char) -> *mut c_char {
    use snarkvm_algorithms::snark::varuna::VarunaVersion;
    use snarkvm_console::network::ConsensusVersion;
    use snarkvm_synthesizer::prelude::InclusionVersion;
    ffi_catch!("panic during execution verification",
        let exec_str = unsafe { read_c_str(execution_json_ptr) }.ok_or("null execution json")?;
        let execution: snarkvm_ledger_block::Execution<N> =
            serde_json::from_str(exec_str).map_err(|e| format!("parse execution: {e}"))?;
        let process = Process::<N>::load().map_err(|e| format!("load process: {e}"))?;
        process.verify_execution(
                ConsensusVersion::latest(),
                VarunaVersion::V2,
                InclusionVersion::V1,
                &execution,
            )
            .map_err(|e| format!("verify execution: {e}"))?;
        Ok("true".to_string())
    )
}
