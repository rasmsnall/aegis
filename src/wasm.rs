//! WebAssembly entry points for the website's playground.
//!
//! The playground sends JSON in and reads JSON out through linear memory:
//! `alloc` a buffer, write `{"policy": ..., "calls": [...]}` into it, call
//! `simulate` with its pointer and length, then read `output_len()` bytes
//! from the returned pointer. The input buffer is freed by `simulate`.

use std::cell::RefCell;

use serde::Deserialize;

use crate::policy::{Policy, SimCall, simulate as run};

thread_local! {
    static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

#[derive(Deserialize)]
struct Input {
    policy: Policy,
    calls: Vec<SimCall>,
}

/// Allocates `len` bytes for the caller to write input into.
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Simulates the calls in the JSON at `ptr` and returns a pointer to the JSON
/// result (`{"entries": ..., "context": ...}` or `{"error": ...}`).
///
/// # Safety
/// `ptr` must come from `alloc(len)` with `len` bytes written to it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simulate(ptr: *mut u8, len: usize) -> *const u8 {
    // SAFETY: the caller got `ptr` from `alloc(len)` and filled it.
    let input = unsafe { Vec::from_raw_parts(ptr, len, len) };
    let result = match serde_json::from_slice::<Input>(&input) {
        Ok(input) => serde_json::to_vec(&run(&input.policy, &input.calls)),
        Err(e) => serde_json::to_vec(&serde_json::json!({ "error": e.to_string() })),
    }
    .unwrap_or_else(|_| br#"{"error":"serialization failed"}"#.to_vec());
    OUTPUT.with(|out| {
        *out.borrow_mut() = result;
        out.borrow().as_ptr()
    })
}

/// Length of the result returned by the last `simulate` call.
#[unsafe(no_mangle)]
pub extern "C" fn output_len() -> usize {
    OUTPUT.with(|out| out.borrow().len())
}
