#![no_main]
// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
use libfuzzer_sys::fuzz_target;
use mybastion::protocol::Instruction;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz single-instruction parsing
        let _ = Instruction::parse(s);
    }
});
