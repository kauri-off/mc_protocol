//! Compile-fail tests for `#[derive(Packet)]` diagnostics.

#[test]
#[cfg_attr(miri, ignore)]
fn derive_ui() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
