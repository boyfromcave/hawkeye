//! Set-signature attribution behind a trait (plan §4.5): the daemon uses
//! [`hawkeye_core::attribution::attribute_template_input`]; tests against the mock ycashd, whose
//! set signatures are placeholders, substitute their own.

use hawkeye_core::attribution::Attribution;

/// Who signed a template input.
pub trait Attributor: Send + Sync {
    /// Attribute input `input_index` of `tx_bytes`, which spends `prev_spk` worth
    /// `prev_value_zat`, under `branch_id`.
    fn attribute(
        &self,
        tx_bytes: &[u8],
        input_index: usize,
        prev_spk: &[u8],
        prev_value_zat: u64,
        branch_id: u32,
    ) -> Result<Attribution, String>;
}

/// The real attribution: ZIP-243 sighash, `SetSigMsg`, recovery (hawkeye-core).
#[derive(Debug, Default, Clone, Copy)]
pub struct CoreAttributor;

impl Attributor for CoreAttributor {
    fn attribute(
        &self,
        tx_bytes: &[u8],
        input_index: usize,
        prev_spk: &[u8],
        prev_value_zat: u64,
        branch_id: u32,
    ) -> Result<Attribution, String> {
        hawkeye_core::attribution::attribute_template_input(
            tx_bytes,
            input_index,
            prev_spk,
            prev_value_zat,
            branch_id,
        )
        .map_err(|e| e.to_string())
    }
}
