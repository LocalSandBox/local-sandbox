pub const HEADER_LEN: usize = 32;
pub const MAX_CONTROL_PAYLOAD: usize = 256 * 1024;
pub const MAX_STREAM_PAYLOAD: usize = 64 * 1024;
pub const STREAM_SEQUENCE_LEN: usize = 8;
pub const INITIAL_STREAM_CREDIT: usize = 256 * 1024;
pub const MAX_FILE_TRANSFER_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_STRING_LEN: usize = 32 * 1024;

pub const MAX_LEDGER_DOCUMENTS: usize = 1_024;
pub const MAX_LEDGER_DOCUMENT_SIZE: usize = 256 * 1024;
pub const MAX_LEDGER_RESOURCES: usize = 256;
pub const MAX_LEDGER_TOTAL_SIZE: usize = 64 * 1024 * 1024;
