pub const HEADER_LEN: usize = 32;
pub const MAX_CONTROL_PAYLOAD: usize = 256 * 1024;
pub const MAX_STREAM_PAYLOAD: usize = 64 * 1024;
pub const STREAM_SEQUENCE_LEN: usize = 8;
pub const INITIAL_STREAM_CREDIT: usize = 256 * 1024;
pub const MAX_FILE_TRANSFER_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_STRING_LEN: usize = 32 * 1024;

pub const MAX_MOUNT_ENTRIES: usize = 100_000;
pub const MAX_MOUNT_TREE_BYTES: u64 = 20 * 1024 * 1024 * 1024;
pub const MAX_MOUNT_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_MOUNT_COMPONENTS: usize = 256;
pub const MAX_MOUNT_WINDOWS_UTF16: usize = 32_767;
pub const MAX_MOUNT_QUEUED_CHANGES: usize = 100;
pub const MAX_MOUNT_FAST_COPY_BYTES: u64 = 16 * 1024 * 1024;

pub const MAX_LEDGER_DOCUMENTS: usize = 1_024;
pub const MAX_LEDGER_DOCUMENT_SIZE: usize = 256 * 1024;
pub const MAX_LEDGER_RESOURCES: usize = 256;
pub const MAX_LEDGER_TOTAL_SIZE: usize = 64 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_limits_match_the_production_decision_record() {
        assert_eq!(MAX_MOUNT_ENTRIES, 100_000);
        assert_eq!(MAX_MOUNT_TREE_BYTES, 20 * 1024 * 1024 * 1024);
        assert_eq!(MAX_MOUNT_FILE_BYTES, 4 * 1024 * 1024 * 1024);
        assert_eq!(MAX_MOUNT_COMPONENTS, 256);
        assert_eq!(MAX_MOUNT_WINDOWS_UTF16, 32_767);
        assert_eq!(MAX_MOUNT_QUEUED_CHANGES, 100);
        assert_eq!(MAX_MOUNT_FAST_COPY_BYTES, 16 * 1024 * 1024);
    }
}
