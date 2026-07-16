fn main() {
    println!("cargo:rerun-if-changed=resources/LocalSandboxSeaWork.mc");
    // Release packaging sets this after locating the Windows SDK mc/rc tools.
    // Keeping hosted development builds tool-independent avoids an implicit PATH lookup.
    if std::env::var_os("LSB_COMPILE_EVENT_MESSAGES").is_some() {
        println!(
            "cargo:warning=Event message compilation is owned by the Phase 6 packaging pipeline"
        );
    }
}
