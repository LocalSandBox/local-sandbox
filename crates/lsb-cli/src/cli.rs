use clap::Parser;

#[derive(clap::Args)]
pub(crate) struct VmArgs {
    /// Number of CPU cores
    #[arg(long)]
    pub cpus: Option<usize>,

    /// Memory in MB
    #[arg(long)]
    pub memory: Option<u64>,

    /// Disk size in MB (default: 4096)
    #[arg(long)]
    pub disk_size: Option<u64>,

    /// Path to kernel
    #[arg(long, env = "LSB_KERNEL")]
    pub kernel: Option<String>,

    /// Path to rootfs image
    #[arg(long, env = "LSB_ROOTFS")]
    pub rootfs: Option<String>,

    /// Pinned base runtime asset version to boot from (defaults to dataDir/VERSION)
    #[arg(long)]
    pub base_version: Option<String>,

    /// Path to initramfs (for loading VirtIO modules)
    #[arg(long, env = "LSB_INITRD")]
    pub initrd: Option<String>,

    /// Allow network access
    #[arg(long)]
    pub allow_net: bool,

    /// Allow direct mounts to write to host filesystem (required for :rw mounts)
    #[arg(long)]
    pub allow_host_writes: bool,

    /// Forward a host port to a guest port (HOST:GUEST, e.g. 8080:80)
    #[arg(short = 'p', long = "port", value_name = "HOST:GUEST")]
    pub port: Vec<String>,

    /// Mount a host directory into the VM (HOST:GUEST[:ro|:rw], default overlay)
    #[arg(long = "mount", value_name = "HOST:GUEST[:ro|:rw]")]
    pub mount: Vec<String>,

    /// Inject a secret via proxy (NAME=VALUE@host1,host2)
    #[arg(long = "secret", value_name = "NAME=VALUE@HOSTS")]
    pub secret: Vec<String>,

    /// Restrict network to specific hosts (repeatable)
    #[arg(long = "allow-host", value_name = "PATTERN")]
    pub allow_host: Vec<String>,

    /// Expose a host port to the guest via host.lsb.internal (HOST:GUEST or PORT)
    #[arg(long = "expose-host", value_name = "HOST:GUEST", hide = true)]
    pub expose_host: Vec<String>,

    /// Path to config file (default: ./lsb.json)
    #[arg(long)]
    pub config: Option<String>,

    /// Show verbose output (kernel boot, init messages)
    #[arg(short = 'v', long)]
    pub verbose: bool,
}

#[derive(Parser)]
#[command(name = "lsb", about = "microVM sandbox for AI agents", version)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand)]
pub(crate) enum Commands {
    /// Boot a VM and run a command inside it
    Run {
        #[command(flatten)]
        vm: VmArgs,

        /// Start from a named checkpoint instead of the base image
        #[arg(long)]
        from: Option<String>,

        /// Attach to raw serial console instead of running a command
        #[arg(long)]
        console: bool,

        /// Run in stdio mode (JSON-lines protocol over stdin/stdout)
        #[arg(long, hide = true)]
        stdio: bool,

        /// Command and arguments to run inside the VM
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Download or update OS image assets
    Init {
        /// Runtime asset version to initialize (defaults to this CLI version)
        #[arg(long)]
        version: Option<String>,

        /// Force re-download even if assets exist
        #[arg(long)]
        force: bool,

        /// Apply all available automatic host configuration fixes
        #[arg(long)]
        fix: bool,

        /// Initialize Windows host tools without downloading runtime assets
        #[arg(long, hide = true)]
        host_tools_only: bool,
    },

    /// Upgrade lsb to the latest release (CLI + OS image)
    Upgrade,

    /// Manage disk checkpoints
    Checkpoint {
        #[command(subcommand)]
        action: CheckpointCommands,
    },

    /// Diagnose host configuration issues
    Doctor {
        #[command(subcommand)]
        action: DoctorCommands,
    },

    /// Remove inactive runtime data
    Prune {
        /// Remove inactive mount-cache objects instead of orphaned VM instances
        #[arg(long)]
        mount_cache: bool,
    },
}

#[derive(clap::Subcommand)]
pub(crate) enum CheckpointCommands {
    /// Run a command and save the resulting disk state as a checkpoint
    Create {
        /// Checkpoint name
        name: String,

        #[command(flatten)]
        vm: VmArgs,

        /// Start from an existing checkpoint instead of the base image
        #[arg(long)]
        from: Option<String>,

        /// Command and arguments to run inside the VM
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// List all checkpoints
    List,

    /// Delete a checkpoint
    Delete {
        /// Checkpoint name
        name: String,
    },

    /// Push a checkpoint to a remote store
    Push {
        /// Checkpoint name
        name: String,
    },

    /// Pull a checkpoint from a remote store
    Pull {
        /// Checkpoint name
        name: String,
    },
}

#[derive(clap::Subcommand)]
pub(crate) enum DoctorCommands {
    /// Diagnose or repair Windows direct SMB mount policy
    WindowsSmbPolicy {
        /// Apply the recommended local security policy repair
        #[arg(long)]
        fix: bool,

        /// Confirm the repair without prompting
        #[arg(long)]
        yes: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_accepts_fix() {
        let cli = Cli::try_parse_from(["lsb", "init", "--fix"]).expect("parse init --fix");
        assert!(matches!(cli.command, Commands::Init { fix: true, .. }));
    }
}
