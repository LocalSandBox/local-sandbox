use anyhow::{bail, Result};

use lsb_platform::windows_x86_64::fs::smb::{
    diagnose_windows_smb_policy, fix_windows_smb_policy, WindowsSmbPolicyDiagnosis,
    WindowsSmbPolicyPrincipal, WINDOWS_SMB_LOCAL_ACCOUNT_SID, WINDOWS_SMB_LOCAL_ADMIN_ACCOUNT_SID,
};

pub(crate) fn windows_smb_policy(fix: bool, yes: bool) -> Result<()> {
    if yes && !fix {
        bail!("--yes is only valid with --fix");
    }

    let diagnosis = diagnose_windows_smb_policy()?;
    print_diagnosis(&diagnosis);

    if !fix {
        if diagnosis.blocks_generated_smb_users() {
            bail!(
                "Windows SMB direct mounts are blocked; run `lsb doctor windows-smb-policy --fix` from elevated PowerShell"
            );
        }
        return Ok(());
    }

    if !diagnosis.blocks_generated_smb_users() {
        eprintln!("lsb: Windows SMB policy already allows generated SMB users");
        return Ok(());
    }

    let risky = diagnosis.risky_network_logon_principals();
    if !risky.is_empty() {
        bail!(
            "automatic fix refused because SeNetworkLogonRight includes broad principal(s): {}",
            risky
                .iter()
                .map(|principal| format!("{} ({})", principal.label, principal.sid))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    eprintln!();
    eprintln!("Planned machine-wide policy change:");
    eprintln!(
        "  remove {} from SeDenyNetworkLogonRight",
        WINDOWS_SMB_LOCAL_ACCOUNT_SID
    );
    eprintln!(
        "  add {} to SeDenyNetworkLogonRight",
        WINDOWS_SMB_LOCAL_ADMIN_ACCOUNT_SID
    );
    eprintln!("  keep other existing deny entries unchanged");

    if !yes && !confirm_fix()? {
        bail!("aborted");
    }

    let report = fix_windows_smb_policy()?;
    if report.changed {
        eprintln!("lsb: Windows SMB policy repaired");
    } else {
        eprintln!("lsb: Windows SMB policy did not require changes");
    }
    print_diagnosis(&report.after);

    Ok(())
}

fn print_diagnosis(diagnosis: &WindowsSmbPolicyDiagnosis) {
    eprintln!("Windows SMB direct mount policy");
    eprintln!();
    eprintln!("SeNetworkLogonRight:");
    print_principal_list(&diagnosis.network_logon);
    eprintln!("SeDenyNetworkLogonRight:");
    print_principal_list(&diagnosis.deny_network_logon);
    eprintln!();

    if diagnosis.blocks_generated_smb_users() {
        eprintln!("status: blocked");
        eprintln!(
            "reason: NT AUTHORITY\\Local account ({WINDOWS_SMB_LOCAL_ACCOUNT_SID}) denies network logon for generated lsb_* SMB users"
        );
    } else {
        eprintln!("status: ready");
    }
}

fn print_principal_list(principals: &[WindowsSmbPolicyPrincipal]) {
    if principals.is_empty() {
        eprintln!("  (none)");
        return;
    }
    for principal in principals {
        eprintln!("  {} ({})", principal.label, principal.sid);
    }
}

fn confirm_fix() -> Result<bool> {
    use std::io::Write;

    eprint!("Continue? [y/N] ");
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    Ok(matches!(response.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
}
