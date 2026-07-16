use std::time::Duration;

use windows_service::service::{
    ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};

pub fn pending(state: ServiceState, checkpoint: u32, wait_hint: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint,
        wait_hint,
        process_id: None,
    }
}

pub fn running() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    }
}

pub fn stopped() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_and_running_statuses_obey_scm_contract() {
        let start = pending(ServiceState::StartPending, 1, Duration::from_secs(30));
        assert_eq!(start.checkpoint, 1);
        assert!(!start.wait_hint.is_zero());
        assert!(start.controls_accepted.is_empty());
        let running = running();
        assert!(running
            .controls_accepted
            .contains(ServiceControlAccept::STOP));
        assert!(running
            .controls_accepted
            .contains(ServiceControlAccept::PRESHUTDOWN));
    }
}
