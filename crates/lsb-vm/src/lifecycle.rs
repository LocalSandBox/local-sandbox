use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxLifecyclePhase {
    SnapshotWalk,
    CacheLookup,
    CacheConfiguration,
    SmbSetup,
    SmbInstanceLock,
    SmbMountRevalidate,
    SmbStaleCleanup,
    SmbAdminPreflight,
    SmbPolicyPreflight,
    SmbLoopbackPreflight,
    SmbCredentialGeneration,
    SmbAccountCreate,
    SmbAclPlan,
    SmbAclApply,
    SmbAclVerify,
    SmbShareCreate,
    SmbMountRequestsPublish,
    VmBoot,
    Transfer,
    CachePrepare,
    CacheValidate,
    SyncBarrier,
    OverlayMount,
    SmbSync,
    VmStop,
    CacheDiskDetach,
    CacheFinalize,
    SmbTeardown,
    SmbMountRequestsRemove,
    SmbShareRemove,
    SmbAclRevoke,
    SmbAccountDelete,
    SmbManifestRemove,
    SmbInstanceLockRelease,
    SmbRollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxLifecycleState {
    Started,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxLifecycleEvent {
    pub phase: SandboxLifecyclePhase,
    pub parent_phase: Option<SandboxLifecyclePhase>,
    pub state: SandboxLifecycleState,
    pub succeeded: Option<bool>,
    pub data: BTreeMap<String, String>,
}

pub trait SandboxLifecycleObserver: std::fmt::Debug + Send + Sync {
    fn record(&self, event: SandboxLifecycleEvent);
}

pub(crate) struct LifecyclePhaseGuard {
    observer: Option<Arc<dyn SandboxLifecycleObserver>>,
    phase: SandboxLifecyclePhase,
    parent_phase: Option<SandboxLifecyclePhase>,
    completed: bool,
}

impl LifecyclePhaseGuard {
    pub(crate) fn start(
        observer: Option<&Arc<dyn SandboxLifecycleObserver>>,
        phase: SandboxLifecyclePhase,
        data: BTreeMap<String, String>,
    ) -> Self {
        Self::start_with_parent(observer, phase, None, data)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub(crate) fn start_child(
        observer: Option<&Arc<dyn SandboxLifecycleObserver>>,
        phase: SandboxLifecyclePhase,
        parent_phase: SandboxLifecyclePhase,
        data: BTreeMap<String, String>,
    ) -> Self {
        Self::start_with_parent(observer, phase, Some(parent_phase), data)
    }

    fn start_with_parent(
        observer: Option<&Arc<dyn SandboxLifecycleObserver>>,
        phase: SandboxLifecyclePhase,
        parent_phase: Option<SandboxLifecyclePhase>,
        data: BTreeMap<String, String>,
    ) -> Self {
        let observer = observer.cloned();
        if let Some(observer) = &observer {
            observer.record(SandboxLifecycleEvent {
                phase,
                parent_phase,
                state: SandboxLifecycleState::Started,
                succeeded: None,
                data,
            });
        }
        Self {
            observer,
            phase,
            parent_phase,
            completed: false,
        }
    }

    pub(crate) fn finish(mut self, succeeded: bool, data: BTreeMap<String, String>) {
        self.complete(succeeded, data);
    }

    fn complete(&mut self, succeeded: bool, data: BTreeMap<String, String>) {
        if self.completed {
            return;
        }
        if let Some(observer) = &self.observer {
            observer.record(SandboxLifecycleEvent {
                phase: self.phase,
                parent_phase: self.parent_phase,
                state: SandboxLifecycleState::Completed,
                succeeded: Some(succeeded),
                data,
            });
        }
        self.completed = true;
    }
}

impl Drop for LifecyclePhaseGuard {
    fn drop(&mut self) {
        self.complete(false, BTreeMap::new());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Debug, Default)]
    struct Recorder(Mutex<Vec<SandboxLifecycleEvent>>);

    impl SandboxLifecycleObserver for Recorder {
        fn record(&self, event: SandboxLifecycleEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[test]
    fn guard_always_closes_a_started_phase() {
        let recorder = Arc::new(Recorder::default());
        {
            let _guard = LifecyclePhaseGuard::start(
                Some(&(recorder.clone() as Arc<dyn SandboxLifecycleObserver>)),
                SandboxLifecyclePhase::VmBoot,
                BTreeMap::new(),
            );
        }
        let events = recorder.0.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].state, SandboxLifecycleState::Started);
        assert_eq!(events[1].state, SandboxLifecycleState::Completed);
        assert_eq!(events[1].succeeded, Some(false));
    }
}
