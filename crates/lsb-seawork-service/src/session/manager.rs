use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use lsb_service_proto::SelectedMount;

use super::quota::{QuotaBook, QuotaLimits, SandboxResources};
use super::{CancellationToken, ResourceHandle};
use crate::admission::{ActiveUseLease, AdmissionController};
#[cfg(windows)]
use crate::engine::ServiceEngineConfig;
#[cfg(windows)]
use crate::resource::process::{
    GuestProcessResource, ManagedProcess, ManagedProcessController, ManagedProcessOutput,
};
#[cfg(windows)]
use crate::resource::vm::{
    ManagedExecResult, ManagedExecSpec, ManagedFileOp, ManagedFileResult, ManagedVm, ManagedVmSpec,
};
#[cfg(windows)]
use crate::resource::watch::{
    ManagedWatch, ManagedWatchController, ManagedWatchEvent, WatchResource,
};

const MAX_RETIRED_HANDLES: usize = 4_096;
const RETIRED_HANDLE_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_START_REPLAY_RECORDS: usize = 4_096;
const START_REPLAY_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientIdentityKey {
    pub user_sid: String,
    pub logon_sid: String,
    pub authentication_luid: u64,
    pub session_id: u32,
}

impl ClientIdentityKey {
    #[cfg(test)]
    pub fn for_test(user_sid: &str, logon_sid: &str, session_id: u32) -> Self {
        Self {
            user_sid: user_sid.to_string(),
            logon_sid: logon_sid.to_string(),
            authentication_luid: session_id as u64,
            session_id,
        }
    }
}

#[derive(Debug)]
struct Session {
    identity: ClientIdentityKey,
    cancellation: CancellationToken,
    test_resources: HashMap<ResourceHandle, TestResource>,
    #[cfg(windows)]
    sandboxes: HashMap<ResourceHandle, SandboxSlot>,
    #[cfg(windows)]
    processes: HashMap<ResourceHandle, ProcessSlot>,
    #[cfg(windows)]
    watches: HashMap<ResourceHandle, WatchSlot>,
    retired: VecDeque<(Instant, ResourceHandle)>,
}

#[cfg(windows)]
#[derive(Debug)]
struct SandboxSlot {
    vm: Option<ManagedVm>,
    _active_use: ActiveUseLease,
}

#[derive(Debug)]
struct TestResource {
    value: String,
    _active_use: ActiveUseLease,
}

#[cfg(windows)]
#[derive(Debug)]
enum ProcessSlot {
    Preparing(GuestProcessResource),
    Running {
        resource: GuestProcessResource,
        process: ManagedProcess,
    },
}

#[cfg(windows)]
#[derive(Debug)]
enum WatchSlot {
    Preparing(WatchResource),
    Running {
        resource: WatchResource,
        watch: ManagedWatch,
    },
}

#[cfg(windows)]
impl WatchSlot {
    fn resource(&self) -> &WatchResource {
        match self {
            Self::Preparing(resource) | Self::Running { resource, .. } => resource,
        }
    }

    fn controller(&self) -> Option<ManagedWatchController> {
        match self {
            Self::Preparing(_) => None,
            Self::Running { watch, .. } => Some(watch.controller()),
        }
    }
}

#[cfg(windows)]
impl ProcessSlot {
    fn resource(&self) -> &GuestProcessResource {
        match self {
            Self::Preparing(resource) | Self::Running { resource, .. } => resource,
        }
    }

    fn controller(&self) -> Option<ManagedProcessController> {
        match self {
            Self::Preparing(_) => None,
            Self::Running { process, .. } => Some(process.controller()),
        }
    }
}

#[derive(Debug)]
struct State {
    sessions: HashMap<ResourceHandle, Session>,
    quotas: QuotaBook,
    start_replays: HashMap<StartReplayKey, StartReplayRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StartReplayKey {
    identity: ClientIdentityKey,
    client_instance_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StartReplayState {
    Preparing,
    Running {
        sandbox_id: ResourceHandle,
        mounts: Vec<SelectedMount>,
    },
    Retired,
}

#[derive(Debug)]
struct StartReplayRecord {
    session_id: ResourceHandle,
    state: StartReplayState,
    updated_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartReplayDecision {
    Begin,
    InProgress,
    Replay {
        sandbox_id: ResourceHandle,
        mounts: Vec<SelectedMount>,
    },
    Expired,
    CapacityExceeded,
}

#[derive(Debug, Clone)]
pub struct SessionManager {
    state: Arc<Mutex<State>>,
    admissions: AdmissionController,
}

impl SessionManager {
    pub fn new(limits: QuotaLimits) -> Self {
        Self::with_admissions(limits, AdmissionController::new(true))
    }

    pub fn with_admissions(limits: QuotaLimits, admissions: AdmissionController) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                sessions: HashMap::new(),
                quotas: QuotaBook::new(limits),
                start_replays: HashMap::new(),
            })),
            admissions,
        }
    }

    pub fn admissions(&self) -> &AdmissionController {
        &self.admissions
    }

    pub fn open(&self, identity: ClientIdentityKey) -> Result<ResourceHandle> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        state.quotas.reserve_connection(&identity)?;
        let id = unique_handle(&state.sessions)?;
        state.sessions.insert(
            id,
            Session {
                identity,
                cancellation: CancellationToken::default(),
                test_resources: HashMap::new(),
                #[cfg(windows)]
                sandboxes: HashMap::new(),
                #[cfg(windows)]
                processes: HashMap::new(),
                #[cfg(windows)]
                watches: HashMap::new(),
                retired: VecDeque::new(),
            },
        );
        Ok(id)
    }

    pub fn close(&self, session_id: ResourceHandle, identity: &ClientIdentityKey) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let Some(session) = state.sessions.get(&session_id) else {
            return Ok(false);
        };
        if &session.identity != identity {
            return Ok(false);
        }
        session.cancellation.cancel();
        let now = Instant::now();
        for record in state.start_replays.values_mut() {
            if record.session_id == session_id {
                record.state = StartReplayState::Retired;
                record.updated_at = now;
            }
        }
        let session = state
            .sessions
            .remove(&session_id)
            .context("session disappeared")?;
        let mut sandbox_handles = session.test_resources.keys().copied().collect::<Vec<_>>();
        #[cfg(windows)]
        sandbox_handles.extend(session.sandboxes.keys().copied());
        for handle in sandbox_handles {
            state.quotas.release_sandbox(session_id, handle, identity);
        }
        #[cfg(windows)]
        for process in session.processes.values() {
            state
                .quotas
                .release_process(process.resource().sandbox_id, identity);
            if let Some(controller) = process.controller() {
                let _ = controller.kill();
            }
        }
        #[cfg(windows)]
        for watch in session.watches.values() {
            state
                .quotas
                .release_watch(watch.resource().sandbox_id, identity);
            if let Some(controller) = watch.controller() {
                controller.stop();
            }
        }
        state.quotas.release_connection(identity);
        Ok(true)
    }

    pub fn drain_all(&self) -> Result<usize> {
        let sessions = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
            state
                .sessions
                .iter()
                .map(|(id, session)| (*id, session.identity.clone()))
                .collect::<Vec<_>>()
        };
        let mut drained = 0;
        for (session_id, identity) in sessions {
            if self.close(session_id, &identity)? {
                drained += 1;
            }
        }
        Ok(drained)
    }

    pub fn is_empty(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.sessions.is_empty())
            .unwrap_or(false)
    }

    pub fn cancellation(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
    ) -> Option<CancellationToken> {
        let state = self.state.lock().ok()?;
        let session = state.sessions.get(&session_id)?;
        (&session.identity == identity).then(|| session.cancellation.clone())
    }

    pub fn create_test_resource(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        value: String,
    ) -> Result<ResourceHandle> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let matches = state
            .sessions
            .get(&session_id)
            .is_some_and(|session| &session.identity == identity);
        if !matches {
            bail!("resource not found");
        }
        let active_use = self.admissions.reserve_active_use()?;
        let handle = ResourceHandle::random()?;
        state
            .quotas
            .reserve_sandbox(session_id, handle, identity, SandboxResources::default())?;
        let session = state
            .sessions
            .get_mut(&session_id)
            .context("session disappeared")?;
        session.test_resources.insert(
            handle,
            TestResource {
                value,
                _active_use: active_use,
            },
        );
        Ok(handle)
    }

    pub fn get_test_resource(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        handle: ResourceHandle,
    ) -> Option<String> {
        let state = self.state.lock().ok()?;
        let session = state.sessions.get(&session_id)?;
        if &session.identity != identity {
            return None;
        }
        session
            .test_resources
            .get(&handle)
            .map(|resource| resource.value.clone())
    }

    pub fn close_test_resource(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        handle: ResourceHandle,
    ) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let session = state
            .sessions
            .get_mut(&session_id)
            .context("resource not found")?;
        if &session.identity != identity {
            return Ok(false);
        }
        prune_retired(&mut session.retired);
        if session
            .retired
            .iter()
            .any(|(_, retired)| *retired == handle)
        {
            return Ok(true);
        }
        if session.test_resources.remove(&handle).is_none() {
            return Ok(false);
        }
        session.retired.push_back((Instant::now(), handle));
        if session.retired.len() > MAX_RETIRED_HANDLES {
            session.retired.pop_front();
        }
        state.quotas.release_sandbox(session_id, handle, identity);
        Ok(true)
    }

    pub fn counts(&self) -> (usize, usize) {
        self.state
            .lock()
            .map(|state| state.quotas.totals())
            .unwrap_or_default()
    }

    pub fn begin_start_replay(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        client_instance_id: &str,
    ) -> Result<StartReplayDecision> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let owns_session = state
            .sessions
            .get(&session_id)
            .is_some_and(|session| &session.identity == identity);
        if !owns_session {
            bail!("resource not found");
        }
        prune_start_replays(&mut state.start_replays);
        let key = StartReplayKey {
            identity: identity.clone(),
            client_instance_id: client_instance_id.to_string(),
        };
        if let Some(record) = state.start_replays.get(&key) {
            return Ok(match &record.state {
                StartReplayState::Preparing if record.session_id == session_id => {
                    StartReplayDecision::InProgress
                }
                StartReplayState::Running { sandbox_id, mounts }
                    if record.session_id == session_id =>
                {
                    StartReplayDecision::Replay {
                        sandbox_id: *sandbox_id,
                        mounts: mounts.clone(),
                    }
                }
                StartReplayState::Preparing
                | StartReplayState::Running { .. }
                | StartReplayState::Retired => StartReplayDecision::Expired,
            });
        }
        if state.start_replays.len() >= MAX_START_REPLAY_RECORDS {
            return Ok(StartReplayDecision::CapacityExceeded);
        }
        state.start_replays.insert(
            key,
            StartReplayRecord {
                session_id,
                state: StartReplayState::Preparing,
                updated_at: Instant::now(),
            },
        );
        Ok(StartReplayDecision::Begin)
    }

    pub fn complete_start_replay(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        client_instance_id: &str,
        sandbox_id: ResourceHandle,
        mounts: Vec<SelectedMount>,
    ) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let key = StartReplayKey {
            identity: identity.clone(),
            client_instance_id: client_instance_id.to_string(),
        };
        let Some(record) = state.start_replays.get_mut(&key) else {
            return Ok(false);
        };
        if record.session_id != session_id || record.state != StartReplayState::Preparing {
            return Ok(false);
        }
        record.state = StartReplayState::Running { sandbox_id, mounts };
        record.updated_at = Instant::now();
        Ok(true)
    }

    pub fn abandon_start_replay(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        client_instance_id: &str,
    ) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let key = StartReplayKey {
            identity: identity.clone(),
            client_instance_id: client_instance_id.to_string(),
        };
        let remove = state.start_replays.get(&key).is_some_and(|record| {
            record.session_id == session_id && record.state == StartReplayState::Preparing
        });
        if remove {
            state.start_replays.remove(&key);
        }
        Ok(remove)
    }

    #[cfg(windows)]
    fn retire_start_replay(
        state: &mut State,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        sandbox_id: ResourceHandle,
    ) {
        let now = Instant::now();
        for (key, record) in &mut state.start_replays {
            if &key.identity == identity
                && record.session_id == session_id
                && matches!(
                    record.state,
                    StartReplayState::Running {
                        sandbox_id: replay_sandbox_id,
                        ..
                    } if replay_sandbox_id == sandbox_id
                )
            {
                record.state = StartReplayState::Retired;
                record.updated_at = now;
            }
        }
    }

    #[cfg(windows)]
    pub fn reserve_managed_vm(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        resources: SandboxResources,
    ) -> Result<ResourceHandle> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let matches = state
            .sessions
            .get(&session_id)
            .is_some_and(|session| &session.identity == identity);
        if !matches {
            bail!("resource not found");
        }
        let active_use = self.admissions.reserve_active_use()?;
        let handle = ResourceHandle::random()?;
        state
            .quotas
            .reserve_sandbox(session_id, handle, identity, resources)?;
        let session = state
            .sessions
            .get_mut(&session_id)
            .context("session disappeared")?;
        session.sandboxes.insert(
            handle,
            SandboxSlot {
                vm: None,
                _active_use: active_use,
            },
        );
        Ok(handle)
    }

    #[cfg(windows)]
    pub fn cancel_managed_vm_reservation(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        handle: ResourceHandle,
    ) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let removed = state
            .sessions
            .get_mut(&session_id)
            .filter(|session| &session.identity == identity)
            .is_some_and(|session| {
                if session
                    .sandboxes
                    .get(&handle)
                    .is_some_and(|slot| slot.vm.is_none())
                {
                    session.sandboxes.remove(&handle);
                    true
                } else {
                    false
                }
            });
        if removed {
            state.quotas.release_sandbox(session_id, handle, identity);
        }
        Ok(removed)
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    pub fn start_reserved_managed_vm(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        handle: ResourceHandle,
        engine: &ServiceEngineConfig,
        transaction: crate::resource::transaction::ResourceTransaction,
        spec: ManagedVmSpec,
        startup_cancellation: CancellationToken,
    ) -> Result<ResourceHandle> {
        let cancellation = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
            let session = state
                .sessions
                .get(&session_id)
                .filter(|session| &session.identity == identity)
                .context("resource not found")?;
            if session
                .sandboxes
                .get(&handle)
                .is_none_or(|slot| slot.vm.is_some())
            {
                bail!("sandbox reservation is unavailable");
            }
            session.cancellation.clone()
        };

        let started = ManagedVm::start(
            engine,
            transaction,
            spec,
            cancellation,
            startup_cancellation,
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let Some(session) = state.sessions.get_mut(&session_id) else {
            if let Ok(vm) = started {
                let _ = vm.stop(std::time::Duration::from_secs(30));
            }
            bail!("session closed during VM startup");
        };
        if &session.identity != identity
            || session
                .sandboxes
                .get(&handle)
                .is_none_or(|slot| slot.vm.is_some())
        {
            if let Ok(vm) = started {
                let _ = vm.stop(std::time::Duration::from_secs(30));
            }
            bail!("session changed during VM startup");
        }
        match started {
            Ok(vm) => {
                session
                    .sandboxes
                    .get_mut(&handle)
                    .context("sandbox reservation disappeared")?
                    .vm = Some(vm);
                Ok(handle)
            }
            Err(error) => {
                session.sandboxes.remove(&handle);
                state.quotas.release_sandbox(session_id, handle, identity);
                Err(error)
            }
        }
    }

    #[cfg(windows)]
    pub fn stop_managed_vm(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        handle: ResourceHandle,
        timeout: std::time::Duration,
    ) -> Result<bool> {
        let (vm, processes, watches) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
            let (vm, processes, watches) = {
                let session = state
                    .sessions
                    .get_mut(&session_id)
                    .context("resource not found")?;
                if &session.identity != identity {
                    return Ok(false);
                }
                let slot = match session.sandboxes.remove(&handle) {
                    Some(slot) if slot.vm.is_some() => slot,
                    Some(slot) => {
                        session.sandboxes.insert(handle, slot);
                        bail!("sandbox is still preparing");
                    }
                    None => return Ok(false),
                };
                let process_ids = session
                    .processes
                    .iter()
                    .filter_map(|(id, process)| {
                        (process.resource().sandbox_id == handle).then_some(*id)
                    })
                    .collect::<Vec<_>>();
                let processes = process_ids
                    .into_iter()
                    .filter_map(|id| session.processes.remove(&id))
                    .collect::<Vec<_>>();
                let watch_ids = session
                    .watches
                    .iter()
                    .filter_map(|(id, watch)| {
                        (watch.resource().sandbox_id == handle).then_some(*id)
                    })
                    .collect::<Vec<_>>();
                let watches = watch_ids
                    .into_iter()
                    .filter_map(|id| session.watches.remove(&id))
                    .collect::<Vec<_>>();
                (slot, processes, watches)
            };
            for process in &processes {
                state
                    .quotas
                    .release_process(process.resource().sandbox_id, identity);
            }
            for watch in &watches {
                state
                    .quotas
                    .release_watch(watch.resource().sandbox_id, identity);
            }
            (vm, processes, watches)
        };
        for process in processes {
            if let Some(controller) = process.controller() {
                let _ = controller.kill();
            }
        }
        for watch in watches {
            if let Some(controller) = watch.controller() {
                controller.stop();
            }
        }
        let mut slot = vm;
        let result = slot
            .vm
            .take()
            .context("running sandbox lost its VM")?
            .stop(timeout);
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        state.quotas.release_sandbox(session_id, handle, identity);
        Self::retire_start_replay(&mut state, session_id, identity, handle);
        result.map(|()| true)
    }

    #[cfg(windows)]
    pub fn exec_managed_vm(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        handle: ResourceHandle,
        spec: ManagedExecSpec,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<Option<ManagedExecResult>> {
        let controller = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
            let Some(session) = state.sessions.get(&session_id) else {
                return Ok(None);
            };
            if &session.identity != identity {
                return Ok(None);
            }
            match session
                .sandboxes
                .get(&handle)
                .and_then(|slot| slot.vm.as_ref())
            {
                Some(vm) => vm.controller(),
                _ => return Ok(None),
            }
        };
        controller.exec(spec, timeout, cancellation).map(Some)
    }

    #[cfg(windows)]
    pub fn file_managed_vm(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        handle: ResourceHandle,
        op: ManagedFileOp,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<Option<ManagedFileResult>> {
        let controller = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
            let Some(session) = state.sessions.get(&session_id) else {
                return Ok(None);
            };
            if &session.identity != identity {
                return Ok(None);
            }
            match session
                .sandboxes
                .get(&handle)
                .and_then(|slot| slot.vm.as_ref())
            {
                Some(vm) => vm.controller(),
                _ => return Ok(None),
            }
        };
        controller.file(op, timeout, cancellation).map(Some)
    }

    #[cfg(windows)]
    pub fn spawn_managed_process(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        sandbox_id: ResourceHandle,
        spec: ManagedExecSpec,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<Option<GuestProcessResource>> {
        let (resource, controller) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
            let controller = {
                let Some(session) = state.sessions.get(&session_id) else {
                    return Ok(None);
                };
                if &session.identity != identity {
                    return Ok(None);
                }
                match session
                    .sandboxes
                    .get(&sandbox_id)
                    .and_then(|slot| slot.vm.as_ref())
                {
                    Some(vm) => vm.controller(),
                    _ => return Ok(None),
                }
            };
            let resource = GuestProcessResource::new(sandbox_id)?;
            state.quotas.reserve_process(sandbox_id, identity)?;
            let session = state
                .sessions
                .get_mut(&session_id)
                .context("session disappeared")?;
            session
                .processes
                .insert(resource.id, ProcessSlot::Preparing(resource.clone()));
            (resource, controller)
        };

        let started = controller.spawn(spec, timeout, cancellation);
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let valid = state.sessions.get(&session_id).is_some_and(|session| {
            &session.identity == identity
                && session.processes.contains_key(&resource.id)
                && session
                    .sandboxes
                    .get(&sandbox_id)
                    .is_some_and(|slot| slot.vm.is_some())
        });
        if !valid {
            if let Ok(process) = started {
                let _ = process.controller().kill();
            }
            return Ok(None);
        }
        match started {
            Ok(process) => {
                let session = state
                    .sessions
                    .get_mut(&session_id)
                    .context("session disappeared")?;
                session.processes.insert(
                    resource.id,
                    ProcessSlot::Running {
                        resource: resource.clone(),
                        process,
                    },
                );
                Ok(Some(resource))
            }
            Err(error) => {
                let session = state
                    .sessions
                    .get_mut(&session_id)
                    .context("session disappeared")?;
                session.processes.remove(&resource.id);
                state.quotas.release_process(sandbox_id, identity);
                Err(error)
            }
        }
    }

    #[cfg(windows)]
    pub fn kill_managed_process(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        process_id: ResourceHandle,
    ) -> Result<bool> {
        let controller = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
            let session = state
                .sessions
                .get_mut(&session_id)
                .context("resource not found")?;
            if &session.identity != identity {
                return Ok(false);
            }
            prune_retired(&mut session.retired);
            if session
                .retired
                .iter()
                .any(|(_, retired)| *retired == process_id)
            {
                return Ok(true);
            }
            let Some(process) = session.processes.get(&process_id) else {
                return Ok(false);
            };
            if matches!(process, ProcessSlot::Preparing(_)) {
                bail!("process is still preparing");
            }
            process.controller()
        };
        if let Some(controller) = controller {
            controller.kill()?;
        }
        Ok(true)
    }

    #[cfg(windows)]
    pub fn retire_managed_process(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        process_id: ResourceHandle,
    ) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let session = state
            .sessions
            .get_mut(&session_id)
            .context("resource not found")?;
        if &session.identity != identity {
            return Ok(false);
        }
        prune_retired(&mut session.retired);
        if session
            .retired
            .iter()
            .any(|(_, retired)| *retired == process_id)
        {
            return Ok(true);
        }
        let Some(process) = session.processes.remove(&process_id) else {
            return Ok(false);
        };
        session.retired.push_back((Instant::now(), process_id));
        if session.retired.len() > MAX_RETIRED_HANDLES {
            session.retired.pop_front();
        }
        state
            .quotas
            .release_process(process.resource().sandbox_id, identity);
        Ok(true)
    }

    #[cfg(windows)]
    pub fn managed_process_output(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        process_id: ResourceHandle,
        timeout: Duration,
    ) -> Result<Option<ManagedProcessOutput>> {
        let controller = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
            let Some(session) = state.sessions.get(&session_id) else {
                return Ok(None);
            };
            if &session.identity != identity {
                return Ok(None);
            }
            let Some(process) = session.processes.get(&process_id) else {
                return Ok(None);
            };
            process.controller()
        };
        match controller {
            Some(controller) => controller.output(timeout),
            None => Ok(None),
        }
    }

    #[cfg(windows)]
    pub fn owns_managed_process(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        process_id: ResourceHandle,
    ) -> bool {
        self.state.lock().is_ok_and(|state| {
            state.sessions.get(&session_id).is_some_and(|session| {
                &session.identity == identity && session.processes.contains_key(&process_id)
            })
        })
    }

    #[cfg(windows)]
    pub fn managed_process_closed(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        process_id: ResourceHandle,
    ) -> bool {
        self.state.lock().map_or(true, |state| {
            state.sessions.get(&session_id).is_none_or(|session| {
                if &session.identity != identity {
                    return true;
                }
                session
                    .processes
                    .get(&process_id)
                    .and_then(ProcessSlot::controller)
                    .is_none_or(|controller| controller.is_closed())
            })
        })
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    pub fn start_managed_watch(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        sandbox_id: ResourceHandle,
        path: String,
        recursive: bool,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<Option<WatchResource>> {
        let (resource, controller) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
            let controller = {
                let Some(session) = state.sessions.get(&session_id) else {
                    return Ok(None);
                };
                if &session.identity != identity {
                    return Ok(None);
                }
                match session
                    .sandboxes
                    .get(&sandbox_id)
                    .and_then(|slot| slot.vm.as_ref())
                {
                    Some(vm) => vm.controller(),
                    _ => return Ok(None),
                }
            };
            let resource = WatchResource::new(sandbox_id, path.clone())?;
            state.quotas.reserve_watch(sandbox_id, identity)?;
            let session = state
                .sessions
                .get_mut(&session_id)
                .context("session disappeared")?;
            session
                .watches
                .insert(resource.id, WatchSlot::Preparing(resource.clone()));
            (resource, controller)
        };

        let started = controller.watch(path, recursive, timeout, cancellation);
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let valid = state.sessions.get(&session_id).is_some_and(|session| {
            &session.identity == identity
                && session.watches.contains_key(&resource.id)
                && session
                    .sandboxes
                    .get(&sandbox_id)
                    .is_some_and(|slot| slot.vm.is_some())
        });
        if !valid {
            if let Ok(watch) = started {
                watch.controller().stop();
            }
            return Ok(None);
        }
        match started {
            Ok(watch) => {
                let session = state
                    .sessions
                    .get_mut(&session_id)
                    .context("session disappeared")?;
                session.watches.insert(
                    resource.id,
                    WatchSlot::Running {
                        resource: resource.clone(),
                        watch,
                    },
                );
                Ok(Some(resource))
            }
            Err(error) => {
                let session = state
                    .sessions
                    .get_mut(&session_id)
                    .context("session disappeared")?;
                session.watches.remove(&resource.id);
                state.quotas.release_watch(sandbox_id, identity);
                Err(error)
            }
        }
    }

    #[cfg(windows)]
    pub fn stop_managed_watch(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        watch_id: ResourceHandle,
    ) -> Result<bool> {
        let watch = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
            let session = state
                .sessions
                .get_mut(&session_id)
                .context("resource not found")?;
            if &session.identity != identity {
                return Ok(false);
            }
            prune_retired(&mut session.retired);
            if session
                .retired
                .iter()
                .any(|(_, retired)| *retired == watch_id)
            {
                return Ok(true);
            }
            if matches!(
                session.watches.get(&watch_id),
                Some(WatchSlot::Preparing(_))
            ) {
                bail!("watch is still preparing");
            }
            let Some(watch) = session.watches.remove(&watch_id) else {
                return Ok(false);
            };
            session.retired.push_back((Instant::now(), watch_id));
            if session.retired.len() > MAX_RETIRED_HANDLES {
                session.retired.pop_front();
            }
            state
                .quotas
                .release_watch(watch.resource().sandbox_id, identity);
            watch
        };
        if let Some(controller) = watch.controller() {
            controller.stop();
        }
        Ok(true)
    }

    #[cfg(windows)]
    pub fn retire_managed_watch(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        watch_id: ResourceHandle,
    ) -> Result<bool> {
        self.stop_managed_watch(session_id, identity, watch_id)
    }

    #[cfg(windows)]
    pub fn managed_watch_event(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        watch_id: ResourceHandle,
        timeout: Duration,
    ) -> Result<Option<ManagedWatchEvent>> {
        let controller = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
            let Some(session) = state.sessions.get(&session_id) else {
                return Ok(None);
            };
            if &session.identity != identity {
                return Ok(None);
            }
            session
                .watches
                .get(&watch_id)
                .and_then(WatchSlot::controller)
        };
        match controller {
            Some(controller) => controller.next(timeout),
            None => Ok(None),
        }
    }

    #[cfg(windows)]
    pub fn managed_watch_closed(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        watch_id: ResourceHandle,
    ) -> bool {
        self.state.lock().map_or(true, |state| {
            state.sessions.get(&session_id).is_none_or(|session| {
                if &session.identity != identity {
                    return true;
                }
                session
                    .watches
                    .get(&watch_id)
                    .and_then(WatchSlot::controller)
                    .is_none_or(|controller| controller.is_closed())
            })
        })
    }
}

fn unique_handle<T>(map: &HashMap<ResourceHandle, T>) -> Result<ResourceHandle> {
    for _ in 0..8 {
        let handle = ResourceHandle::random()?;
        if !map.contains_key(&handle) {
            return Ok(handle);
        }
    }
    bail!("could not allocate a unique resource handle")
}

fn prune_retired(retired: &mut VecDeque<(Instant, ResourceHandle)>) {
    prune_retired_at(retired, Instant::now());
}

fn prune_retired_at(retired: &mut VecDeque<(Instant, ResourceHandle)>, now: Instant) {
    while retired
        .front()
        .is_some_and(|(created, _)| now.saturating_duration_since(*created) > RETIRED_HANDLE_TTL)
    {
        retired.pop_front();
    }
}

fn prune_start_replays(records: &mut HashMap<StartReplayKey, StartReplayRecord>) {
    prune_start_replays_at(records, Instant::now());
}

fn prune_start_replays_at(records: &mut HashMap<StartReplayKey, StartReplayRecord>, now: Instant) {
    records.retain(|_, record| {
        record.state != StartReplayState::Retired
            || now.saturating_duration_since(record.updated_at) <= START_REPLAY_TTL
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_pruning_tolerates_timestamps_after_the_observed_instant() {
        let now = Instant::now();
        let future = now + Duration::from_secs(1);
        let handle = ResourceHandle::random().unwrap();
        let mut retired = VecDeque::from([(future, handle)]);
        prune_retired_at(&mut retired, now);
        assert_eq!(retired.front(), Some(&(future, handle)));

        let key = StartReplayKey {
            identity: ClientIdentityKey::for_test("user", "logon", 1),
            client_instance_id: "post-reboot-start".to_string(),
        };
        let mut records = HashMap::from([(
            key.clone(),
            StartReplayRecord {
                session_id: ResourceHandle::random().unwrap(),
                state: StartReplayState::Retired,
                updated_at: future,
            },
        )]);
        prune_start_replays_at(&mut records, now);
        assert!(records.contains_key(&key));
    }

    #[test]
    fn start_replay_is_at_most_once_and_connection_bound() {
        let manager = SessionManager::new(QuotaLimits::default());
        let identity = ClientIdentityKey::for_test("user", "logon", 1);
        let original_session = manager.open(identity.clone()).unwrap();
        let reconnect_session = manager.open(identity.clone()).unwrap();
        let sandbox_id = ResourceHandle::random().unwrap();
        let selected_mounts = vec![SelectedMount {
            guest_path: "/workspace".to_string(),
            backend: "compat-smb-direct".to_string(),
        }];

        assert_eq!(
            manager
                .begin_start_replay(original_session, &identity, "stable-start")
                .unwrap(),
            StartReplayDecision::Begin
        );
        assert_eq!(
            manager
                .begin_start_replay(original_session, &identity, "stable-start")
                .unwrap(),
            StartReplayDecision::InProgress
        );
        assert!(manager
            .complete_start_replay(
                original_session,
                &identity,
                "stable-start",
                sandbox_id,
                selected_mounts.clone(),
            )
            .unwrap());
        assert_eq!(
            manager
                .begin_start_replay(original_session, &identity, "stable-start")
                .unwrap(),
            StartReplayDecision::Replay {
                sandbox_id,
                mounts: selected_mounts,
            }
        );
        assert_eq!(
            manager
                .begin_start_replay(reconnect_session, &identity, "stable-start")
                .unwrap(),
            StartReplayDecision::Expired
        );

        assert!(manager.close(original_session, &identity).unwrap());
        assert_eq!(
            manager
                .begin_start_replay(reconnect_session, &identity, "stable-start")
                .unwrap(),
            StartReplayDecision::Expired
        );
    }

    #[test]
    fn failed_start_can_retry_but_disconnect_tombstones_pending_start() {
        let manager = SessionManager::new(QuotaLimits::default());
        let identity = ClientIdentityKey::for_test("user", "logon", 1);
        let first_session = manager.open(identity.clone()).unwrap();

        assert_eq!(
            manager
                .begin_start_replay(first_session, &identity, "retryable-start")
                .unwrap(),
            StartReplayDecision::Begin
        );
        assert!(manager
            .abandon_start_replay(first_session, &identity, "retryable-start")
            .unwrap());
        assert_eq!(
            manager
                .begin_start_replay(first_session, &identity, "retryable-start")
                .unwrap(),
            StartReplayDecision::Begin
        );
        assert!(manager.close(first_session, &identity).unwrap());

        let reconnect_session = manager.open(identity.clone()).unwrap();
        assert_eq!(
            manager
                .begin_start_replay(reconnect_session, &identity, "retryable-start")
                .unwrap(),
            StartReplayDecision::Expired
        );
        assert!(!manager
            .abandon_start_replay(reconnect_session, &identity, "retryable-start")
            .unwrap());
    }

    #[test]
    fn active_start_replay_records_are_bounded_without_eviction() {
        let manager = SessionManager::new(QuotaLimits::default());
        let identity = ClientIdentityKey::for_test("user", "logon", 1);
        let session = manager.open(identity.clone()).unwrap();

        for index in 0..MAX_START_REPLAY_RECORDS {
            assert_eq!(
                manager
                    .begin_start_replay(session, &identity, &format!("start-{index}"))
                    .unwrap(),
                StartReplayDecision::Begin
            );
        }
        assert_eq!(
            manager
                .begin_start_replay(session, &identity, "one-too-many")
                .unwrap(),
            StartReplayDecision::CapacityExceeded
        );
        assert_eq!(
            manager
                .begin_start_replay(session, &identity, "start-0")
                .unwrap(),
            StartReplayDecision::InProgress
        );
    }

    #[test]
    fn resources_are_owner_and_connection_bound() {
        let manager = SessionManager::new(QuotaLimits::default());
        let first = ClientIdentityKey::for_test("user-a", "logon-a", 1);
        let second = ClientIdentityKey::for_test("user-a", "logon-b", 2);
        let first_session = manager.open(first.clone()).unwrap();
        let second_session = manager.open(second.clone()).unwrap();
        let resource = manager
            .create_test_resource(first_session, &first, "secret".to_string())
            .unwrap();
        assert_eq!(
            manager.get_test_resource(first_session, &first, resource),
            Some("secret".to_string())
        );
        assert_eq!(
            manager.get_test_resource(first_session, &second, resource),
            None
        );
        assert_eq!(
            manager.get_test_resource(second_session, &second, resource),
            None
        );
        assert!(!manager
            .close_test_resource(first_session, &second, resource)
            .unwrap());
        assert!(manager
            .close_test_resource(first_session, &first, resource)
            .unwrap());
        assert!(manager
            .close_test_resource(first_session, &first, resource)
            .unwrap());
        assert_eq!(manager.counts(), (2, 0));
    }

    #[test]
    fn disconnect_cancels_and_releases_everything() {
        let manager = SessionManager::new(QuotaLimits::default());
        let identity = ClientIdentityKey::for_test("user", "logon", 1);
        let session = manager.open(identity.clone()).unwrap();
        manager
            .create_test_resource(session, &identity, "resource".to_string())
            .unwrap();
        let cancellation = manager.cancellation(session, &identity).unwrap();
        assert!(manager.close(session, &identity).unwrap());
        assert!(cancellation.is_cancelled());
        assert_eq!(manager.counts(), (0, 0));
    }

    #[test]
    fn global_drain_closes_every_identity_and_releases_quotas() {
        let manager = SessionManager::new(QuotaLimits::default());
        for (user, session_id) in [("user-a", 1), ("user-b", 2)] {
            let identity = ClientIdentityKey::for_test(user, user, session_id);
            let session = manager.open(identity.clone()).unwrap();
            manager
                .create_test_resource(session, &identity, "resource".to_string())
                .unwrap();
        }
        assert_eq!(manager.drain_all().unwrap(), 2);
        assert!(manager.is_empty());
        assert_eq!(manager.counts(), (0, 0));
    }

    #[cfg(windows)]
    #[test]
    fn cancelled_vm_preparation_releases_its_reservation() {
        let manager = SessionManager::new(QuotaLimits::default());
        let identity = ClientIdentityKey::for_test("user", "logon", 1);
        let session = manager.open(identity.clone()).unwrap();
        let handle = manager
            .reserve_managed_vm(
                session,
                &identity,
                SandboxResources {
                    cpus: 2,
                    memory_mib: 1024,
                    disk_mib: 4096,
                },
            )
            .unwrap();
        assert_eq!(manager.counts(), (1, 1));
        assert!(manager
            .cancel_managed_vm_reservation(session, &identity, handle)
            .unwrap());
        assert!(!manager
            .cancel_managed_vm_reservation(session, &identity, handle)
            .unwrap());
        assert_eq!(manager.counts(), (1, 0));
    }
}
