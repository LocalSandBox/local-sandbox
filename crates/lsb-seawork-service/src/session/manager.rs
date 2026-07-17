use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use super::quota::{QuotaBook, QuotaLimits};
use super::{CancellationToken, ResourceHandle};
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
    test_resources: HashMap<ResourceHandle, String>,
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
enum SandboxSlot {
    Preparing,
    Running(ManagedVm),
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
}

#[derive(Debug, Clone)]
pub struct SessionManager {
    state: Arc<Mutex<State>>,
}

impl SessionManager {
    pub fn new(limits: QuotaLimits) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                sessions: HashMap::new(),
                quotas: QuotaBook::new(limits),
            })),
        }
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
        let session = state
            .sessions
            .remove(&session_id)
            .context("session disappeared")?;
        #[cfg(windows)]
        let sandbox_count = session.sandboxes.len();
        #[cfg(not(windows))]
        let sandbox_count = 0;
        for _ in 0..session.test_resources.len() + sandbox_count {
            state.quotas.release_sandbox(session_id, identity);
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
        state.quotas.reserve_sandbox(session_id, identity)?;
        let handle = ResourceHandle::random()?;
        let session = state
            .sessions
            .get_mut(&session_id)
            .context("session disappeared")?;
        session.test_resources.insert(handle, value);
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
        session.test_resources.get(&handle).cloned()
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
        state.quotas.release_sandbox(session_id, identity);
        Ok(true)
    }

    pub fn counts(&self) -> (usize, usize) {
        self.state
            .lock()
            .map(|state| state.quotas.totals())
            .unwrap_or_default()
    }

    #[cfg(windows)]
    pub fn start_managed_vm(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        engine: &ServiceEngineConfig,
        spec: ManagedVmSpec,
    ) -> Result<ResourceHandle> {
        let (handle, cancellation) = {
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
            state.quotas.reserve_sandbox(session_id, identity)?;
            let handle = ResourceHandle::random()?;
            let session = state
                .sessions
                .get_mut(&session_id)
                .context("session disappeared")?;
            let cancellation = session.cancellation.clone();
            session.sandboxes.insert(handle, SandboxSlot::Preparing);
            (handle, cancellation)
        };

        let started = ManagedVm::start(engine, spec, cancellation);
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
        if &session.identity != identity || !session.sandboxes.contains_key(&handle) {
            if let Ok(vm) = started {
                let _ = vm.stop(std::time::Duration::from_secs(30));
            }
            bail!("session changed during VM startup");
        }
        match started {
            Ok(vm) => {
                session.sandboxes.insert(handle, SandboxSlot::Running(vm));
                Ok(handle)
            }
            Err(error) => {
                session.sandboxes.remove(&handle);
                state.quotas.release_sandbox(session_id, identity);
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
                let vm = match session.sandboxes.remove(&handle) {
                    Some(SandboxSlot::Running(vm)) => vm,
                    Some(slot @ SandboxSlot::Preparing) => {
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
                (vm, processes, watches)
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
        let result = vm.stop(timeout);
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        state.quotas.release_sandbox(session_id, identity);
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
            match session.sandboxes.get(&handle) {
                Some(SandboxSlot::Running(vm)) => vm.controller(),
                _ => return Ok(None),
            }
        };
        controller.exec(spec, timeout).map(Some)
    }

    #[cfg(windows)]
    pub fn file_managed_vm(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        handle: ResourceHandle,
        op: ManagedFileOp,
        timeout: Duration,
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
            match session.sandboxes.get(&handle) {
                Some(SandboxSlot::Running(vm)) => vm.controller(),
                _ => return Ok(None),
            }
        };
        controller.file(op, timeout).map(Some)
    }

    #[cfg(windows)]
    pub fn spawn_managed_process(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        sandbox_id: ResourceHandle,
        spec: ManagedExecSpec,
        timeout: Duration,
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
                match session.sandboxes.get(&sandbox_id) {
                    Some(SandboxSlot::Running(vm)) => vm.controller(),
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

        let started = controller.spawn(spec, timeout);
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let valid = state.sessions.get(&session_id).is_some_and(|session| {
            &session.identity == identity
                && session.processes.contains_key(&resource.id)
                && matches!(
                    session.sandboxes.get(&sandbox_id),
                    Some(SandboxSlot::Running(_))
                )
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
    pub fn start_managed_watch(
        &self,
        session_id: ResourceHandle,
        identity: &ClientIdentityKey,
        sandbox_id: ResourceHandle,
        path: String,
        recursive: bool,
        timeout: Duration,
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
                match session.sandboxes.get(&sandbox_id) {
                    Some(SandboxSlot::Running(vm)) => vm.controller(),
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

        let started = controller.watch(path, recursive, timeout);
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("session manager poisoned"))?;
        let valid = state.sessions.get(&session_id).is_some_and(|session| {
            &session.identity == identity
                && session.watches.contains_key(&resource.id)
                && matches!(
                    session.sandboxes.get(&sandbox_id),
                    Some(SandboxSlot::Running(_))
                )
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
    let cutoff = Instant::now() - RETIRED_HANDLE_TTL;
    while retired
        .front()
        .is_some_and(|(created, _)| *created < cutoff)
    {
        retired.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
