//! In-memory hypervisor used for development, UI work and tests.
//!
//! It never creates host files or executes commands. Production code should
//! surface the backend name prominently so mock VMs cannot be mistaken for
//! real domains.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::{
    validate_create_request, validate_resize_request, validate_snapshot_name, validate_vm_name,
    CreateVmRequest, Hypervisor, HypervisorCapabilities, HypervisorError, HypervisorResult, PowerAction,
    ReinstallVmRequest, ResizeVmRequest, SnapshotInfo, SnapshotRequest, VmImage, VmInfo, VmPowerState,
    VmStats, VncTarget,
};

const GIB: u64 = 1024 * 1024 * 1024;

#[derive(Clone)]
pub struct MockHypervisor {
    inner: Arc<RwLock<HashMap<String, MockVm>>>,
    next_vnc_port: Arc<AtomicU32>,
}

#[derive(Clone)]
struct MockVm {
    info: VmInfo,
    image: VmImage,
    cloud_init_iso: Option<PathBuf>,
    stats: VmStats,
    snapshots: Vec<SnapshotInfo>,
    vnc_port: u16,
    network_enabled: bool,
}

impl Default for MockHypervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl MockHypervisor {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            next_vnc_port: Arc::new(AtomicU32::new(5901)),
        }
    }

    /// Allows a metrics test or demo sampler to update cumulative counters.
    pub async fn set_stats(&self, name: &str, stats: VmStats) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        let mut vms = self.inner.write().await;
        let vm = vms
            .get_mut(name)
            .ok_or_else(|| HypervisorError::NotFound(name.to_owned()))?;
        vm.stats = stats;
        Ok(())
    }

    pub async fn network_enabled(&self, name: &str) -> HypervisorResult<bool> {
        validate_vm_name(name)?;
        self.inner
            .read()
            .await
            .get(name)
            .map(|vm| vm.network_enabled)
            .ok_or_else(|| HypervisorError::NotFound(name.to_owned()))
    }

    fn allocate_vnc_port(&self) -> HypervisorResult<u16> {
        let raw = self.next_vnc_port.fetch_add(1, Ordering::Relaxed);
        u16::try_from(raw)
            .map_err(|_| HypervisorError::BackendUnavailable("mock VNC port space is exhausted".into()))
    }

    async fn with_vm_mut<T>(
        &self,
        name: &str,
        apply: impl FnOnce(&mut MockVm) -> HypervisorResult<T>,
    ) -> HypervisorResult<T> {
        validate_vm_name(name)?;
        let mut vms = self.inner.write().await;
        let vm = vms
            .get_mut(name)
            .ok_or_else(|| HypervisorError::NotFound(name.to_owned()))?;
        apply(vm)
    }
}

#[async_trait]
impl Hypervisor for MockHypervisor {
    async fn capabilities(&self) -> HypervisorResult<HypervisorCapabilities> {
        Ok(HypervisorCapabilities {
            backend: "mock".into(),
            available: true,
            uri: None,
            hypervisor_version: Some("in-memory mock".into()),
            emulator_version: None,
            kvm_device_available: false,
            supports_live_resize: true,
            supports_snapshots: true,
            supports_vnc: true,
            detail: Some("No host resources are changed in mock mode".into()),
        })
    }

    async fn list_vms(&self) -> HypervisorResult<Vec<VmInfo>> {
        let vms = self.inner.read().await;
        let mut result: Vec<_> = vms.values().map(|vm| vm.info.clone()).collect();
        result.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(result)
    }

    async fn get_vm(&self, name: &str) -> HypervisorResult<VmInfo> {
        validate_vm_name(name)?;
        self.inner
            .read()
            .await
            .get(name)
            .map(|vm| vm.info.clone())
            .ok_or_else(|| HypervisorError::NotFound(name.to_owned()))
    }

    async fn create_vm(&self, request: CreateVmRequest) -> HypervisorResult<VmInfo> {
        validate_create_request(&request)?;
        let mut vms = self.inner.write().await;
        if vms.contains_key(&request.name) {
            return Err(HypervisorError::Conflict(format!(
                "VM '{}' already exists",
                request.name
            )));
        }

        let vnc_port = self.allocate_vnc_port()?;
        let info = VmInfo {
            name: request.name.clone(),
            uuid: Some(Uuid::new_v4()),
            state: if request.start {
                VmPowerState::Running
            } else {
                VmPowerState::ShutOff
            },
            vcpus: request.vcpus,
            memory_mib: request.memory_mib,
            disk_bytes: request.disk_gib.saturating_mul(GIB),
            disk_path: Some(PathBuf::from(format!(
                "/var/lib/vexa-vm/mock/{}.qcow2",
                request.name
            ))),
            interface_name: None,
            interface_type: Some("bridge".into()),
            bridge: request.bridge.or_else(|| Some("vexa-mock".into())),
            mac_address: Some(request.mac_address),
            autostart: request.autostart,
            persistent: true,
        };
        vms.insert(
            request.name,
            MockVm {
                info: info.clone(),
                image: request.image,
                cloud_init_iso: request.cloud_init_iso,
                stats: VmStats::default(),
                snapshots: Vec::new(),
                vnc_port,
                network_enabled: true,
            },
        );
        Ok(info)
    }

    async fn delete_vm(&self, name: &str, _delete_storage: bool) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        if self.inner.write().await.remove(name).is_none() {
            return Err(HypervisorError::NotFound(name.to_owned()));
        }
        Ok(())
    }

    async fn power(&self, name: &str, action: PowerAction) -> HypervisorResult<VmInfo> {
        self.with_vm_mut(name, |vm| {
            vm.info.state = match action {
                PowerAction::Start | PowerAction::Reboot | PowerAction::Reset => VmPowerState::Running,
                PowerAction::Shutdown | PowerAction::ForceOff => VmPowerState::ShutOff,
                PowerAction::Suspend => {
                    if !vm.info.state.is_active() {
                        return Err(HypervisorError::Conflict(
                            "a stopped VM cannot be suspended".into(),
                        ));
                    }
                    VmPowerState::Paused
                }
                PowerAction::Resume => {
                    if vm.info.state != VmPowerState::Paused {
                        return Err(HypervisorError::Conflict(
                            "only a paused VM can be resumed".into(),
                        ));
                    }
                    VmPowerState::Running
                }
            };
            Ok(vm.info.clone())
        })
        .await
    }

    async fn resize(&self, name: &str, request: ResizeVmRequest) -> HypervisorResult<VmInfo> {
        validate_resize_request(&request)?;
        self.with_vm_mut(name, |vm| {
            if let Some(vcpus) = request.vcpus {
                vm.info.vcpus = vcpus;
            }
            if let Some(memory_mib) = request.memory_mib {
                vm.info.memory_mib = memory_mib;
            }
            if let Some(disk_gib) = request.disk_gib {
                let requested_bytes = disk_gib.saturating_mul(GIB);
                if requested_bytes < vm.info.disk_bytes {
                    return Err(HypervisorError::InvalidInput(
                        "disk shrinking is not supported".into(),
                    ));
                }
                vm.info.disk_bytes = requested_bytes;
            }
            Ok(vm.info.clone())
        })
        .await
    }

    async fn set_memory_balloon(&self, name: &str, target_mib: u64) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        self.with_vm_mut(name, |vm| {
            if !vm.info.state.is_active() {
                return Err(HypervisorError::Conflict(
                    "memory ballooning requires a running VM".into(),
                ));
            }
            if !(256..=vm.info.memory_mib).contains(&target_mib) {
                return Err(HypervisorError::InvalidInput(
                    "live balloon target is outside the VM memory entitlement".into(),
                ));
            }
            Ok(())
        })
        .await
    }

    async fn reinstall(&self, name: &str, request: ReinstallVmRequest) -> HypervisorResult<VmInfo> {
        if !(1..=1024 * 1024).contains(&request.disk_gib) {
            return Err(HypervisorError::InvalidInput(
                "disk capacity must be between 1 GiB and 1 PiB".into(),
            ));
        }
        self.with_vm_mut(name, |vm| {
            vm.image = request.image;
            vm.cloud_init_iso = request.cloud_init_iso;
            vm.info.disk_bytes = request.disk_gib.saturating_mul(GIB);
            vm.info.state = if request.start {
                VmPowerState::Running
            } else {
                VmPowerState::ShutOff
            };
            vm.stats = VmStats::default();
            vm.snapshots.clear();
            Ok(vm.info.clone())
        })
        .await
    }

    async fn detach_seed_media(&self, name: &str, expected_source: &std::path::Path) -> HypervisorResult<()> {
        if !expected_source.is_absolute() {
            return Err(HypervisorError::InvalidInput(
                "seed media path must be absolute".into(),
            ));
        }
        self.with_vm_mut(name, |vm| match vm.cloud_init_iso.as_deref() {
            Some(source) if source == expected_source => {
                vm.cloud_init_iso = None;
                Ok(())
            }
            Some(_) => Err(HypervisorError::Conflict(
                "refusing to detach a CD-ROM that is not the expected seed".into(),
            )),
            None => Ok(()),
        })
        .await
    }

    async fn stats(&self, name: &str) -> HypervisorResult<VmStats> {
        validate_vm_name(name)?;
        self.inner
            .read()
            .await
            .get(name)
            .map(|vm| vm.stats.clone())
            .ok_or_else(|| HypervisorError::NotFound(name.to_owned()))
    }

    async fn set_network_enabled(&self, name: &str, enabled: bool) -> HypervisorResult<()> {
        self.with_vm_mut(name, |vm| {
            vm.network_enabled = enabled;
            Ok(())
        })
        .await
    }

    async fn create_snapshot(&self, name: &str, request: SnapshotRequest) -> HypervisorResult<SnapshotInfo> {
        validate_snapshot_name(&request.name)?;
        self.with_vm_mut(name, |vm| {
            if vm.snapshots.iter().any(|item| item.name == request.name) {
                return Err(HypervisorError::Conflict(format!(
                    "snapshot '{}' already exists",
                    request.name
                )));
            }
            for item in &mut vm.snapshots {
                item.current = false;
            }
            let snapshot = SnapshotInfo {
                name: request.name,
                description: request.description,
                created_at: Some(Utc::now()),
                current: true,
            };
            vm.snapshots.push(snapshot.clone());
            Ok(snapshot)
        })
        .await
    }

    async fn list_snapshots(&self, name: &str) -> HypervisorResult<Vec<SnapshotInfo>> {
        validate_vm_name(name)?;
        self.inner
            .read()
            .await
            .get(name)
            .map(|vm| vm.snapshots.clone())
            .ok_or_else(|| HypervisorError::NotFound(name.to_owned()))
    }

    async fn revert_snapshot(&self, name: &str, snapshot: &str) -> HypervisorResult<VmInfo> {
        validate_snapshot_name(snapshot)?;
        self.with_vm_mut(name, |vm| {
            if !vm.snapshots.iter().any(|item| item.name == snapshot) {
                return Err(HypervisorError::NotFound(format!("{name} snapshot {snapshot}")));
            }
            for item in &mut vm.snapshots {
                item.current = item.name == snapshot;
            }
            Ok(vm.info.clone())
        })
        .await
    }

    async fn delete_snapshot(&self, name: &str, snapshot: &str) -> HypervisorResult<()> {
        validate_snapshot_name(snapshot)?;
        self.with_vm_mut(name, |vm| {
            let original_len = vm.snapshots.len();
            vm.snapshots.retain(|item| item.name != snapshot);
            if vm.snapshots.len() == original_len {
                return Err(HypervisorError::NotFound(format!("{name} snapshot {snapshot}")));
            }
            if !vm.snapshots.iter().any(|item| item.current) {
                if let Some(last) = vm.snapshots.last_mut() {
                    last.current = true;
                }
            }
            Ok(())
        })
        .await
    }

    async fn vnc_target(&self, name: &str) -> HypervisorResult<VncTarget> {
        validate_vm_name(name)?;
        let vms = self.inner.read().await;
        let vm = vms
            .get(name)
            .ok_or_else(|| HypervisorError::NotFound(name.to_owned()))?;
        if vm.info.state != VmPowerState::Running {
            return Err(HypervisorError::Conflict(
                "VNC is available only while the VM is running".into(),
            ));
        }
        Ok(VncTarget {
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: vm.vnc_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypervisor::Firmware;

    fn create_request(name: &str) -> CreateVmRequest {
        CreateVmRequest {
            name: name.into(),
            vcpus: 2,
            memory_mib: 2048,
            initial_memory_mib: None,
            disk_gib: 20,
            image: VmImage::Blank,
            cloud_init_iso: None,
            guest_tools_socket: None,
            bridge: Some("virbr0".into()),
            tap_name: None,
            mac_address: "52:54:00:12:34:56".into(),
            network_limit_mbps: None,
            firmware: Firmware::Bios,
            machine_type: "q35".into(),
            autostart: false,
            start: true,
        }
    }

    #[tokio::test]
    async fn mock_lifecycle_is_deterministic() {
        let backend = MockHypervisor::new();
        let created = backend.create_vm(create_request("demo-1")).await.unwrap();
        assert_eq!(created.state, VmPowerState::Running);

        let stopped = backend.power("demo-1", PowerAction::ForceOff).await.unwrap();
        assert_eq!(stopped.state, VmPowerState::ShutOff);
        assert!(backend.vnc_target("demo-1").await.is_err());

        backend.delete_vm("demo-1", true).await.unwrap();
        assert!(backend.get_vm("demo-1").await.is_err());
    }

    #[tokio::test]
    async fn mock_seed_detach_requires_the_exact_source_and_is_idempotent() {
        let backend = MockHypervisor::new();
        let expected = PathBuf::from("/var/lib/vexa-vm/cloud-init/demo-seed.iso");
        let mut request = create_request("demo-seed");
        request.cloud_init_iso = Some(expected.clone());
        backend.create_vm(request).await.unwrap();

        assert!(backend
            .detach_seed_media(
                "demo-seed",
                std::path::Path::new("/var/lib/vexa-vm/cloud-init/other.iso"),
            )
            .await
            .is_err());
        backend.detach_seed_media("demo-seed", &expected).await.unwrap();
        backend.detach_seed_media("demo-seed", &expected).await.unwrap();
    }
}
