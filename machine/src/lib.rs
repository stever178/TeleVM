// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
//
// Copyright (c) 2023 China Telecom Co.,Ltd. All rights reserved.
// 
// Modifications made by China Telecom Co.,Ltd:
// - Modify micro machine for risc-v architecture
//
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

pub mod error;
pub mod micro_vm;

pub use crate::error::MachineError;
use std::collections::{BTreeMap, HashMap};
use std::fs::{remove_file, File};
use std::net::TcpListener;
use std::ops::Deref;
use std::os::unix::{io::AsRawFd, net::UnixListener};
use std::rc::Rc;
use std::sync::{Arc, Barrier, Condvar, Mutex, Weak};

use kvm_ioctls::VcpuFd;
use util::file::{lock_file, unlock_file};
use util::loop_context::read_fd;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

pub use micro_vm::LightMachine;

use address_space::{
    create_host_mmaps, set_host_memory_policy, AddressSpace, KvmMemoryListener, Region,
};
pub use anyhow::Result;
use anyhow::{anyhow, bail, Context};
use cpu::{ArchCPU, CPUBootConfig, CPUInterface, CPUTopology, CPU};
use devices::legacy::FwCfgOps;
#[cfg(target_arch = "riscv64")]
use devices::InterruptController;
use hypervisor::kvm::KVM_FDS;
use machine_manager::config::{
    parse_device_id, 
    parse_virtconsole, parse_virtio_serial, Incoming,
    MachineMemConfig, MigrateMode, SerialConfig, VmConfig, DriveFile
};
use machine_manager::{
    event_loop::EventLoop,
    machine::{KvmVmState, MachineInterface},
};
use migration::{MigrationManager, MigrationStatus};
use sysbus::SysBus;

use util::{
    arg_parser,
    loop_context::{EventNotifier, NotifierCallback, NotifierOperation},
};
use virtio::{Console, VirtioConsoleState, VirtioDevice, VirtioMmioDevice, VirtioMmioState};

pub trait MachineOps {
    /// Calculate the ranges of memory according to architecture.
    ///
    /// # Arguments
    ///
    /// * `mem_size` - memory size of VM.
    ///
    /// # Returns
    ///
    /// A array of ranges, it's element represents (start_addr, size).
    /// On x86_64, there is a gap ranged from (4G - 768M) to 4G, which will be skipped.
    fn arch_ram_ranges(&self, mem_size: u64) -> Vec<(u64, u64)>;

    fn load_boot_source(&self, fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>) -> Result<CPUBootConfig>;

    /// Init I/O & memory address space and mmap guest memory.
    ///
    /// # Arguments
    ///
    /// * `mem_config` - Memory setting.
    /// * `sys_io` - IO address space required for x86_64.
    /// * `sys_mem` - Memory address space.
    fn init_memory(
        &self,
        mem_config: &MachineMemConfig,
        sys_mem: &Arc<AddressSpace>,
        nr_cpus: u8,
    ) -> Result<()> {
        // KVM_CREATE_VM system call is invoked when KVM_FDS is used for the first time. The system
        // call registers some notifier functions in the KVM, which are frequently triggered when
        // doing memory prealloc.To avoid affecting memory prealloc performance, create_host_mmaps
        // needs to be invoked first.
        let mut mem_mappings = Vec::new();
        let migrate_info = self.get_migrate_info();
        if migrate_info.0 != MigrateMode::File {
            let ram_ranges = self.arch_ram_ranges(mem_config.mem_size);
            mem_mappings = create_host_mmaps(&ram_ranges, mem_config, nr_cpus)
                .with_context(|| "Failed to mmap guest ram.")?;
            set_host_memory_policy(&mem_mappings, &mem_config.mem_zones)
                .with_context(|| "Failed to set host memory NUMA policy.")?;
        }

        sys_mem
            .register_listener(Arc::new(Mutex::new(KvmMemoryListener::new(
                KVM_FDS.load().fd.as_ref().unwrap().get_nr_memslots() as u32,
            ))))
            .with_context(|| "Failed to register KVM listener for memory space.")?;

        if migrate_info.0 != MigrateMode::File {
            for mmap in mem_mappings.iter() {
                let base = mmap.start_address().raw_value();
                let size = mmap.size();
                sys_mem
                    .root()
                    .add_subregion(Region::init_ram_region(mmap.clone()), base)
                    .with_context(|| anyhow!(MachineError::RegMemRegionErr(base, size)))?;
            }
        }

        MigrationManager::register_memory_instance(sys_mem.clone());

        Ok(())
    }
    /// Init vcpu register with boot message.
    ///
    /// # Arguments
    ///
    /// * `vm` - `MachineInterface` to obtain functions cpu can use.
    /// * `nr_cpus` - The number of vcpus.
    /// * `fds` - File descriptors obtained by creating new Vcpu in KVM.
    /// * `boot_cfg` - Boot message generated by reading boot source to guest memory.
    fn init_vcpu(
        vm: Arc<Mutex<dyn MachineInterface + Send + Sync>>,
        nr_cpus: u8,
        topology: &CPUTopology,
        fds: &[Arc<VcpuFd>],
        boot_cfg: &Option<CPUBootConfig>,
    ) -> Result<Vec<Arc<CPU>>>
    where
        Self: Sized,
    {
        let mut cpus = Vec::<Arc<CPU>>::new();

        for vcpu_id in 0..nr_cpus {
            #[cfg(target_arch = "riscv64")]
            let arch_cpu = ArchCPU::new(u32::from(vcpu_id));
            let cpu = Arc::new(CPU::new(
                fds[vcpu_id as usize].clone(),
                vcpu_id,
                Arc::new(Mutex::new(arch_cpu)),
                vm.clone(),
            ));
            cpus.push(cpu.clone());
        }

        if let Some(boot_config) = boot_cfg {
            for cpu_index in 0..nr_cpus as usize {
                cpus[cpu_index as usize]
                    .realize(
                        boot_config,
                        topology,
                    )
                    .with_context(|| {
                        format!(
                            "Failed to realize arch cpu register/features for CPU {}/KVM",
                            cpu_index
                        )
                    })?;
            }
        }

        Ok(cpus)
    }

    /// Add interrupt controller.
    ///
    /// # Arguments
    ///
    /// * `vcpu_count` - The number of vcpu.
    fn init_interrupt_controller(
        &mut self,
        vcpu_fds: Vec<Arc<VcpuFd>>,
        vcpu_count: u32,
    ) -> Result<Arc<Mutex<InterruptController>>>;

    /// Add serial device.
    ///
    /// # Arguments
    ///
    /// * `config` - Device configuration.
    fn add_serial_device(
        &mut self,
        config: &SerialConfig,
        irq_chip: Arc<Mutex<InterruptController>>,
    ) -> Result<()>;

    /// Add block device.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM configuration.
    /// * `cfg_args` - Device configuration args.
    fn add_virtio_mmio_block(&mut self, _vm_config: &mut VmConfig, _cfg_args: &str) -> Result<()> {
        bail!("Virtio mmio devices Not supported!");
    }

    fn realize_virtio_mmio_device(
        &mut self,
        _dev: VirtioMmioDevice,
    ) -> Result<Arc<Mutex<VirtioMmioDevice>>> {
        bail!("Virtio mmio devices not supported");
    }

    fn get_sys_mem(&mut self) -> &Arc<AddressSpace>;

    fn get_vm_config(&self) -> Arc<Mutex<VmConfig>>;

    fn get_vm_state(&self) -> &Arc<(Mutex<KvmVmState>, Condvar)>;

    /// Get migration mode and path from VM config. There are four modes in total:
    /// Tcp, Unix, File and Unknown.
    fn get_migrate_info(&self) -> Incoming;

    /// Add net device.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM configuration.
    /// * `cfg_args` - Device configuration args.
    fn add_virtio_mmio_net(
        &mut self,
        _vm_config: &mut VmConfig,
        _cfg_args: &str,
        irq_chip: Arc<Mutex<InterruptController>>,
    ) -> Result<()> {
        bail!("Virtio mmio device Not supported!");
    }

    /// Add console device.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM configuration.
    /// * `cfg_args` - Device configuration args.
    fn add_virtio_console(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
        irq_chip: Arc<Mutex<InterruptController>>,
    ) -> Result<()> {
        let device_cfg = parse_virtconsole(vm_config, cfg_args)?;
        let sys_mem = self.get_sys_mem();
        let console = Arc::new(Mutex::new(Console::new(device_cfg.clone())));
        if let Some(serial) = &vm_config.virtio_serial {
            if serial.pci_bdf.is_none() {
                let device = VirtioMmioDevice::new(sys_mem, console.clone(), #[cfg(target_arch = "riscv64")] irq_chip.clone());
                MigrationManager::register_device_instance(
                    VirtioMmioState::descriptor(),
                    self.realize_virtio_mmio_device(device)
                        .with_context(|| anyhow!(MachineError::RlzVirtioMmioErr))?,
                    &device_cfg.id,
                );
            } else {
                // let virtio_serial_info = if let Some(serial_info) = &vm_config.virtio_serial {
                //     serial_info
                // } else {
                //     bail!("No virtio-serial-pci device configured for virtconsole");
                // };
                // // Reasonable, because for virtio-serial-pci device, the bdf has been checked.
                // let bdf = virtio_serial_info.pci_bdf.clone().unwrap();
                // let multi_func = virtio_serial_info.multifunction;
                // let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
                // let sys_mem = self.get_sys_mem().clone();
                // let virtio_pci_device = VirtioPciDevice::new(
                //     device_cfg.id.clone(),
                //     devfn,
                //     sys_mem,
                //     console.clone(),
                //     parent_bus,
                //     multi_func,
                // );
                // virtio_pci_device
                //     .realize()
                //     .with_context(|| "Failed  to add virtio pci console device")?;
            }
        } else {
            bail!("No virtio-serial-bus specified");
        }
        MigrationManager::register_device_instance(
            VirtioConsoleState::descriptor(),
            console,
            &device_cfg.id,
        );

        Ok(())
    }

    fn add_virtio_serial(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        parse_virtio_serial(vm_config, cfg_args)?;
        Ok(())
    }

    fn get_sys_bus(&mut self) -> &SysBus;

    
    /// Add peripheral devices.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM Configuration.
    fn add_devices(
        &mut self,
        vm_config: &mut VmConfig,
        #[cfg(target_arch = "riscv64")]
        irq_chip: Arc<Mutex<InterruptController>>,
    ) -> Result<()> {

        let cloned_vm_config = vm_config.clone();
        if let Some(serial) = cloned_vm_config.serial.as_ref() {
            self.add_serial_device(serial, #[cfg(target_arch = "riscv64")] irq_chip.clone())
                .with_context(|| anyhow!(MachineError::AddDevErr("serial".to_string())))?;
        }

        for dev in &cloned_vm_config.devices {
            let cfg_args = dev.1.as_str();
            // Check whether the device id exists to ensure device uniqueness.
            let id = parse_device_id(cfg_args)?;
            //self.check_device_id_existed(&id)
            //    .with_context(|| format!("Failed to check device id: config {}", cfg_args))?;
            match dev.0.as_str() {
                "virtio-blk-device" => {
                    self.add_virtio_mmio_block(vm_config, cfg_args)?;
                }
                "virtio-net-device" => {
                    self.add_virtio_mmio_net(vm_config, cfg_args, #[cfg(target_arch = "riscv64")] irq_chip.clone())?;
                }
                "virtio-serial-device" | "virtio-serial-pci" => {
                    self.add_virtio_serial(vm_config, cfg_args)?;
                }
                "virtconsole" => {
                    self.add_virtio_console(vm_config, cfg_args, #[cfg(target_arch = "riscv64")] irq_chip.clone())?;
                }
                _ => {
                    bail!("Unsupported device: {:?}", dev.0.as_str());
                }
            }
        }

        Ok(())
    }

    /// Register event notifier for power button of mainboard.
    ///
    /// # Arguments
    ///
    /// * `power_button` - Eventfd of the power button.
    fn register_power_event(&self, power_button: Arc<EventFd>) -> Result<()> {
        let button_fd = power_button.as_raw_fd();
        let power_button_handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
            read_fd(button_fd);
            None
        });
        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            button_fd,
            None,
            EventSet::IN,
            vec![power_button_handler],
        );
        trace_eventnotifier(&notifier);

        EventLoop::update_event(vec![notifier], None)
            .with_context(|| anyhow!(MachineError::RegNotifierErr))?;
        Ok(())
    }

    /// Get the drive backend files.
    fn get_drive_files(&self) -> Arc<Mutex<HashMap<String, DriveFile>>>;

    /// Fetch a cloned file from drive backend files.
    fn fetch_drive_file(&self, path: &str) -> Result<File> {
        let files = self.get_drive_files();
        let drive_files = files.lock().unwrap();
        VmConfig::fetch_drive_file(&drive_files, path)
    }

    /// Register a new drive backend file.
    fn register_drive_file(&self, path: &str, read_only: bool, direct: bool) -> Result<()> {
        let files = self.get_drive_files();
        let mut drive_files = files.lock().unwrap();
        VmConfig::add_drive_file(&mut drive_files, path, read_only, direct)?;

        // Lock the added file if VM is running.
        let drive_file = drive_files.get_mut(path).unwrap();
        let vm_state = self.get_vm_state().deref().0.lock().unwrap();
        if *vm_state == KvmVmState::Running && !drive_file.locked {
            if let Err(e) = lock_file(&drive_file.file, path, read_only) {
                VmConfig::remove_drive_file(&mut drive_files, path)?;
                return Err(e);
            }
            drive_file.locked = true;
        }
        Ok(())
    }

    /// Unregister a drive backend file.
    fn unregister_drive_file(&self, path: &str) -> Result<()> {
        let files = self.get_drive_files();
        let mut drive_files = files.lock().unwrap();
        VmConfig::remove_drive_file(&mut drive_files, path)
    }

    /// Active drive backend files. i.e., Apply lock.
    fn active_drive_files(&self) -> Result<()> {
        for drive_file in self.get_drive_files().lock().unwrap().values_mut() {
            if drive_file.locked {
                continue;
            }
            lock_file(&drive_file.file, &drive_file.path, drive_file.read_only)?;
            drive_file.locked = true;
        }
        Ok(())
    }

    /// Deactive drive backend files. i.e., Release lock.
    fn deactive_drive_files(&self) -> Result<()> {
        for drive_file in self.get_drive_files().lock().unwrap().values_mut() {
            if !drive_file.locked {
                continue;
            }
            unlock_file(&drive_file.file, &drive_file.path)?;
            drive_file.locked = false;
        }
        Ok(())
    }

    /// Realize the machine.
    ///
    /// # Arguments
    ///
    /// * `vm` - The machine structure.
    /// * `vm_config` - VM configuration.
    fn realize(vm: &Arc<Mutex<Self>>, vm_config: &mut VmConfig) -> Result<()>
    where
        Self: Sized;

    /// Run `LightMachine` with `paused` flag.
    ///
    /// # Arguments
    ///
    /// * `paused` - Flag for `paused` when `LightMachine` starts to run.
    fn run(&self, paused: bool) -> Result<()>;

    /// Start machine as `Running` or `Paused` state.
    ///
    /// # Arguments
    ///
    /// * `paused` - After started, paused all vcpu or not.
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm kvm vm state.
    fn vm_start(&self, paused: bool, cpus: &[Arc<CPU>], vm_state: &mut KvmVmState) -> Result<()>
    {
        if !paused {
            self.active_drive_files()?;
        }

        let nr_vcpus = cpus.len();
        let cpus_thread_barrier = Arc::new(Barrier::new((nr_vcpus + 1) as usize));
        for cpu_index in 0..nr_vcpus {
            let cpu_thread_barrier = cpus_thread_barrier.clone();
            let cpu = cpus[cpu_index as usize].clone();
            CPU::start(cpu, cpu_thread_barrier, paused)
                .with_context(|| format!("Failed to run vcpu{}", cpu_index))?;
        }

        if paused {
            *vm_state = KvmVmState::Paused;
        } else {
            *vm_state = KvmVmState::Running;
        }
        cpus_thread_barrier.wait();

        Ok(())
    }

    /// Pause VM as `Paused` state, sleepy all vcpu thread.
    ///
    /// # Arguments
    ///
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm kvm vm state.
    fn vm_pause(
        &self,
        cpus: &[Arc<CPU>],
        #[cfg(target_arch = "aarch64")] irq_chip: &Option<Arc<InterruptController>>,
        vm_state: &mut KvmVmState,
    ) -> Result<()> {
        self.deactive_drive_files()?;

        for (cpu_index, cpu) in cpus.iter().enumerate() {
           if let Err(e) = cpu.pause() {
                self.active_drive_files()?;
                return Err(anyhow!("Failed to pause vcpu{}, {:?}", cpu_index, e));
            }
        }

        #[cfg(target_arch = "aarch64")]
        irq_chip.as_ref().unwrap().stop();

        *vm_state = KvmVmState::Paused;

        Ok(())
    }

    /// Resume VM as `Running` state, awaken all vcpu thread.
    ///
    /// # Arguments
    ///
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm kvm vm state.
    fn vm_resume(&self, cpus: &[Arc<CPU>], vm_state: &mut KvmVmState) -> Result<()> {
        self.active_drive_files()?;

        for (cpu_index, cpu) in cpus.iter().enumerate() {
            if let Err(e) = cpu.resume() {
                self.deactive_drive_files()?;
                return Err(anyhow!("Failed to resume vcpu{}, {:?}", cpu_index, e));
            }
        }

        *vm_state = KvmVmState::Running;

        Ok(())
    }

    /// Destroy VM as `Shutdown` state, destroy vcpu thread.
    ///
    /// # Arguments
    ///
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm kvm vm state.
    fn vm_destroy(&self, cpus: &[Arc<CPU>], vm_state: &mut KvmVmState) -> Result<()> {
        for (cpu_index, cpu) in cpus.iter().enumerate() {
            cpu.destroy()
                .with_context(|| format!("Failed to destroy vcpu{}", cpu_index))?;
        }

        *vm_state = KvmVmState::Shutdown;

        Ok(())
    }

    /// Transfer VM state from `old` to `new`.
    ///
    /// # Arguments
    ///
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm kvm vm state.
    /// * `old_state` - Old vm state want to leave.
    /// * `new_state` - New vm state want to transfer to.
    fn vm_state_transfer(
        &self,
        cpus: &[Arc<CPU>],
        #[cfg(target_arch = "aarch64")] irq_chip: &Option<Arc<InterruptController>>,
        vm_state: &mut KvmVmState,
        old_state: KvmVmState,
        new_state: KvmVmState,
    ) -> Result<()> {
        use KvmVmState::*;

        if *vm_state != old_state {
            bail!("Vm lifecycle error: state check failed.");
        }

        match (old_state, new_state) {
            (Created, Running) => self
            .vm_start(false, cpus, vm_state)
                .with_context(|| "Failed to start vm.")?,
            (Running, Paused) => self
            .vm_pause(
                cpus,
                #[cfg(target_arch = "aarch64")]
                irq_chip,
                vm_state,
            )
            .with_context(|| "Failed to pause vm.")?,
            (Paused, Running) => self
            .vm_resume(cpus, vm_state)
                .with_context(|| "Failed to resume vm.")?,
            (_, Shutdown) => {
                self.vm_destroy(cpus, vm_state)
                    .with_context(|| "Failed to destroy vm.")?;
            }
            (_, _) => {
                bail!("Vm lifecycle error: this transform is illegal.");
            }
        }

        if *vm_state != new_state {
            bail!(
                "Vm lifecycle error: state '{:?} -> {:?}' transform failed.",
                old_state,
                new_state
            );
        }

        Ok(())
    }
}

/// Normal run or resume virtual machine from migration/snapshot  .
///
/// # Arguments
///
/// * `vm` - virtual machine that implement `MachineOps`.
/// * `cmd_args` - Command arguments from user.
pub fn vm_run(
    vm: &Arc<Mutex<dyn MachineOps + Send + Sync>>,
    cmd_args: &arg_parser::ArgMatches,
) -> Result<()> {
    let migrate = vm.lock().unwrap().get_migrate_info();
    if migrate.0 == MigrateMode::Unknown {
    vm.lock()
        .unwrap()
        .run(cmd_args.is_present("freeze_cpu"))
        .with_context(|| "Failed to start VM.")?;
     } else {
         start_incoming_migration(vm).with_context(|| "Failed to start migration.")?;
      }

    Ok(())
}


/// Start incoming migration from destination.
fn start_incoming_migration(vm: &Arc<Mutex<dyn MachineOps + Send + Sync>>) -> Result<()> {
    let (mode, path) = vm.lock().unwrap().get_migrate_info();
    match mode {
        MigrateMode::File => {
            MigrationManager::restore_snapshot(&path)
                .with_context(|| "Failed to restore snapshot")?;
            vm.lock()
                .unwrap()
                .run(false)
                .with_context(|| "Failed to start VM.")?;
        }
        MigrateMode::Unix => {
            let listener = UnixListener::bind(&path)?;
            let (mut sock, _) = listener.accept()?;
            remove_file(&path)?;

            MigrationManager::recv_migration(&mut sock)
                .with_context(|| "Failed to receive migration with unix mode")?;
            vm.lock()
                .unwrap()
                .run(false)
                .with_context(|| "Failed to start VM.")?;
            MigrationManager::finish_migration(&mut sock)
                .with_context(|| "Failed to finish migraton.")?;
        }
        MigrateMode::Tcp => {
            let listener = TcpListener::bind(&path)?;
            let mut sock = listener.accept().map(|(stream, _)| stream)?;

            MigrationManager::recv_migration(&mut sock)
                .with_context(|| "Failed to receive migration with tcp mode")?;
            vm.lock()
                .unwrap()
                .run(false)
                .with_context(|| "Failed to start VM.")?;
            MigrationManager::finish_migration(&mut sock)
                .with_context(|| "Failed to finish migraton.")?;
        }
        MigrateMode::Unknown => {
            bail!("Unknown migration mode");
        }
    }

    // End the migration and reset the mode.
    let locked_vm = vm.lock().unwrap();
    let vm_config = locked_vm.get_vm_config();
    if let Some((mode, _)) = vm_config.lock().unwrap().incoming.as_mut() {
        *mode = MigrateMode::Unknown;
    }

    Ok(())
}

/// Description of the trace for eventnotifier.
fn trace_eventnotifier(eventnotifier: &EventNotifier) {
    util::ftrace!(trace_eventnotifier, "{:#?}", eventnotifier);
}
