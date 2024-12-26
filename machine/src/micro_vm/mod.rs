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
pub use error::MicroVmError;
use util::aio::AioEngine;

pub mod mem_layout;

use super::Result as MachineResult;
use log::error;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Condvar, Mutex};
use std::vec::Vec;
use vmm_sys_util::eventfd::EventFd;

use address_space::{AddressSpace, GuestAddress, Region};
use boot_loader::{load_linux, BootLoaderConfig};
use cpu::{CPUBootConfig, CPUTopology, CpuLifecycleState, CpuTopology, CPU};
use devices::legacy::{FwCfgOps, Serial};
#[cfg(target_arch = "riscv64")]
use devices::{InterruptController, InterruptControllerConfig, MAX_DEVICES};
use hypervisor::kvm::KVM_FDS;
use kvm_ioctls::VcpuFd;
use machine_manager::config::{
    parse_blk, parse_incoming_uri, parse_net, BlkDevConfig, Incoming, MigrateMode,
};
use machine_manager::event;
use machine_manager::machine::{
    DeviceInterface, KvmVmState, MachineAddressInterface, MachineExternalInterface,
    MachineInterface, MachineLifecycle, MachineTestInterface, MigrateInterface,
};
use machine_manager::{
    config::{BootSource, ConfigCheck, NetworkInterfaceConfig, SerialConfig, VmConfig, DEFAULT_VIRTQUEUE_SIZE, DriveFile},
    qmp::{qmp_schema, QmpChannel, Response},
};
use mem_layout::{LayoutEntryType, MEM_LAYOUT};
use migration::{MigrationManager, MigrationStatus};
use sysbus::{SysBus, SysBusDevType, SysRes, IRQ_BASE, IRQ_MAX};
use util::device_tree::{self, CompileFDT, FdtBuilder};
use util::{loop_context::EventLoopManager, set_termi_canon_mode};
use virtio::{
    create_tap, Block, BlockState, Net, VhostKern, VirtioDevice, VirtioMmioDevice,
    VirtioMmioState, VirtioNetState,
};
use devices::pcie_mem::PcieMem;

use super::{error::MachineError, MachineOps};
use anyhow::{anyhow, bail, Context, Result};

// The replaceable block device maximum count.
const MMIO_REPLACEABLE_BLK_NR: usize = 1;
// The replaceable network device maximum count.
const MMIO_REPLACEABLE_NET_NR: usize = 1;

// The config of replaceable device.
#[derive(Debug)]
struct MmioReplaceableConfig {
    // Device id.
    id: String,
    // The dev_config of the related backend device.
    dev_config: Arc<dyn ConfigCheck>,
}

// The device information of replaceable device.
struct MmioReplaceableDevInfo {
    // The related MMIO device.
    device: Arc<Mutex<dyn VirtioDevice>>,
    // Device id.
    id: String,
    // Identify if this device is be used.
    used: bool,
}

impl fmt::Debug for MmioReplaceableDevInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmioReplaceableDevInfo")
            .field("device_type", &self.device.lock().unwrap().device_type())
            .field("id", &self.id)
            .field("used", &self.used)
            .finish()
    }
}

// The gather of config, info and count of all replaceable devices.
#[derive(Debug)]
struct MmioReplaceableInfo {
    // The arrays of all replaceable configs.
    configs: Arc<Mutex<Vec<MmioReplaceableConfig>>>,
    // The arrays of all replaceable device information.
    devices: Arc<Mutex<Vec<MmioReplaceableDevInfo>>>,
    // The count of block device which is plugin.
    block_count: usize,
    // The count of network device which is plugin.
    net_count: usize,
}

impl MmioReplaceableInfo {
    fn new() -> Self {
        MmioReplaceableInfo {
            configs: Arc::new(Mutex::new(Vec::new())),
            devices: Arc::new(Mutex::new(Vec::new())),
            block_count: 0_usize,
            net_count: 0_usize,
        }
    }
}

/// A wrapper around creating and using a kvm-based micro VM.
pub struct LightMachine {
    // `vCPU` topology, support sockets, cores, threads.
    cpu_topo: CpuTopology,
    // `vCPU` devices.
    cpus: Vec<Arc<CPU>>,
    // Memory address space.
    sys_mem: Arc<AddressSpace>,
    // System bus.
    sysbus: SysBus,
    // All replaceable device information.
    replaceable_info: MmioReplaceableInfo,
    // VM running state.
    vm_state: Arc<(Mutex<KvmVmState>, Condvar)>,
    // Vm boot_source config.
    boot_source: Arc<Mutex<BootSource>>,
    // VM power button, handle VM `Shutdown` event.
    power_button: Arc<EventFd>,
    // All configuration information of virtual machine.
    vm_config: Arc<Mutex<VmConfig>>,
    // Drive backend files.
    drive_files: Arc<Mutex<HashMap<String, DriveFile>>>,
}

impl LightMachine {
    /// Constructs a new `LightMachine`.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - Represents the configuration for VM.
    pub fn new(vm_config: &VmConfig) -> MachineResult<Self> {
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value()))
            .with_context(|| anyhow!(MachineError::CrtMemSpaceErr))?;
        let free_irqs: (i32, i32) = (IRQ_BASE, IRQ_MAX);
        let mmio_region: (u64, u64) = (
            MEM_LAYOUT[LayoutEntryType::Mmio as usize].0,
            MEM_LAYOUT[LayoutEntryType::Mmio as usize + 1].0,
        );
        let sysbus = SysBus::new(
            &sys_mem,
            free_irqs,
            mmio_region,
        );

        // Machine state init
        let vm_state = Arc::new((Mutex::new(KvmVmState::Created), Condvar::new()));
        let power_button =
            Arc::new(EventFd::new(libc::EFD_NONBLOCK).with_context(|| {
                anyhow!(MachineError::InitEventFdErr("power_button".to_string()))
            })?);

        Ok(LightMachine {
            cpu_topo: CpuTopology::new(
                vm_config.machine_config.nr_cpus,
                vm_config.machine_config.nr_sockets,
                vm_config.machine_config.nr_dies,
                vm_config.machine_config.nr_clusters,
                vm_config.machine_config.nr_cores,
                vm_config.machine_config.nr_threads,
                vm_config.machine_config.max_cpus,
            ),
            cpus: Vec::new(),
            sys_mem,
            sysbus,
            replaceable_info: MmioReplaceableInfo::new(),
            boot_source: Arc::new(Mutex::new(vm_config.clone().boot_source)),
            vm_state,
            power_button,
            vm_config: Arc::new(Mutex::new(vm_config.clone())),
            drive_files: Arc::new(Mutex::new(vm_config.init_drive_files()?)),
        })
    }

    fn create_replaceable_devices(&mut self, 
        #[cfg(target_arch = "riscv64")]
        irq_chip: Arc<Mutex<InterruptController>>,
    ) -> Result<()> {
        let mut rpl_devs: Vec<VirtioMmioDevice> = Vec::new();
        for id in 0..MMIO_REPLACEABLE_BLK_NR {
            let block = Arc::new(Mutex::new(Block::new(
                BlkDevConfig::default(),
                self.get_drive_files(),
            )));
            let virtio_mmio = VirtioMmioDevice::new(&self.sys_mem, block.clone(), #[cfg(target_arch = "riscv64")] irq_chip.clone());
            rpl_devs.push(virtio_mmio);

            MigrationManager::register_device_instance(
                BlockState::descriptor(),
                block,
                &id.to_string(),
            );
        }
        for id in 0..MMIO_REPLACEABLE_NET_NR {
            let net = Arc::new(Mutex::new(Net::default()));
            let virtio_mmio = VirtioMmioDevice::new(&self.sys_mem, net.clone(), #[cfg(target_arch = "riscv64")] irq_chip.clone());
            rpl_devs.push(virtio_mmio);

            MigrationManager::register_device_instance(
                VirtioNetState::descriptor(),
                net,
                &id.to_string(),
            );
        }

        let mut region_base = self.sysbus.min_free_base;
        let region_size = MEM_LAYOUT[LayoutEntryType::Mmio as usize].1;
        for (id, dev) in rpl_devs.into_iter().enumerate() {
            self.replaceable_info
                .devices
                .lock()
                .unwrap()
                .push(MmioReplaceableDevInfo {
                    device: dev.device.clone(),
                    id: id.to_string(),
                    used: false,
                });

            MigrationManager::register_transport_instance(
                VirtioMmioState::descriptor(),
                VirtioMmioDevice::realize(
                    dev,
                    &mut self.sysbus,
                    region_base,
                    MEM_LAYOUT[LayoutEntryType::Mmio as usize].1,
                    #[cfg(target_arch = "x86_64")]
                    &self.boot_source,
                )
                .with_context(|| anyhow!(MicroVmError::RlzVirtioMmioErr))?,
                &id.to_string(),
            );
            region_base += region_size;
        }
        self.sysbus.min_free_base = region_base;
        Ok(())
    }

    fn fill_replaceable_device(
        &mut self,
        id: &str,
        dev_config: Arc<dyn ConfigCheck>,
        index: usize,
    ) -> Result<()> {
        let mut replaceable_devices = self.replaceable_info.devices.lock().unwrap();
        if let Some(device_info) = replaceable_devices.get_mut(index) {
            if device_info.used {
                bail!("{}: index {} is already used.", id, index);
            }

            device_info.id = id.to_string();
            device_info.used = true;
            device_info
                .device
                .lock()
                .unwrap()
                .update_config(Some(dev_config.clone()))
                .with_context(|| anyhow!(MicroVmError::UpdCfgErr(id.to_string())))?;
        }

        self.add_replaceable_config(id, dev_config)?;
        Ok(())
    }

    fn add_replaceable_config(&self, id: &str, dev_config: Arc<dyn ConfigCheck>) -> Result<()> {
        let mut configs_lock = self.replaceable_info.configs.lock().unwrap();
        let limit = MMIO_REPLACEABLE_BLK_NR + MMIO_REPLACEABLE_NET_NR;
        if configs_lock.len() >= limit {
            return Err(anyhow!(MicroVmError::RplDevLmtErr("".to_string(), limit)));
        }

        for config in configs_lock.iter() {
            if config.id == id {
                bail!("{} is already registered.", id);
            }
        }

        let config = MmioReplaceableConfig {
            id: id.to_string(),
            dev_config,
        };

        trace_mmio_replaceable_config(&config);
        configs_lock.push(config);
        Ok(())
    }

    fn add_replaceable_device(&self, id: &str, driver: &str, slot: usize) -> Result<()> {
        // Find the configuration by id.
        let configs_lock = self.replaceable_info.configs.lock().unwrap();
        let mut dev_config = None;
        for config in configs_lock.iter() {
            if config.id == id {
                dev_config = Some(config.dev_config.clone());
            }
        }
        if dev_config.is_none() {
            bail!("Failed to find device configuration.");
        }

        // Sanity check for config, driver and slot.
        let cfg_any = dev_config.as_ref().unwrap().as_any();
        let index = if driver.contains("net") {
            if slot >= MMIO_REPLACEABLE_NET_NR {
                return Err(anyhow!(MicroVmError::RplDevLmtErr(
                    "net".to_string(),
                    MMIO_REPLACEABLE_NET_NR
                )));
            }
            if cfg_any.downcast_ref::<NetworkInterfaceConfig>().is_none() {
                return Err(anyhow!(MicroVmError::DevTypeErr("net".to_string())));
            }
            slot + MMIO_REPLACEABLE_BLK_NR
        } else if driver.contains("blk") {
            if slot >= MMIO_REPLACEABLE_BLK_NR {
                return Err(anyhow!(MicroVmError::RplDevLmtErr(
                    "block".to_string(),
                    MMIO_REPLACEABLE_BLK_NR
                )));
            }
            if cfg_any.downcast_ref::<BlkDevConfig>().is_none() {
                return Err(anyhow!(MicroVmError::DevTypeErr("blk".to_string())));
            }
            slot
        } else {
            bail!("Unsupported replaceable device type.");
        };

        // Find the replaceable device and replace it.
        let mut replaceable_devices = self.replaceable_info.devices.lock().unwrap();
        if let Some(device_info) = replaceable_devices.get_mut(index) {
            if device_info.used {
                bail!("The slot {} is occupied already.", slot);
            }

            device_info.id = id.to_string();
            device_info.used = true;
            device_info
                .device
                .lock()
                .unwrap()
                .update_config(dev_config)
                .with_context(|| anyhow!(MicroVmError::UpdCfgErr(id.to_string())))?;
        }
        Ok(())
    }

    fn del_replaceable_device(&self, id: &str) -> Result<String> {
        // find the index of configuration by name and remove it
        let mut is_exist = false;
        let mut configs_lock = self.replaceable_info.configs.lock().unwrap();
        for (index, config) in configs_lock.iter().enumerate() {
            if config.id == id {
                if let Some(blkconf) = config.dev_config.as_any().downcast_ref::<BlkDevConfig>() {
                    self.unregister_drive_file(&blkconf.path_on_host)?;
                }
                configs_lock.remove(index);
                is_exist = true;
                break;
            }
        }

        // set the status of the device to 'unused'
        let mut replaceable_devices = self.replaceable_info.devices.lock().unwrap();
        for device_info in replaceable_devices.iter_mut() {
            if device_info.id == id {
                device_info.id = "".to_string();
                device_info.used = false;
                device_info
                    .device
                    .lock()
                    .unwrap()
                    .update_config(None)
                    .with_context(|| anyhow!(MicroVmError::UpdCfgErr(id.to_string())))?;
            }
        }

        if !is_exist {
            bail!("Device {} not found", id);
        }
        Ok(id.to_string())
    }
}

impl MachineOps for LightMachine {
    fn arch_ram_ranges(&self, mem_size: u64) -> Vec<(u64, u64)> {
        #[allow(unused_mut)]
        let mut ranges: Vec<(u64, u64)>;

        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        {
            let mem_start = MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
            ranges = vec![(mem_start, mem_size)];
        }
        #[cfg(target_arch = "x86_64")]
        {
            let gap_start = MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0
                + MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1;
            ranges = vec![(0, std::cmp::min(gap_start, mem_size))];
            if mem_size > gap_start {
                let gap_end = MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0;
                ranges.push((gap_end, mem_size - gap_start));
            }
        }
        ranges
    }

    #[cfg(target_arch = "riscv64")]
    fn init_interrupt_controller(
        &mut self,
        vcpu_fds: Vec<Arc<VcpuFd>>,
        vcpu_count: u32,
    ) -> MachineResult<Arc<Mutex<InterruptController>>> {
        let intc_conf = InterruptControllerConfig {
            version: None,
            vcpu_count,
            region_base: MEM_LAYOUT[LayoutEntryType::Plic as usize].0,
            region_size: MEM_LAYOUT[LayoutEntryType::Plic as usize].1,
        };

        let irq_chip = InterruptController::new(vcpu_fds, &mut self.sysbus, &intc_conf)?;
        Ok(Arc::new(Mutex::new(irq_chip)))
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    fn load_boot_source(
        &self,
        fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>,
    ) -> MachineResult<CPUBootConfig> {
        let mut boot_source = self.boot_source.lock().unwrap();
        let initrd = boot_source.initrd.as_ref().map(|b| b.initrd_file.clone());

        let bootloader_config = BootLoaderConfig {
            kernel: boot_source.kernel_file.clone(),
            initrd,
            mem_start: MEM_LAYOUT[LayoutEntryType::Mem as usize].0,
        };
        let layout = load_linux(&bootloader_config, &self.sys_mem, fwcfg)
            .with_context(|| anyhow!(MachineError::LoadKernErr))?;
        if let Some(rd) = &mut boot_source.initrd {
            rd.initrd_addr = layout.initrd_start;
            rd.initrd_size = layout.initrd_size;
        }

        Ok(CPUBootConfig {
            fdt_addr: layout.dtb_start,
            boot_pc: layout.boot_pc,
        })
    }

    fn realize_virtio_mmio_device(
        &mut self,
        dev: VirtioMmioDevice,
    ) -> MachineResult<Arc<Mutex<VirtioMmioDevice>>> {
        let region_base = self.sysbus.min_free_base;
        let region_size = MEM_LAYOUT[LayoutEntryType::Mmio as usize].1;
        let realized_virtio_mmio_device = VirtioMmioDevice::realize(
            dev,
            &mut self.sysbus,
            region_base,
            region_size,
        )
        .with_context(|| anyhow!(MicroVmError::RlzVirtioMmioErr))?;
        self.sysbus.min_free_base += region_size;
        Ok(realized_virtio_mmio_device)
    }

    fn get_sys_mem(&mut self) -> &Arc<AddressSpace> {
        &self.sys_mem
    }

    fn get_vm_config(&self) -> Arc<Mutex<VmConfig>> {
        self.vm_config.clone()
    }

    fn get_vm_state(&self) -> &Arc<(Mutex<KvmVmState>, Condvar)> {
        &self.vm_state
    }

    fn get_migrate_info(&self) -> Incoming {
        if let Some((mode, path)) = self.get_vm_config().lock().unwrap().incoming.as_ref() {
            return (*mode, path.to_string());
        }

        (MigrateMode::Unknown, String::new())
    }

    fn get_sys_bus(&mut self) -> &SysBus {
        &self.sysbus
    }

    fn add_serial_device(
        &mut self,
        config: &SerialConfig,
        #[cfg(target_arch = "riscv64")]
        irq_chip: Arc<Mutex<InterruptController>>,
    ) -> MachineResult<()> {
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        let region_base: u64 = MEM_LAYOUT[LayoutEntryType::Uart as usize].0;
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        let region_size: u64 = MEM_LAYOUT[LayoutEntryType::Uart as usize].1;

        let serial = Serial::new(config.clone(), #[cfg(target_arch = "riscv64")] irq_chip.clone());
        serial
            .realize(
                &mut self.sysbus,
                region_base,
                region_size,
                &self.boot_source,
            )
            .with_context(|| "Failed to realize serial device.")?;
        Ok(())
    }

    fn add_virtio_mmio_net(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
        #[cfg(target_arch = "riscv64")]
        irq_chip: Arc<Mutex<InterruptController>>,
    ) -> MachineResult<()> {
        let device_cfg = parse_net(vm_config, cfg_args)?;
        if device_cfg.vhost_type.is_some() {
            let net = Arc::new(Mutex::new(VhostKern::Net::new(&device_cfg, &self.sys_mem)));
            let device = VirtioMmioDevice::new(&self.sys_mem, net, #[cfg(target_arch = "riscv64")] irq_chip.clone());
            self.realize_virtio_mmio_device(device)?;
        } else {
            let index = MMIO_REPLACEABLE_BLK_NR + self.replaceable_info.net_count;
            if index >= MMIO_REPLACEABLE_BLK_NR + MMIO_REPLACEABLE_NET_NR {
                bail!(
                    "A maximum of {} net replaceable devices are supported.",
                    MMIO_REPLACEABLE_NET_NR
                );
            }
            self.fill_replaceable_device(&device_cfg.id, Arc::new(device_cfg.clone()), index)?;
            self.replaceable_info.net_count += 1;
        }
        Ok(())
    }

    fn add_virtio_mmio_block(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
    ) -> MachineResult<()> {
        let device_cfg = parse_blk(vm_config, cfg_args, None)?;
        if self.replaceable_info.block_count >= MMIO_REPLACEABLE_BLK_NR {
            bail!(
                "A maximum of {} block replaceable devices are supported.",
                MMIO_REPLACEABLE_BLK_NR
            );
        }
        let index = self.replaceable_info.block_count;
        self.fill_replaceable_device(&device_cfg.id, Arc::new(device_cfg.clone()), index)?;
        self.replaceable_info.block_count += 1;
        Ok(())
    }

    // fn syscall_whitelist(&self) -> Vec<BpfRule> {
    //     syscall_whitelist()
    // }
    fn get_drive_files(&self) -> Arc<Mutex<HashMap<String, DriveFile>>> {
        self.drive_files.clone()
    }


    fn realize(vm: &Arc<Mutex<Self>>, vm_config: &mut VmConfig) -> MachineResult<()> {
        let mut locked_vm = vm.lock().unwrap();

        // 创建并注册PcieMem设备
        let pcie_ecam = Arc::new(Mutex::new(PcieMem::new(
            MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].1
        )));
        locked_vm.sysbus.attach_device(
            &pcie_ecam,
            MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].0,
            MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].1,
        )?;

        let pcie_mmio = Arc::new(Mutex::new(PcieMem::new(
            MEM_LAYOUT[LayoutEntryType::PcieMmio as usize].1
        )));
        locked_vm.sysbus.attach_device(
            &pcie_mmio,
            MEM_LAYOUT[LayoutEntryType::PcieMmio as usize].0,
            MEM_LAYOUT[LayoutEntryType::PcieMmio as usize].1,
        )?;

        //trace for lightmachine
        trace_sysbus(&locked_vm.sysbus);
        trace_vm_state(&locked_vm.vm_state);

        locked_vm.init_memory(
            &vm_config.machine_config.mem_config,
            &locked_vm.sys_mem,
            vm_config.machine_config.nr_cpus,
        )?;

        let migrate_info = locked_vm.get_migrate_info();

        let mut vcpu_fds = vec![];
        for vcpu_id in 0..vm_config.machine_config.nr_cpus {
            vcpu_fds.push(Arc::new(
                KVM_FDS
                    .load()
                    .vm_fd
                    .as_ref()
                    .unwrap()
                    .create_vcpu(vcpu_id as u64)?,
            ));
        }


        #[cfg(target_arch = "riscv64")]
        let irq_chip = locked_vm.init_interrupt_controller(
            vcpu_fds.clone(),
            u32::from(vm_config.machine_config.nr_cpus),
        )?;

        locked_vm
            .create_replaceable_devices(#[cfg(target_arch = "riscv64")] irq_chip.clone())
            .with_context(|| "Failed to create replaceable devices.")?;
        locked_vm.add_devices(vm_config, #[cfg(target_arch = "riscv64")] irq_chip.clone())?;
        trace_replaceable_info(&locked_vm.replaceable_info);

        let boot_config = Some(locked_vm.load_boot_source(None)?);
        // if migrate_info.0 == MigrateMode::Unknown {
        //     Some(locked_vm.load_boot_source(None)?)
        // } else {
        //     None
        // };

        let topology = CPUTopology::new().set_topology((
            vm_config.machine_config.nr_threads,
            vm_config.machine_config.nr_cores,
            vm_config.machine_config.nr_dies,
        ));
        trace_cpu_topo(&topology);

        #[cfg(target_arch = "aarch64")]
        let cpu_config = if migrate_info.0 == MigrateMode::Unknown {
            Some(locked_vm.load_cpu_features(vm_config)?)
        } else {
            None
        };

        // vCPUs init,and apply CPU features (for aarch64)
        locked_vm.cpus.extend(<Self as MachineOps>::init_vcpu(
            vm.clone(),
            vm_config.machine_config.nr_cpus,
            &topology,
            &vcpu_fds,
            &boot_config,
        )?);

        if let Some(boot_cfg) = boot_config {
            let mut fdt_helper = FdtBuilder::new();
            locked_vm
                .generate_fdt_node(&mut fdt_helper)
                .with_context(|| anyhow!(MachineError::GenFdtErr))?;
            let fdt_vec = fdt_helper.finish()?;
            locked_vm
                .sys_mem
                .write(
                    &mut fdt_vec.as_slice(),
                    GuestAddress(boot_cfg.fdt_addr as u64),
                    fdt_vec.len() as u64,
                )
                .with_context(|| {
                    anyhow!(MachineError::WrtFdtErr(boot_cfg.fdt_addr, fdt_vec.len()))
                })?;
        }
        locked_vm
            .register_power_event(locked_vm.power_button.clone())
            .with_context(|| anyhow!(MachineError::InitEventFdErr("power_button".to_string())))?;

        Ok(())
    }

    fn run(&self, paused: bool) -> MachineResult<()> {
        self.vm_start(paused, &self.cpus, &mut self.vm_state.0.lock().unwrap())
    }
}

// impl LightMachine {
//     fn init_pci_host(&self) -> Result<()> {
//         let pcie_ecam_base = MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].0;
//         let pcie_ecam_size = MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].1;
//         let pcie_mmio_base = MEM_LAYOUT[LayoutEntryType::PcieMmio as usize].0;
//         let pcie_mmio_size = MEM_LAYOUT[LayoutEntryType::PcieMmio as usize].1;

//         // 初始化PCI主机控制器
//         let pci_host = PciHost::new(
//             &self.sys_mem,
//             pcie_ecam_base,
//             pcie_ecam_size,
//             pcie_mmio_base, 
//             pcie_mmio_size
//         )?;

//         // 注册到系统总线
//         self.sysbus.attach_device(pci_host)?;
        
//         Ok(())
//     }
// }

impl MachineLifecycle for LightMachine {
    fn pause(&self) -> bool {
        if self.notify_lifecycle(KvmVmState::Running, KvmVmState::Paused) {
            event!(Stop);
            true
        } else {
            false
        }
    }

    fn resume(&self) -> bool {
        if !self.notify_lifecycle(KvmVmState::Paused, KvmVmState::Running) {
            return false;
        }

        event!(Resume);
        true
    }

    fn destroy(&self) -> bool {
        let vmstate = {
            let state = self.vm_state.deref().0.lock().unwrap();
            *state
        };

        if !self.notify_lifecycle(vmstate, KvmVmState::Shutdown) {
            return false;
        }

        if self.power_button.write(1).is_err() {
            error!("Micro vm write power button failed");
            return false;
        }
        true
    }


    fn reset(&mut self) -> bool {
        // For micro vm, the reboot command is equivalent to the shutdown command.
        for cpu in self.cpus.iter() {
            let (cpu_state, _) = cpu.state();
            *cpu_state.lock().unwrap() = CpuLifecycleState::Stopped;
        }

        self.destroy()
    }

    fn notify_lifecycle(&self, old: KvmVmState, new: KvmVmState) -> bool {
        self.vm_state_transfer(
            &self.cpus,
            &mut self.vm_state.0.lock().unwrap(),
            old,
            new,
        )
        .is_ok()
    }
}

impl MachineAddressInterface for LightMachine {
    fn mmio_read(&self, addr: u64, mut data: &mut [u8]) -> bool {
        let length = data.len() as u64;
        self.sys_mem
            .read(&mut data, GuestAddress(addr), length)
            .is_ok()
    }

    fn mmio_write(&self, addr: u64, mut data: &[u8]) -> bool {
        let count = data.len() as u64;
        self.sys_mem
            .write(&mut data, GuestAddress(addr), count)
            .is_ok()
    }
}

impl DeviceInterface for LightMachine {
    fn query_status(&self) -> Response {
        //todo
        let vmstate = self.vm_state.deref().0.lock().unwrap();
        let qmp_state = match *vmstate {
            KvmVmState::Running => qmp_schema::StatusInfo {
                singlestep: false,
                running: true,
                status: qmp_schema::RunState::running,
            },
            KvmVmState::Paused => qmp_schema::StatusInfo {
                singlestep: false,
                running: false,
                status: qmp_schema::RunState::paused,
            },
            _ => Default::default(),
        };
     
        Response::create_response(serde_json::to_value(&qmp_state).unwrap(), None)
    }

    fn query_cpus(&self) -> Response {
        let mut cpu_vec: Vec<serde_json::Value> = Vec::new();
        for cpu_index in 0..self.cpu_topo.max_cpus {
            if self.cpu_topo.get_mask(cpu_index as usize) == 1 {
                let thread_id = self.cpus[cpu_index as usize].tid();
                let cpu_instance = self.cpu_topo.get_topo_instance_for_qmp(cpu_index as usize);
                let cpu_common = qmp_schema::CpuInfoCommon {
                    current: true,
                    qom_path: String::from("/machine/unattached/device[")
                        + &cpu_index.to_string()
                        + "]",
                    halted: false,
                    props: Some(cpu_instance),
                    CPU: cpu_index as isize,
                    thread_id: thread_id as isize,
                };
                #[cfg(target_arch = "x86_64")]
                {
                    let cpu_info = qmp_schema::CpuInfo::x86 {
                        common: cpu_common,
                        x86: qmp_schema::CpuInfoX86 {},
                    };
                    cpu_vec.push(serde_json::to_value(cpu_info).unwrap());
                }
                #[cfg(target_arch = "aarch64")]
                {
                    let cpu_info = qmp_schema::CpuInfo::Arm {
                        common: cpu_common,
                        arm: qmp_schema::CpuInfoArm {},
                    };
                    cpu_vec.push(serde_json::to_value(cpu_info).unwrap());
                }
                #[cfg(target_arch = "riscv64")]
                {
                    let cpu_info = qmp_schema::CpuInfo::RISCV {
                        common: cpu_common,
                        arm: qmp_schema::CpuInfoRISCV {},
                    };
                    cpu_vec.push(serde_json::to_value(cpu_info).unwrap());
                }
            }
        }
        Response::create_response(cpu_vec.into(), None)
    }

    fn query_hotpluggable_cpus(&self) -> Response {
        let mut hotplug_vec: Vec<serde_json::Value> = Vec::new();
        #[cfg(target_arch = "riscv64")]
        let cpu_type = String::from("host-riscv64-cpu");

        for cpu_index in 0..self.cpu_topo.max_cpus {
            if self.cpu_topo.get_mask(cpu_index as usize) == 0 {
                let cpu_instance = self.cpu_topo.get_topo_instance_for_qmp(cpu_index as usize);
                let hotpluggable_cpu = qmp_schema::HotpluggableCPU {
                    type_: cpu_type.clone(),
                    vcpus_count: 1,
                    props: cpu_instance,
                    qom_path: None,
                };
                hotplug_vec.push(serde_json::to_value(hotpluggable_cpu).unwrap());
            } else {
                let cpu_instance = self.cpu_topo.get_topo_instance_for_qmp(cpu_index as usize);
                let hotpluggable_cpu = qmp_schema::HotpluggableCPU {
                    type_: cpu_type.clone(),
                    vcpus_count: 1,
                    props: cpu_instance,
                    qom_path: Some(
                        String::from("/machine/unattached/device[") + &cpu_index.to_string() + "]",
                    ),
                };
                hotplug_vec.push(serde_json::to_value(hotpluggable_cpu).unwrap());
            }
        }
        Response::create_response(hotplug_vec.into(), None)
    }

    fn balloon(&self, value: u64) -> Response {
        // if qmp_balloon(value) {
        //     return Response::create_empty_response();
        // }
        Response::create_error_response(
            qmp_schema::QmpErrorClass::DeviceNotActive(
                "No balloon device has been activated".to_string(),
            ),
            None,
        )
    }

    fn query_balloon(&self) -> Response {
        // if let Some(actual) = qmp_query_balloon() {
        //     let ret = qmp_schema::BalloonInfo { actual };
        //     return Response::create_response(serde_json::to_value(&ret).unwrap(), None);
        // }
        Response::create_error_response(
            qmp_schema::QmpErrorClass::DeviceNotActive(
                "No balloon device has been activated".to_string(),
            ),
            None,
        )
    }

    fn device_add(&mut self, args: Box<qmp_schema::DeviceAddArgument>) -> Response {
        // get slot of bus by addr or lun
        let mut slot = 0;
        if let Some(addr) = args.addr {
            let slot_str = addr.as_str().trim_start_matches("0x");

            if let Ok(n) = usize::from_str_radix(slot_str, 16) {
                slot = n;
            }
        } else if let Some(lun) = args.lun {
            slot = lun + 1;
        }

        match self.add_replaceable_device(&args.id, &args.driver, slot) {
            Ok(()) => Response::create_empty_response(),
            Err(ref e) => {
                error!("{:?}", e);
                error!("Failed to add device: id {}, type {}", args.id, args.driver);
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn device_del(&mut self, device_id: String) -> Response {
        match self.del_replaceable_device(&device_id) {
            Ok(path) => {
                let block_del_event = qmp_schema::DeviceDeleted {
                    device: Some(device_id),
                    path,
                };
                event!(DeviceDeleted; block_del_event);

                Response::create_empty_response()
            }
            Err(ref e) => {
                error!("Failed to delete device: {:?}", e);
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn blockdev_add(&self, args: Box<qmp_schema::BlockDevAddArgument>) -> Response {
        let read_only = args.read_only.unwrap_or(false);
        let direct = if let Some(cache) = args.cache {
            match cache.direct {
                Some(direct) => direct,
                _ => true,
            }
        } else {
            true
        };

        let config = BlkDevConfig {
            id: args.node_name.clone(),
            path_on_host: args.file.filename,
            read_only,
            direct,
            serial_num: None,
            iothread: None,
            iops: None,
            queues: 1,
            boot_index: None,
            chardev: None,
            socket_path: None,
            // TODO Add aio option by qmp, now we set it based on "direct".
            aio: if direct {
                AioEngine::Native
            } else {
                AioEngine::Off
            },
            queue_size: DEFAULT_VIRTQUEUE_SIZE,
        };
        if let Err(e) = config.check() {
            error!("{:?}", e);
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            );
        }
        match self.add_replaceable_config(&args.node_name, Arc::new(config)) {
            Ok(()) => Response::create_empty_response(),
            Err(ref e) => {
                error!("{:?}", e);
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn blockdev_del(&self, _node_name: String) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError("blockdev_del not support yet".to_string()),
            None,
        )
    }

    fn netdev_add(&mut self, args: Box<qmp_schema::NetDevAddArgument>) -> Response {
        let mut config = NetworkInterfaceConfig {
            id: args.id.clone(),
            host_dev_name: "".to_string(),
            mac: None,
            tap_fds: None,
            vhost_type: None,
            vhost_fds: None,
            iothread: None,
            queues: 2,
            mq: false,
            socket_path: None,
            queue_size: DEFAULT_VIRTQUEUE_SIZE,
        };

        if let Some(fds) = args.fds {
            let netdev_fd = if fds.contains(':') {
                let col: Vec<_> = fds.split(':').collect();
                String::from(col[col.len() - 1])
            } else {
                String::from(&fds)
            };

            if let Some(fd_num) = QmpChannel::get_fd(&netdev_fd) {
                config.tap_fds = Some(vec![fd_num]);
            } else {
                // try to convert string to RawFd
                let fd_num = match netdev_fd.parse::<i32>() {
                    Ok(fd) => fd,
                    _ => {
                        error!(
                            "Add netdev error: failed to convert {} to RawFd.",
                            netdev_fd
                        );
                        return Response::create_error_response(
                            qmp_schema::QmpErrorClass::GenericError(
                                "Add netdev error: failed to convert {} to RawFd.".to_string(),
                            ),
                            None,
                        );
                    }
                };
                config.tap_fds = Some(vec![fd_num]);
            }
        } else if let Some(if_name) = args.if_name {
            config.host_dev_name = if_name.clone();
            if create_tap(None, Some(&if_name), 1).is_err() {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(
                        "Tap device already in use".to_string(),
                    ),
                    None,
                );
            }
        }

        match self.add_replaceable_config(&args.id, Arc::new(config)) {
            Ok(()) => Response::create_empty_response(),
            Err(ref e) => {
                error!("{:?}", e);
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn netdev_del(&mut self, _node_name: String) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError("netdev_del not support yet".to_string()),
            None,
        )
    }

    fn chardev_add(&mut self, _args: qmp_schema::CharDevAddArgument) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "chardev_add not supported yet for microVM".to_string(),
            ),
            None,
        )
    }

    fn chardev_remove(&mut self, _id: String) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "chardev_remove not supported yet for microVM".to_string(),
            ),
            None,
        )
    }

    fn getfd(&self, fd_name: String, if_fd: Option<RawFd>) -> Response {
        if let Some(fd) = if_fd {
            QmpChannel::set_fd(fd_name, fd);
            Response::create_empty_response()
        } else {
            let err_resp =
                qmp_schema::QmpErrorClass::GenericError("Invalid SCM message".to_string());
            Response::create_error_response(err_resp, None)
        }
    }
}

impl MigrateInterface for LightMachine {
    fn migrate(&self, uri: String) -> Response {
        match parse_incoming_uri(&uri) {
            Ok((MigrateMode::File, path)) => migration::snapshot(path),
            Ok((MigrateMode::Unix, _)) | Ok((MigrateMode::Tcp, _)) => {
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(
                        "MicroVM does not support migration".to_string(),
                    ),
                    None,
                )
            }
            _ => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(format!("Invalid uri: {}", uri)),
                None,
            ),
        }
    }

    fn query_migrate(&self) -> Response {
        migration::query_migrate()
    }
}

impl MachineInterface for LightMachine {}
impl MachineExternalInterface for LightMachine {}

impl EventLoopManager for LightMachine {
    fn loop_should_exit(&self) -> bool {
        let vmstate = self.vm_state.deref().0.lock().unwrap();
        *vmstate == KvmVmState::Shutdown
    }

    fn loop_cleanup(&self) -> util::Result<()> {
        set_termi_canon_mode().with_context(|| "Failed to set terminal to canonical mode")?;
        Ok(())
    }
}

#[cfg(target_arch = "riscv64")]
fn generate_plic_device_node(
    fdt: &mut FdtBuilder,
    res: &SysRes,
    nr_vcpu: usize,
) -> util::Result<()> {
    let region_base = res.region_base;
    let region_size = res.region_size;
    let node = format!("interrupt-controller@{:x}", region_base);
    let intc_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "riscv,plic0")?;
    fdt.set_property("interrupt-controller", &Vec::new())?;
    fdt.set_property_u32("#interrupt-cells", 0x1)?;
    fdt.set_property_u32("phandle", device_tree::PLIC_PHANDLE)?;
    fdt.set_property_u32("riscv,ndev", 10)?;
    // fdt.set_property_u32("riscv,ndev", MAX_DEVICES - 1)?;
    fdt.set_property_array_u64("reg", &[region_base, region_size])?;

    let num_context = nr_vcpu * 2;
    let mut irq_cells = Vec::new();
    let mut i: u32 = 0;
    while i < (num_context / 2) as u32 {
        irq_cells.push(device_tree::INCT_PHANDLE_START + i);
        irq_cells.push(0xffff_ffff);
        irq_cells.push(device_tree::INCT_PHANDLE_START + i);
        irq_cells.push(9);
        i += 1;
    }

    let irq_cells = irq_cells.as_slice();
    fdt.set_property_array_u32("interrupts-extended", irq_cells)?;

    fdt.end_node(intc_node_dep)?;

    Ok(())
}

// Function that helps to generate serial node in device-tree.
//
// # Arguments
//
// * `dev_info` - Device resource info of serial device.
// * `fdt` - Flatted device-tree blob where serial node will be filled into.
#[cfg(target_arch = "riscv64")]
fn generate_serial_device_node(fdt: &mut FdtBuilder, res: &SysRes) -> util::Result<()> {
    let node = format!("uart@{:x}", res.region_base);
    let serial_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "ns16550a")?;
    fdt.set_property_array_u64("reg", &[res.region_base, res.region_size])?;
    fdt.set_property_u32("clock-frequency", 3686400)?;
    fdt.set_property_u32("interrupt-parent", device_tree::PLIC_PHANDLE)?;
    fdt.set_property_u32("interrupts", res.irq as u32)?;
    fdt.end_node(serial_node_dep)?;
    Ok(())
}

// Function that helps to generate Virtio-Mmio device's node in device-tree.
//
// # Arguments
//
// * `dev_info` - Device resource info of Virtio-Mmio device.
// * `fdt` - Flatted device-tree blob where node will be filled into.
#[cfg(target_arch = "riscv64")]
fn generate_virtio_devices_node(fdt: &mut FdtBuilder, res: &SysRes) -> util::Result<()> {
    let node = format!("virtio_mmio@{:x}", res.region_base);
    let virtio_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "virtio,mmio")?;
    fdt.set_property_u32("interrupt-parent", device_tree::PLIC_PHANDLE)?;
    fdt.set_property_array_u64("reg", &[res.region_base, res.region_size])?;
    fdt.set_property_u32("interrupts", res.irq as u32)?;
    fdt.end_node(virtio_node_dep)?;
    Ok(())
}

/// Trait that helps to generate all nodes in device-tree.
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
trait CompileFDTHelper {
    /// Function that helps to generate cpu nodes.
    fn generate_cpu_nodes(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
    /// Function that helps to generate memory nodes.
    fn generate_memory_node(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
    /// Function that helps to generate Virtio-mmio devices' nodes.
    fn generate_devices_node(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
    /// Function that helps to generate the chosen node.
    fn generate_chosen_node(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
}

#[cfg(target_arch = "riscv64")]
impl CompileFDTHelper for LightMachine {
    fn generate_cpu_nodes(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        let node = "cpus";

        let cpus = &self.cpus;
        let cpus_node_dep = fdt.begin_node(node)?;
        fdt.set_property_u32("#address-cells", 0x02)?;
        fdt.set_property_u32("#size-cells", 0x0)?;
        let frequency = cpus[0].arch().lock().unwrap().timer_regs().frequency;
        fdt.set_property_u32("timebase-frequency", frequency as u32)?;

        let nr_vcpus = cpus.len();
        for cpu_index in 0..nr_vcpus {
            let node = format!("cpu@{:x}", cpu_index);
            let cpu_node_dep = fdt.begin_node(&node)?;
            fdt.set_property_u32(
                "phandle",
                cpu_index as u32 + device_tree::CPU_PHANDLE_START,
            )?;
            fdt.set_property_string("device_type", "cpu")?;
            fdt.set_property_string("compatible", "riscv")?;

            let xlen = self.cpus[cpu_index]
                .arch()
                .lock()
                .unwrap()
                .get_xlen()
                .to_string();
            let mut isa = format!("rv{}", xlen);
            let valid_isa_order = String::from("IEMAFDQCLBJTPVNSUHKORWXYZG");
            for char in valid_isa_order.chars() {
                let index = char as u32 - 'A' as u32;
                let cpu_isa = self.cpus[cpu_index]
                    .arch()
                    .lock()
                    .unwrap()
                    .config_regs()
                    .isa;
                if (cpu_isa & (1 << index) as u64) > 0 {
                    let tmp = char::from('a' as u8 + index as u8);
                    isa = format!("{}{}", isa, tmp);
                }
            }

            fdt.set_property_string("riscv,isa", &isa)?;

            fdt.set_property_u64("reg", cpu_index as u64)?;

            let node = "interrupt-controller";
            let interrupt_controller = fdt.begin_node(node)?;
            fdt.set_property_string("compatible", "riscv,cpu-intc")?;
            fdt.set_property_u32("#interrupt-cells", 1)?;
            fdt.set_property("interrupt-controller", &Vec::new())?;
            fdt.set_property_u32(
                "phandle",
                cpu_index as u32 + device_tree::INCT_PHANDLE_START,
            )?;
            fdt.end_node(interrupt_controller)?;

            fdt.end_node(cpu_node_dep)?;
        }

        fdt.end_node(cpus_node_dep)?;

        Ok(())
    }

    fn generate_memory_node(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        let mem_base = MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
        let mem_size = self.sys_mem.memory_end_address().raw_value()
            - MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
        let node = "memory";
        let memory_node_dep = fdt.begin_node(node)?;
        fdt.set_property_string("device_type", "memory")?;
        fdt.set_property_array_u64("reg", &[mem_base, mem_size as u64])?;
        fdt.end_node(memory_node_dep)?;

        Ok(())
    }

    fn generate_devices_node(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        let node = "soc";
        let smb_node_dep = fdt.begin_node(node)?;
        fdt.set_property_string("compatible", "simple-bus")?;
        fdt.set_property_u32("#address-cells", 0x02)?;
        fdt.set_property_u32("#size-cells", 0x2)?;
        fdt.set_property("ranges", &Vec::new())?;

        for dev in self.sysbus.devices.iter() {
            let mut locked_dev = dev.lock().unwrap();
            let dev_type = locked_dev.get_type();
            let sys_res = locked_dev.get_sys_resource().unwrap();
            match dev_type {
                SysBusDevType::Plic => generate_plic_device_node(fdt, sys_res, self.cpus.len())?,
                SysBusDevType::Serial => generate_serial_device_node(fdt, sys_res)?,
                SysBusDevType::VirtioMmio => generate_virtio_devices_node(fdt, sys_res)?,
                _ => (),
            }
        }
        fdt.end_node(smb_node_dep)?;
        Ok(())
    }

    fn generate_chosen_node(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        let node = "chosen";
        let boot_source = self.boot_source.lock().unwrap();

        let chosen_node_dep = fdt.begin_node(node)?;
        let cmdline = &boot_source.kernel_cmdline.to_string();
        fdt.set_property_string("bootargs", cmdline.as_str())?;

        match &boot_source.initrd {
            Some(initrd) => {
                fdt.set_property_u64("linux,initrd-start", initrd.initrd_addr)?;
                fdt.set_property_u64("linux,initrd-end", initrd.initrd_addr + initrd.initrd_size)?;
            }
            None => {}
        }
        fdt.end_node(chosen_node_dep)?;

        Ok(())
    }
}

#[cfg(target_arch = "riscv64")]
impl device_tree::CompileFDT for LightMachine {
    fn generate_fdt_node(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        let node_dep = fdt.begin_node("")?;

        fdt.set_property_string("compatible", "linux,dummy-virt")?;
        fdt.set_property_u32("#address-cells", 0x2)?;
        fdt.set_property_u32("#size-cells", 0x2)?;

        self.generate_cpu_nodes(fdt)?;
        self.generate_memory_node(fdt)?;
        self.generate_devices_node(fdt)?;
        self.generate_chosen_node(fdt)?;

        fdt.end_node(node_dep)?;

        Ok(())
    }
}

impl MachineTestInterface for LightMachine {}

/// Trace descriptions for some devices at stratovirt startup.
fn trace_cpu_topo(cpu_topo: &CPUTopology) {
    util::ftrace!(trace_cpu_topo, "{:#?}", cpu_topo);
}

fn trace_sysbus(sysbus: &SysBus) {
    util::ftrace!(trace_sysbus, "{:?}", sysbus);
}

fn trace_replaceable_info(replaceable_info: &MmioReplaceableInfo) {
    util::ftrace!(trace_replaceable_info, "{:?}", replaceable_info);
}

fn trace_vm_state(vm_state: &Arc<(Mutex<KvmVmState>, Condvar)>) {
    util::ftrace!(trace_vm_state, "{:#?}", vm_state);
}

fn trace_mmio_replaceable_config(config: &MmioReplaceableConfig) {
    util::ftrace!(trace_mmio_replaceable_config, "{:#?}", config);
}
