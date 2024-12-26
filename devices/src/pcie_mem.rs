use sysbus::{SysBusDevOps, SysRes, SysBusDevType};
use address_space::GuestAddress;

pub struct PcieMem {
    sys_res: SysRes,
    mem: Vec<u8>,
}

impl PcieMem {
    pub fn new(size: u64) -> Self {
        Self {
            sys_res: SysRes::default(),
            mem: vec![0; size as usize],
        }
    }
}

impl SysBusDevOps for PcieMem {
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        if offset as usize + data.len() > self.mem.len() {
            return false;
        }
        data.copy_from_slice(&self.mem[offset as usize..offset as usize + data.len()]);
        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        if offset as usize + data.len() > self.mem.len() {
            return false;
        }
        self.mem[offset as usize..offset as usize + data.len()].copy_from_slice(data);
        true
    }

    fn get_type(&self) -> SysBusDevType {
        SysBusDevType::PcieMem
    }

    fn get_sys_resource(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.sys_res)
    }
} 