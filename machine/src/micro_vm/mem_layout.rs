// Copyright (c) 2023 China Telecom Co.,Ltd. All rights reserved.
//
// TeleVM is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
//
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

/// The type of memory layout entry on riscv64
#[repr(usize)]
pub enum LayoutEntryType {
    Plic,
    Uart,
    Mmio,
    PcieEcam,
    PcieMmio,
    Mem,
}
/// Layout of riscv64
pub const MEM_LAYOUT: &[(u64, u64)] = &[
    (0x0c00_0000, 0x0400_0000),    // Plic 
    (0x1000_0000, 0x0000_0100),    // Uart
    (0x1000_1000, 0x0000_1000),    // Mmio
    (0x2000_0000, 0x1000_0000),      // PcieEcam
    (0x3000_0000, 0x1000_0000),      // PcieMmio
    (0x8000_0000, 0x80_0000_0000), // Mem
];

