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

//! Interfaces for simulating various devices.
//!
//! This crate simulates:
//! - interrupt controller (riscv64)
//! - legacy devices, such as serial devices

pub mod pcie_mem; 
mod interrupt_controller;
pub mod legacy;

#[cfg(target_arch = "riscv64")]
pub use interrupt_controller::{
     InterruptController, InterruptControllerConfig, MAX_DEVICES
};
pub use legacy::error::LegacyError as LegacyErrs;