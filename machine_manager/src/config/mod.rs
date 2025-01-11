// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.


pub use boot_source::*;
pub use chardev::*;
pub use devices::*;
pub use drive::*;
pub use error::ConfigError;
pub use fs::*;
pub use incoming::*;
pub use iothread::*;
pub use machine_config::*;
pub use network::*;
pub use pci::*;
pub use rng::*;
pub use sasl_auth::*;
pub use tls_creds::*;
pub use vnc::*;

mod boot_source;
mod chardev;
mod devices;
mod drive;
pub mod error;
mod fs;
mod incoming;
mod iothread;
mod machine_config;
mod network;
mod pci;
mod rng;
mod sasl_auth;
mod tls_creds;
pub mod vnc;

use std::collections::HashMap;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use anyhow::{anyhow, bail, Context, Result};
use log::error;
use util::device_tree::{self, FdtBuilder};
use util::{
    file::{get_file_alignment, open_file},
    test_helper::is_test_enabled,
    trace::enable_trace_events,
    AsAny,
};

pub const MAX_STRING_LENGTH: usize = 255;
pub const MAX_PATH_LENGTH: usize = 4096;
// Maximum length of the socket path is restricted by linux.
pub const MAX_SOCK_PATH_LENGTH: usize = 108;
// FIXME: `queue_config` len in `VirtioPciState` struct needs to be modified together.
pub const MAX_VIRTIO_QUEUE: usize = 32;
pub const FAST_UNPLUG_ON: &str = "1";
pub const FAST_UNPLUG_OFF: &str = "0";
pub const MAX_TAG_LENGTH: usize = 36;
pub const MAX_NODES: u32 = 128;
/// Default virtqueue size for virtio devices excepts virtio-fs.
pub const DEFAULT_VIRTQUEUE_SIZE: u16 = 256;

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct ObjectConfig {
    pub rng_object: HashMap<String, RngObjConfig>,
    pub mem_object: HashMap<String, MemZoneConfig>,
    pub tls_object: HashMap<String, TlsCredObjConfig>,
    pub sasl_object: HashMap<String, SaslAuthObjConfig>,
}

/// This main config structure for Vm, contains Vm's basic configuration and devices.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct VmConfig {
    pub guest_name: String,
    pub machine_config: MachineConfig,
    pub boot_source: BootSource,
    pub drives: HashMap<String, DriveConfig>,
    pub netdevs: HashMap<String, NetDevcfg>,
    pub chardev: HashMap<String, ChardevConfig>,
    pub virtio_serial: Option<VirtioSerialInfo>,
    pub devices: Vec<(String, String)>,
    pub serial: Option<SerialConfig>,
    pub iothreads: Option<Vec<IothreadConfig>>,
    pub object: ObjectConfig,
    pub pflashs: Option<Vec<PFlashConfig>>,
    pub dev_name: HashMap<String, u8>,
    pub global_config: HashMap<String, String>,
  //  pub numa_nodes: Vec<(String, String)>,
    pub incoming: Option<Incoming>,
    pub vnc: Option<VncConfig>,
}

impl VmConfig {
    /// Healthy check for `VmConfig`
    pub fn check_vmconfig(&self, is_daemonize: bool) -> Result<()> {
        self.boot_source.check()?;
        self.machine_config.check()?;

        if self.guest_name.len() > MAX_STRING_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "name".to_string(),
                MAX_STRING_LENGTH,
            )));
        }
        if self.boot_source.kernel_file.is_none()
            && self.machine_config.mach_type == MachineType::MicroVm
        {
            bail!("kernel file is required for microvm machine type, which is not provided");
        }

        if self.boot_source.initrd.is_none()
            && self.drives.is_empty()
            && self.chardev.is_empty()
            && !is_test_enabled()
        {
            bail!("Before Vm start, set a initrd or drive_file or vhost-user blk as rootfs");
        }

        let mut stdio_count = 0;
        if let Some(serial) = self.serial.as_ref() {
            if serial.chardev.backend == ChardevType::Stdio {
                stdio_count += 1;
            }
        }
        for (_, char_dev) in self.chardev.clone() {
            if char_dev.backend == ChardevType::Stdio {
                stdio_count += 1;
            }
        }
        if stdio_count > 0 && is_daemonize {
            bail!("Device redirected to stdio and daemonize can't be set together");
        }
        if stdio_count > 1 {
            bail!("Can't set multiple devices redirected to stdio");
        }

        Ok(())
    }

    /// Add argument `name` to `VmConfig`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name `String` updated to `VmConfig`.
    pub fn add_name(&mut self, name: &str) -> Result<()> {
        self.guest_name = name.to_string();
        Ok(())
    }

    /// Add argument `object` to `VmConfig`.
    ///
    /// # Arguments
    ///
    /// * `object_args` - The args of object.
    pub fn add_object(&mut self, object_args: &str) -> Result<()> {
        let mut cmd_params = CmdParser::new("object");
        cmd_params.push("");

        cmd_params.get_parameters(object_args)?;
        let obj_type = cmd_params.get_value::<String>("")?;
        if obj_type.is_none() {
            bail!("Object type not specified");
        }
        let device_type = obj_type.unwrap();
        match device_type.as_str() {
            "iothread" => {
                self.add_iothread(object_args)
                    .with_context(|| "Failed to add iothread")?;
            }
            "rng-random" => {
                let rng_cfg = parse_rng_obj(object_args)?;
                let id = rng_cfg.id.clone();
                if self.object.rng_object.get(&id).is_none() {
                    self.object.rng_object.insert(id, rng_cfg);
                } else {
                    bail!("Object: {} has been added", id);
                }
            }
            "memory-backend-ram" => {
                let zone_config = self.add_mem_zone(object_args)?;
                let id = zone_config.id.clone();
                if self.object.mem_object.get(&id).is_none() {
                    self.object.mem_object.insert(id, zone_config);
                } else {
                    bail!("Object: {} has been added", id);
                }
            }
            "tls-creds-x509" => {
                self.add_tlscred(object_args)?;
            }
            "authz-simple" => {
                self.add_saslauth(object_args)?;
            }
            _ => {
                bail!("Unknow object type: {:?}", &device_type);
            }
        }

        Ok(())
    }

    /// Add argument `global` to `VmConfig`.
    ///
    /// # Arguments
    ///
    /// * `global_config` - The args of global config.
    pub fn add_global_config(&mut self, global_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("global");
        cmd_parser.push("pcie-root-port.fast-unplug");
        cmd_parser.parse(global_config)?;

        if let Some(fast_unplug_value) =
            cmd_parser.get_value::<String>("pcie-root-port.fast-unplug")?
        {
            if fast_unplug_value != FAST_UNPLUG_ON && fast_unplug_value != FAST_UNPLUG_OFF {
                bail!("The value of fast-unplug is invalid: {}", fast_unplug_value);
            }
            let fast_unplug_key = String::from("pcie-root-port.fast-unplug");
            if self.global_config.get(&fast_unplug_key).is_none() {
                self.global_config
                    .insert(fast_unplug_key, fast_unplug_value);
            } else {
                bail!("Global config {} has been added", fast_unplug_key);
            }
        }
        Ok(())
    }

    /// Add a file to drive file store.
    pub fn add_drive_file(
        drive_files: &mut HashMap<String, DriveFile>,
        path: &str,
        read_only: bool,
        direct: bool,
    ) -> Result<()> {
        if let Some(drive_file) = drive_files.get_mut(path) {
            if drive_file.read_only && read_only {
                // File can be shared with read_only.
                drive_file.count += 1;
                return Ok(());
            } else {
                return Err(anyhow!(
                    "Failed to add drive {}, file can only be shared with read_only. \
                    Is it used more than once or another process using the same file?",
                    path
                ));
            }
        }
        let mut file = open_file(path, read_only, direct)?;
        let (req_align, buf_align) = get_file_alignment(&file, direct);
        if req_align == 0 || buf_align == 0 {
            bail!(
                "Failed to detect alignment requirement of drive file {}.",
                path
            );
        }
        let file_size = file.seek(SeekFrom::End(0))?;
        if file_size & (req_align as u64 - 1) != 0 {
            bail!("The size of file {} is not aligned to {}.", path, req_align);
        }
        let drive_file = DriveFile {
            file,
            count: 1,
            read_only,
            path: path.to_string(),
            locked: false,
            req_align,
            buf_align,
        };
        drive_files.insert(path.to_string(), drive_file);
        Ok(())
    }

    /// Remove a file from drive file store.
    pub fn remove_drive_file(
        drive_files: &mut HashMap<String, DriveFile>,
        path: &str,
    ) -> Result<()> {
        if let Some(drive_file) = drive_files.get_mut(path) {
            drive_file.count -= 1;
            if drive_file.count == 0 {
                drive_files.remove(path);
            }
        } else {
            return Err(anyhow!(
                "Failed to remove drive {}, it does not exist",
                path
            ));
        }
        Ok(())
    }

    /// Get a file from drive file store.
    pub fn fetch_drive_file(drive_files: &HashMap<String, DriveFile>, path: &str) -> Result<File> {
        match drive_files.get(path) {
            Some(drive_file) => drive_file
                .file
                .try_clone()
                .with_context(|| format!("Failed to clone drive backend file {}", path)),
            None => Err(anyhow!("The file {} is not in drive backend", path)),
        }
    }

    /// Get alignment requirement from drive file store.
    pub fn fetch_drive_align(
        drive_files: &HashMap<String, DriveFile>,
        path: &str,
    ) -> Result<(u32, u32)> {
        match drive_files.get(path) {
            Some(drive_file) => Ok((drive_file.req_align, drive_file.buf_align)),
            None => Err(anyhow!("The file {} is not in drive backend", path)),
        }
    }

    /// Create initial drive file store from cmdline drive.
    pub fn init_drive_files(&self) -> Result<HashMap<String, DriveFile>> {
        let mut drive_files: HashMap<String, DriveFile> = HashMap::new();
        for drive in self.drives.values() {
            Self::add_drive_file(
                &mut drive_files,
                &drive.path_on_host,
                drive.read_only,
                drive.direct,
            )?;
        }
        if let Some(pflashs) = self.pflashs.as_ref() {
            for pflash in pflashs {
                Self::add_drive_file(
                    &mut drive_files,
                    &pflash.path_on_host,
                    pflash.read_only,
                    false,
                )?;
            }
        }
        Ok(drive_files)
    }
}

impl device_tree::CompileFDT for VmConfig {
    fn generate_fdt_node(&self, _fdt: &mut FdtBuilder) -> util::Result<()> {
        Ok(())
    }
}

/// This trait is to check the legality of Config structure.
pub trait ConfigCheck: AsAny + Send + Sync + std::fmt::Debug {
    /// To check the legality of Config structure.
    ///
    /// # Errors
    ///
    /// * `StringLengthTooLong` - Limit the length of String.
    /// * `NrcpusError` - Limit the number of vcpu in StratoVirt.
    /// * `MemsizeError` - Limit the size of memory in StratoVirt.
    /// * `GuestCidError` - Vsock guest-cid is illegel.
    /// * `MacFormatError` - Mac address is illegel.
    /// * `UnRegularFile` - File is illegel.
    fn check(&self) -> Result<()>;
}

/// Struct `CmdParser` used to parse and check cmdline parameters to vm config.
pub struct CmdParser {
    name: String,
    params: HashMap<String, Option<String>>,
}

impl CmdParser {
    /// Allocates an empty `CmdParser`.
    pub fn new(name: &str) -> Self {
        CmdParser {
            name: name.to_string(),
            params: HashMap::<String, Option<String>>::new(),
        }
    }

    /// Push a new param field into `params`.
    ///
    /// # Arguments
    ///
    /// * `param_field`: The cmdline parameter field name.
    pub fn push(&mut self, param_field: &str) -> &mut Self {
        self.params.insert(param_field.to_string(), None);

        self
    }

    /// Parse cmdline parameters string into `params`.
    ///
    /// # Arguments
    ///
    /// * `cmd_param`: The whole cmdline parameter string.
    pub fn parse(&mut self, cmd_param: &str) -> Result<()> {
        if cmd_param.starts_with(',') || cmd_param.ends_with(',') {
            return Err(anyhow!(ConfigError::InvalidParam(
                cmd_param.to_string(),
                self.name.clone()
            )));
        }
        let param_items = cmd_param.split(',').collect::<Vec<&str>>();
        for (i, param_item) in param_items.iter().enumerate() {
            if param_item.starts_with('=') || param_item.ends_with('=') {
                return Err(anyhow!(ConfigError::InvalidParam(
                    param_item.to_string(),
                    self.name.clone()
                )));
            }
            let param = param_item.splitn(2, '=').collect::<Vec<&str>>();
            let (param_key, param_value) = match param.len() {
                1 => {
                    if i == 0 {
                        ("", param[0])
                    } else {
                        (param[0], "")
                    }
                }
                2 => (param[0], param[1]),
                _ => {
                    return Err(anyhow!(ConfigError::InvalidParam(
                        param_item.to_string(),
                        self.name.clone()
                    )));
                }
            };

            if self.params.contains_key(param_key) {
                let field_value = self.params.get_mut(param_key).unwrap();
                if field_value.is_none() {
                    *field_value = Some(String::from(param_value));
                } else {
                    return Err(anyhow!(ConfigError::FieldRepeat(
                        self.name.clone(),
                        param_key.to_string()
                    )));
                }
            } else {
                return Err(anyhow!(ConfigError::InvalidParam(
                    param[0].to_string(),
                    self.name.clone()
                )));
            }
        }

        Ok(())
    }

    /// Parse all cmdline parameters string into `params`.
    ///
    /// # Arguments
    ///
    /// * `cmd_param`: The whole cmdline parameter string.
    fn get_parameters(&mut self, cmd_param: &str) -> Result<()> {
        if cmd_param.starts_with(',') || cmd_param.ends_with(',') {
            return Err(anyhow!(ConfigError::InvalidParam(
                cmd_param.to_string(),
                self.name.clone()
            )));
        }
        let param_items = cmd_param.split(',').collect::<Vec<&str>>();
        for param_item in param_items {
            let param = param_item.splitn(2, '=').collect::<Vec<&str>>();
            let (param_key, param_value) = match param.len() {
                1 => ("", param[0]),
                2 => (param[0], param[1]),
                _ => {
                    return Err(anyhow!(ConfigError::InvalidParam(
                        param_item.to_string(),
                        self.name.clone()
                    )));
                }
            };

            if self.params.contains_key(param_key) {
                let field_value = self.params.get_mut(param_key).unwrap();
                if field_value.is_none() {
                    *field_value = Some(String::from(param_value));
                } else {
                    return Err(anyhow!(ConfigError::FieldRepeat(
                        self.name.clone(),
                        param_key.to_string()
                    )));
                }
            }
        }

        Ok(())
    }

    /// Get cmdline parameters value from param field name.
    ///
    /// # Arguments
    ///
    /// * `param_field`: The cmdline parameter field name.
    pub fn get_value<T: FromStr>(&self, param_field: &str) -> Result<Option<T>> {
        match self.params.get(param_field) {
            Some(value) => {
                let field_msg = if param_field.is_empty() {
                    &self.name
                } else {
                    param_field
                };

                if let Some(raw_value) = value {
                    Ok(Some(raw_value.parse().map_err(|_| {
                        anyhow!(ConfigError::ConvertValueFailed(
                            field_msg.to_string(),
                            raw_value.clone()
                        ))
                    })?))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
}

/// This struct is a wrapper for `bool`.
/// More switch string can be transferred to this structure.
pub struct ExBool {
    inner: bool,
}

impl FromStr for ExBool {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "true" | "on" | "yes" => Ok(ExBool { inner: true }),
            "false" | "off" | "no" => Ok(ExBool { inner: false }),
            _ => Err(()),
        }
    }
}

impl From<ExBool> for bool {
    fn from(item: ExBool) -> Self {
        item.inner
    }
}

pub fn add_trace_events(config: &str) -> Result<()> {
    let mut cmd_parser = CmdParser::new("trace");
    cmd_parser.push("events");
    cmd_parser.get_parameters(config)?;

    if let Some(file) = cmd_parser.get_value::<String>("events")? {
        enable_trace_events(&file)?;
        return Ok(());
    }
    bail!("trace: events file must be set.");
}

pub struct IntegerList(pub Vec<u64>);

impl FromStr for IntegerList {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut integer_list = Vec::new();
        let lists: Vec<&str> = s
            .trim()
            .trim_matches(|c| c == '[' || c == ']')
            .split(':')
            .collect();
        for list in lists.iter() {
            let items: Vec<&str> = list.split('-').collect();
            if items.len() > 2 {
                return Err(());
            }

            let start = items[0]
                .parse::<u64>()
                .map_err(|_| error!("Invalid value {}", items[0]))?;
            integer_list.push(start);
            if items.len() == 2 {
                let end = items[1]
                    .parse::<u64>()
                    .map_err(|_| error!("Invalid value {}", items[1]))?;
                if start >= end {
                    return Err(());
                }

                for i in start..end {
                    integer_list.push(i + 1);
                }
            }
        }

        Ok(IntegerList(integer_list))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmd_parser() {
        let mut cmd_parser = CmdParser::new("test");
        cmd_parser
            .push("")
            .push("id")
            .push("path")
            .push("num")
            .push("test1")
            .push("test2")
            .push("test3")
            .push("test4")
            .push("test5")
            .push("test6")
            .push("test7");
        assert!(cmd_parser
            .parse("socket,id=charconsole0,path=/tmp/console.sock,num=1,test1=true,test2=on,test3=yes,test4=false,test5=off,test6=no,test7=random")
            .is_ok());
        assert_eq!(
            cmd_parser.get_value::<String>("").unwrap().unwrap(),
            "socket".to_string()
        );
        assert_eq!(
            cmd_parser.get_value::<String>("id").unwrap().unwrap(),
            "charconsole0".to_string()
        );
        assert_eq!(
            cmd_parser.get_value::<String>("path").unwrap().unwrap(),
            "/tmp/console.sock".to_string()
        );
        assert_eq!(cmd_parser.get_value::<u64>("num").unwrap().unwrap(), 1_u64);
        assert_eq!(cmd_parser.get_value::<u32>("num").unwrap().unwrap(), 1_u32);
        assert_eq!(cmd_parser.get_value::<u16>("num").unwrap().unwrap(), 1_u16);
        assert_eq!(cmd_parser.get_value::<u8>("num").unwrap().unwrap(), 1_u8);
        assert_eq!(cmd_parser.get_value::<i64>("num").unwrap().unwrap(), 1_i64);
        assert_eq!(cmd_parser.get_value::<i32>("num").unwrap().unwrap(), 1_i32);
        assert_eq!(cmd_parser.get_value::<i16>("num").unwrap().unwrap(), 1_i16);
        assert_eq!(cmd_parser.get_value::<i8>("num").unwrap().unwrap(), 1_i8);
        assert!(cmd_parser.get_value::<bool>("test1").unwrap().unwrap());
        assert!(
            cmd_parser
                .get_value::<ExBool>("test1")
                .unwrap()
                .unwrap()
                .inner
        );
        assert!(
            cmd_parser
                .get_value::<ExBool>("test2")
                .unwrap()
                .unwrap()
                .inner
        );
        assert!(
            cmd_parser
                .get_value::<ExBool>("test3")
                .unwrap()
                .unwrap()
                .inner
        );
        assert!(!cmd_parser.get_value::<bool>("test4").unwrap().unwrap());
        assert!(
            !cmd_parser
                .get_value::<ExBool>("test4")
                .unwrap()
                .unwrap()
                .inner
        );
        assert!(
            !cmd_parser
                .get_value::<ExBool>("test5")
                .unwrap()
                .unwrap()
                .inner
        );
        assert!(
            !cmd_parser
                .get_value::<ExBool>("test6")
                .unwrap()
                .unwrap()
                .inner
        );
        assert!(cmd_parser.get_value::<bool>("test7").is_err());
        assert!(cmd_parser.get_value::<ExBool>("test7").is_err());
        assert!(cmd_parser.get_value::<String>("random").unwrap().is_none());
        assert!(cmd_parser.parse("random=false").is_err());
    }

    #[test]
    fn test_add_trace_events_01() {
        assert!(add_trace_events("event=test_trace_events").is_err());
        assert!(add_trace_events("events").is_err());
        assert!(add_trace_events("events=test_trace_events").is_err());
    }

    #[test]
    fn test_add_trace_events_02() {
        use std::fs::File;
        use std::io::Write;
        use util::trace::is_trace_event_enabled;

        let file = "/tmp/test_trace_events";
        let mut fd = File::create(file).unwrap();
        let event = "add_trace_events";
        fd.write(event.as_bytes()).unwrap();
        add_trace_events(format!("events={}", file).as_str()).unwrap();

        assert!(is_trace_event_enabled(event));
        std::fs::remove_file(file).unwrap();
    }

    #[test]
    fn test_add_global_config() {
        let mut vm_config = VmConfig::default();
        vm_config
            .add_global_config("pcie-root-port.fast-unplug=1")
            .unwrap();
        let fast_unplug = vm_config.global_config.get("pcie-root-port.fast-unplug");
        assert!(fast_unplug.is_some());
        assert_eq!(fast_unplug.unwrap(), FAST_UNPLUG_ON);

        let mut vm_config = VmConfig::default();
        vm_config
            .add_global_config("pcie-root-port.fast-unplug=0")
            .unwrap();
        let fast_unplug = vm_config.global_config.get("pcie-root-port.fast-unplug");
        assert!(fast_unplug.is_some());
        assert_eq!(fast_unplug.unwrap(), FAST_UNPLUG_OFF);

        let mut vm_config = VmConfig::default();
        let res = vm_config.add_global_config("pcie-root-port.fast-unplug");
        assert!(res.is_err());

        let mut vm_config = VmConfig::default();
        let res = vm_config.add_global_config("pcie-root-port.fast-unplug=2");
        assert!(res.is_err());

        let mut vm_config = VmConfig::default();
        let res = vm_config.add_global_config("pcie-root-port.fast-unplug=0");
        assert!(res.is_ok());
        let res = vm_config.add_global_config("pcie-root-port.fast-unplug=1");
        assert!(res.is_err());
    }
}
