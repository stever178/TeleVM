// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use serde_json::Value;
use std::io;
use std::io::{Read, Write, BufReader, BufRead};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::thread::sleep;
use std::time::{Duration, Instant};
use std::{env, fs};

use hex;

use crate::utils::get_tmp_dir;

pub struct StreamHandler {
    stream: UnixStream,
}

impl StreamHandler {
    fn new(stream: UnixStream) -> Self {
        StreamHandler { stream }
    }

    fn write_line(&self, cmd: &str) {
        self.stream
            .try_clone()
            .unwrap()
            .write_all(cmd.as_bytes())
            .unwrap();
    }

    fn read_line(&self, timeout: Duration) -> String {
        let start = Instant::now();
        let mut resp = String::new();
        let mut stream = self.stream.try_clone().unwrap();
        stream.set_nonblocking(true).unwrap();

        let pos = loop {
            if start + timeout < Instant::now() || resp.find('\n').is_some() {
                break resp.find('\n');
            }

            let mut buff = [0u8; 1024];
            if let Ok(size) = stream.read(&mut buff) {
                resp.push_str(String::from_utf8(buff[..size].to_vec()).unwrap().as_str());
            }
        };

        let (line, _) = resp.split_at(pos.unwrap());
        line.trim().to_string()
    }
}

pub struct TestState {
    process: Child,
    test_sock: StreamHandler,
    qmp_sock: StreamHandler,
    pub resource_path: String,
    // 添加默认超时时间配置
    timeout: Duration,
}

impl Drop for TestState {
    fn drop(&mut self) {
        if let Ok(None) = self.process.try_wait() {
            self.process.kill().unwrap()
        }

        if Path::new(&self.resource_path).exists() {
            fs::remove_dir_all(&self.resource_path).unwrap();
        }
    }
}

impl TestState {
    pub fn new(
        process: Child,
        test_sock: StreamHandler,
        qmp_sock: StreamHandler,
        resource_path: String,
    ) -> Self {
        let ts = Self {
            process,
            test_sock,
            qmp_sock,
            resource_path,
            timeout: Duration::from_secs(360),
        };
        ts.check_qmp_greet();
        ts
    }

    pub fn stop(&mut self) {
        self.qmp("{\"execute\": \"quit\"}");
        self.process.wait().unwrap();
    }

    pub fn set_timeout(&mut self, duration: Duration) {
        self.timeout = duration;
    }

    fn check_qmp_greet(&self) {
        // let timeout = Duration::from_secs(10);
        let resp: Value =
            serde_json::from_slice(self.qmp_sock.read_line(self.timeout).as_bytes()).unwrap();
        assert!(resp.get("QMP").is_some());
    }

    pub fn wait_qmp_event(&self) -> Value {
        // let timeout = Duration::from_secs(10);
        let resp: Value =
            serde_json::from_slice(self.qmp_sock.read_line(self.timeout).as_bytes()).unwrap();
        assert!(resp.get("event").is_some());
        return resp;
    }

    pub fn qmp(&self, cmd: &str) -> Value {
        // let timeout = Duration::from_secs(10);
        self.qmp_sock.write_line(cmd);
        serde_json::from_slice(self.qmp_sock.read_line(self.timeout).as_bytes()).unwrap()
    }

    pub fn qmp_read(&self) -> Value {
        // let timeout = Duration::from_secs(10);
        serde_json::from_slice(self.qmp_sock.read_line(self.timeout).as_bytes()).unwrap()
    }

    fn send_test_cmd(&self, cmd: &str) -> String {
        // let timeout = Duration::from_secs(10);
        self.test_sock.write_line(cmd);
        self.test_sock.read_line(self.timeout)

        // let resp: Vec<&str> = cmd.split(' ').collect();
        // "OK ".to_string() + resp[1]
    }

    fn send_read_cmd(&self, cmd: &str) -> u64 {
        let buf = self.send_test_cmd(cmd);
        let resp: Vec<&str> = buf.split(' ').collect();
        assert_eq!(resp.len(), 2);
        match resp[0] {
            "OK" => u64::from_str_radix(resp[1].replace("0x", "").as_str(), 16).unwrap(),
            _ => panic!("Failed to execute {}.", cmd),
        }
    }

    fn send_write_cmd(&self, cmd: &str) {
        let buf = self.send_test_cmd(cmd);
        let resp: Vec<&str> = buf.split(' ').collect();
        match resp[0] {
            "OK" => (),
            _ => panic!("Failed to execute {}", cmd),
        }
    }

    fn send_clock_cmd(&self, cmd: &str) -> u64 {
        let buf = self.send_test_cmd(cmd);
        let resp: Vec<&str> = buf.split(' ').collect();
        assert_eq!(resp.len(), 2);
        match resp[0] {
            "OK" => resp[1].parse::<u64>().unwrap(),
            _ => panic!("Failed to execute {}.", cmd),
        }
    }

    pub fn readb(&self, addr: u64) -> u8 {
        let cmd = format!("readb 0x{:x}", addr);
        self.send_read_cmd(&cmd) as u8
    }

    pub fn readw(&self, addr: u64) -> u16 {
        let cmd = format!("readw 0x{:x}", addr);
        self.send_read_cmd(&cmd) as u16
    }

    pub fn readl(&self, addr: u64) -> u32 {
        let cmd = format!("readl 0x{:x}", addr);
        self.send_read_cmd(&cmd) as u32
    }

    pub fn readq(&self, addr: u64) -> u64 {
        let cmd = format!("readq 0x{:x}", addr);
        self.send_read_cmd(&cmd) as u64
    }

    pub fn memread(&self, addr: u64, size: u64) -> Vec<u8> {
        let cmd = format!("read 0x{:x} 0x{:x}", addr, size);
        // println!("~~ in memread, cmd is '{}'", &cmd);
        let buf = self.send_test_cmd(&cmd);
        let resp: Vec<&str> = buf.split(' ').collect();
        assert_eq!(resp.len(), 2);
        match resp[0] {
            "OK" => {
                let data = resp[1].replace("0x", "");
                // println!("~~ data in libtest-memread is {}", &data);
                hex::decode(data).unwrap()
            }
            _ => panic!("Failed to execute {}", cmd),
        }
    }

    pub fn writeb(&self, addr: u64, data: u8) {
        let cmd = format!("writeb 0x{:x} 0x{:x}", addr, data);
        self.send_write_cmd(&cmd);
    }

    pub fn writew(&self, addr: u64, data: u16) {
        let cmd = format!("writew 0x{:x} 0x{:x}", addr, data);
        self.send_write_cmd(&cmd);
    }

    pub fn writel(&self, addr: u64, data: u32) {
        let cmd = format!("writel 0x{:x} 0x{:x}", addr, data);
        self.send_write_cmd(&cmd);
    }

    pub fn writeq(&self, addr: u64, data: u64) {
        let cmd = format!("writeq 0x{:x} 0x{:x}", addr, data);
        self.send_write_cmd(&cmd);
    }

    pub fn memwrite(&self, addr: u64, data: &[u8]) {
        // println!("~~~~ in memwrite, data input is {:?}", &data);
        let cmd = format!(
            "write 0x{:x} 0x{:x} 0x{}",
            addr,
            data.len(),
            hex::encode(data)
        );
        // println!("~~~~ in memwrite, cmd is '{}'", &cmd);
        let buf = self.send_test_cmd(&cmd);
        let resp: Vec<&str> = buf.split(' ').collect();
        match resp[0] {
            "OK" => (),
            _ => panic!("Failed to execute {}", cmd),
        }
    }

    pub fn memset(&self, addr: u64, size: u64, pat: &[u8]) {
        let cmd = format!("memset 0x{:x} 0x{:x} 0x{}", addr, size, hex::encode(pat));
        let buf = self.send_test_cmd(&cmd);
        let resp: Vec<&str> = buf.split(' ').collect();
        match resp[0] {
            "OK" => (),
            _ => panic!("Failed to execute {}", cmd),
        }
    }

    pub fn clock_step(&self) -> u64 {
        let cmd = "clock_step".to_string();
        self.send_clock_cmd(&cmd)
    }

    pub fn clock_step_ns(&self, ns: u64) -> u64 {
        let cmd = format!("clock_step {}", ns);
        self.send_clock_cmd(&cmd)
    }

    pub fn clock_set(&self, tgt: u64) -> u64 {
        let cmd = format!("clock_set {}", tgt);
        self.send_clock_cmd(&cmd)
    }

    pub fn query_msix(&self, addr: u64, data: u32) -> bool {
        let cmd = format!("query_msix {} {}", addr, data);
        let buf = self.send_test_cmd(&cmd);
        let resp: Vec<&str> = buf.split(' ').collect();
        assert_eq!(resp.len(), 2);
        match resp[0] {
            "OK" => match resp[1] {
                "TRUE" => true,
                "FALSE" => false,
                _ => panic!("Failed to execute {}.", cmd),
            },
            _ => panic!("Failed to execute {}.", cmd),
        }
    }
}

fn init_socket(path: &str) -> UnixListener {
    let socket = Path::new(path);
    if socket.exists() {
        fs::remove_file(socket).unwrap();
    }
    UnixListener::bind(socket).unwrap()
}

fn connect_socket(path: &str) -> io::Result<UnixStream> {
    UnixStream::connect(path) //.unwrap()
}

fn socket_accept_wait(listener: UnixListener, timeout: Duration) -> Option<UnixStream> {
    let start = Instant::now();
    listener.set_nonblocking(true).unwrap();

    while start + timeout > Instant::now() {
        match listener.accept() {
            Ok((stream, _addr)) => return Some(stream),
            Err(_) => sleep(Duration::from_millis(100)),
        };
    }
    None
}

fn wait_for_socket(socket_path: &str, timeout_secs: u64) -> io::Result<()> {
    // let start_time = std::time::SystemTime::now();
    let mut attempt = 0;

    while attempt < timeout_secs {
        // 检查套接字文件是否存在
        if Path::new(socket_path).exists() {
            match connect_socket(socket_path) {
                Ok(_stream) => {
                    // 连接成功，关闭流并返回
                    // stream.close()?;
                    println!("Connection attempt {} seconds", attempt);
                    return Ok(());
                },
                Err(e) => {
                    // 连接失败，可能是 QEMU 还没有准备好
                    println!("Connection attempt {} failed: {}", attempt, e);
                },
            }
        }

        // 等待一段时间后再次尝试
        std::thread::sleep(Duration::from_secs(1));
        attempt += 1;
    }

    // 超过最大重试次数后返回错误
    Err(io::Error::new(io::ErrorKind::Other, "Timeout waiting for socket"))
}

// fn wait_for_output(child: &mut std::process::Child, expected_output: &str, timeout: Duration) -> std::io::Result<()> {
//     // let mut buffer = String::new();
//     let mut timeout_reached = false;

//     let start_time = std::time::Instant::now();
//     let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

fn wait_for_output(child_stdout: std::process::ChildStdout, expected_output: &str, timeout: Duration) -> std::io::Result<()> {
    let mut timeout_reached = false;
    let start_time = std::time::Instant::now();
    let mut lines = BufReader::new(child_stdout).lines();

    while let Some(line) = lines.next() {
        let line = line?;
        println!("Virtual machine output: {}", line); // 打印输出到控制台

        if line.contains(expected_output) {
            return Ok(()); // 找到了期望的输出
        }

        if start_time.elapsed() > timeout {
            timeout_reached = true;
            break;
        }
    }

    if timeout_reached {
        Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Timeout reached while waiting for output"))
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Process ended without the expected output"))
    }
}

pub fn test_init(extra_arg: Vec<&str>) -> TestState {
    let binary_path = env::var("TELEVM_BINARY").unwrap();
    let tmp_dir = get_tmp_dir();
    let test_socket = format!("{}/test-televm.socket", tmp_dir);
    let qmp_socket = format!("{}/qmp.socket", tmp_dir);
    
    let listener = init_socket(&test_socket);
    
    let shared_path = env::var("SHARED_PATH").unwrap();
    let mut child = Command::new(binary_path)
        // .args(["-smp", &format!("cpus=1,maxcpus=2,sockets=2")])
        // .args(["-m", &format!("1G")])
        .args(["-kernel", &format!("{}/Image-6.9", shared_path)])
        .args(["-append", &format!("root=/dev/vda rw console=ttyS0")])
        .args(["-drive", &format!("id=rootfs,file={}/rootfs_guest.ext4", shared_path)])
        .args(["-device", &format!("virtio-blk-device,drive=rootfs,id=blk1")])
        .args(["-serial", &format!("stdio")])
        // .args(["-netdev", &format!("tap,id=net0,ifname=tap0")])
        .args(["-qmp", &format!("unix:{},server,nowait", qmp_socket)])
        .args(["-mod-test", &test_socket])
        .args(extra_arg)
        // .stdout(Stdio::piped()) // 设置了piped
        .spawn()
        .unwrap();

    // 等待套接字就绪，最多等待 num_secs 秒
    let num_secs = 360;

    // 等待超时
    thread::sleep(Duration::from_secs(num_secs)); 
    // 等待特定的输出 // let output = wait_for_output(&mut child, "Welcome to Ubuntu 22.04 LTS!", Duration::from_secs(num_secs));
    // let child_stdout = child.stdout.take();
    // let output = match child_stdout {
    //     Some(stdout) => wait_for_output(stdout, "Welcome to Ubuntu 22.04 LTS!", Duration::from_secs(num_secs)),
    //     None => Err(std::io::Error::new(std::io::ErrorKind::Other, "Child process stdout is not available")),
    // };
    // match output {
    //     Ok(_) => println!("Virtual machine is ready."),
    //     Err(e) => eprintln!("Error waiting for output: {}", e),
    // };

    let test_sock = StreamHandler::new(socket_accept_wait(listener, Duration::from_secs(num_secs)).unwrap());
    println!("test socket is ready");
    
    // 防止 qmp_sock 尝试连接的时间早于 TeleVM 进程初始化并监听该套接字的时间
    // let qmp_sock = StreamHandler::new(connect_socket(&qmp_socket));
    match wait_for_socket(&qmp_socket, num_secs) {
        Ok(()) => {
            println!("Socket is ready, proceeding with QMP connection");
            // 继续进行 QMP 连接
            let qmp_sock = StreamHandler::new(connect_socket(&qmp_socket).unwrap());

            TestState::new(child, test_sock, qmp_sock, tmp_dir)
        },
        Err(e) => {
            eprintln!("Failed to connect to QMP socket: {}", e);
            
            let qmp_sock = StreamHandler::new(connect_socket(&qmp_socket).unwrap());
            TestState::new(child, test_sock, qmp_sock, tmp_dir)
            // TestState::new(child, qmp_sock, tmp_dir)
        },
    }
}
