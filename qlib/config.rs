// Copyright (c) 2021 Quark Container Authors / 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Config {
    pub DebugLevel: DebugLevel,
    pub KernelMemSize: u64,
    pub LogType: LogType,
    pub LogLevel: LogLevel,
    pub UringIO: bool,
    pub UringBuf: bool,
    pub UringFixedFile: bool,
    pub EnableAIO: bool,
    pub PrintException: bool,
    pub KernelPagetable: bool,
    pub PerfDebug: bool,
    pub UringStatx: bool,
    pub FileBufWrite: bool,
    pub MmapRead: bool,
    pub AsyncAccept: bool,
    pub EnableRDMA: bool,
    pub RDMAPort: u8,
    pub PerSandboxLog: bool,
    pub ReserveCpuCount: usize,
    pub ShimMode: bool,
    pub EnableInotify: bool,
    pub ReaddirCache: bool,
    pub HiberODirect: bool,
    pub DisableCgroup: bool,
}

impl Config {
    pub fn SyncPrint(&self) -> bool {
        return self.LogType == LogType::Sync;
    }

    pub fn Async(&self) -> bool {
        return self.LogType == LogType::Async;
    }
}

impl Config {}

impl Default for Config {
    fn default() -> Self {
        return Self {
            DebugLevel: DebugLevel::Off,
            KernelMemSize: 16, // GB
            LogType: LogType::Sync,
            LogLevel: LogLevel::Simple,
            UringIO: true,
            UringBuf: true,
            UringFixedFile: false,
            EnableAIO: false,
            PrintException: false,
            KernelPagetable: false,
            PerfDebug: true,
            UringStatx: false,
            FileBufWrite: true,
            MmapRead: true,
            AsyncAccept: true,
            EnableRDMA: false,
            RDMAPort: 1,
            PerSandboxLog: false,
            ReserveCpuCount: 2,
            ShimMode: false,
            EnableInotify: false,
            ReaddirCache: true,
            HiberODirect: true,
            DisableCgroup: true,
        };
    }
}

#[derive(Clone, Copy, Debug, PartialOrd, Ord, Eq, PartialEq, Serialize, Deserialize)]
pub enum DebugLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Default for DebugLevel {
    fn default() -> Self {
        return Self::Off;
    }
}

pub const ENABLE_BUFF_IO: bool = false;

#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LogLevel {
    None,
    Simple,
    Complex,
}

impl Default for LogLevel {
    fn default() -> Self {
        return Self::None;
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LogType {
    Sync,
    Async,
}
