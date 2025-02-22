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

use alloc::vec::Vec;
use kvm_ioctls::Kvm;
use libc;
use nix::fcntl::*;
use nix::mount::MsFlags;
use nix::sys::stat::Mode;
use nix::unistd::getcwd;
use procfs;
use serde_json;
use simplelog::*;
use std::fs::File;
use std::fs::OpenOptions;
use std::fs::{canonicalize, create_dir_all};
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::super::super::console::pty::*;
use super::super::super::console::unix_socket::UnixSocket;
use super::super::super::namespace::*;
use super::super::super::qlib::common::*;
use super::super::super::qlib::config::DebugLevel;
use super::super::super::qlib::linux_def::*;
use super::super::super::qlib::path::*;
use super::super::super::qlib::unix_socket;
use super::super::super::ucall::ucall::*;
use super::super::super::ucall::usocket::*;
use super::super::super::util::*;
use super::super::super::QUARK_CONFIG;
use super::super::cmd::config::*;
use super::super::container::container::*;
use super::super::container::mounts::*;
use super::super::container::nix_ext::*;
use super::super::oci::*;
use super::super::shim::container_io::*;
use super::super::specutils::specutils::*;
use super::console::*;
use super::loader::*;
use super::signal_handle::*;
use super::util::*;
use super::vm::*;

const QUARK_SANDBOX_ROOT_PATH: &str = "/var/lib/quark/";

pub struct NSRestore {
    pub fd: i32,
    pub flag: i32,
    pub typ: LinuxNamespaceType,
}

impl Drop for NSRestore {
    fn drop(&mut self) {
        SetNamespace(self.fd, self.flag).unwrap();
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BootArgs {
    pub eventfd: i32,
    pub spec: Spec,
    pub bundleDir: String,
    pub conf: GlobalConfig,
    pub userLog: String,
    pub containerId: String,
    pub ptyfd: Option<i32>,
    pub action: RunAction,
    pub RLimits: Vec<LinuxRlimit>,
    //pub pid: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SandboxProcess {
    pub eventfd: i32,
    pub spec: Spec,
    pub bundleDir: String,
    pub conf: GlobalConfig,
    pub userLog: String,
    pub containerId: String,
    pub action: RunAction,
    pub pivot: bool,
    pub RLimits: Vec<LinuxRlimit>,

    pub CloneFlags: i32,
    pub ToEnterNS: Vec<(i32, i32)>, //mapping from Namespace to namespace fd

    pub UidMappings: Vec<LinuxIDMapping>,
    pub GidMappings: Vec<LinuxIDMapping>,

    pub UserNS: bool,

    pub CCond: Cond,
    pub PCond: Cond,

    pub Rootfs: String,

    /// Root path for this sandbox, FS images for containers running in this sandbox should be mount inside this dir
    pub SandboxRootDir: String,
}

impl SandboxProcess {
    pub fn New(
        gCfg: &GlobalConfig,
        action: RunAction,
        id: &str,
        bundleDir: &str,
        pivot: bool,
    ) -> Result<Self> {
        let specfile = Join(bundleDir, "config.json");

        let mut process = SandboxProcess {
            eventfd: 0,
            spec: Spec::load(&specfile).unwrap(),
            bundleDir: bundleDir.to_string(),
            conf: gCfg.Copy(),
            userLog: "".to_string(),
            containerId: id.to_string(),
            action: action,
            pivot: pivot,
            RLimits: Vec::new(),

            CloneFlags: 0,
            ToEnterNS: Vec::new(),
            UidMappings: Vec::new(),
            GidMappings: Vec::new(),
            UserNS: false,
            CCond: Cond::New()?,
            PCond: Cond::New()?,
            Rootfs: "".to_string(),
            SandboxRootDir: Join(QUARK_SANDBOX_ROOT_PATH, id),
        };

        let spec = &process.spec;

        if !IsAbs(&spec.root.path) {
            process.Rootfs = Join(bundleDir, &spec.root.path);
        } else {
            process.Rootfs = spec.root.path.to_string();
        }

        process.CollectNamespaces()?;

        return Ok(process);
    }

    pub fn Run(&self, controlSock: i32, rdmaSvcCliSock: i32) {
        let id = &self.containerId;
        let sid = unsafe {
            //signal (SIGHUP, SIG_IGN);
            libc::setsid()
        };

        if sid < 0 {
            panic!("SandboxProcess setsid fail");
        }

        PrepareHandler().unwrap();

        let kvmfd = Kvm::open_with_cloexec(false).expect("can't open kvm");
        let mut args = Args::default();
        args.ID = id.to_string();
        args.KvmFd = kvmfd;
        args.Spec = Spec::from_string(&self.spec.to_string().unwrap()).unwrap();
        args.AutoStart = self.action == RunAction::Run;
        args.BundleDir = self.bundleDir.to_string();
        args.Pivot = self.pivot;
        args.Rootfs = Join(QUARK_SANDBOX_ROOT_PATH, id.as_str());
        args.ControlSock = controlSock;
        args.RDMASvcCliSock = rdmaSvcCliSock;

        let exitStatus = match VirtualMachine::Init(args) {
            Ok(mut vm) => {
                let ret = vm.run().expect("vm.run() fail");
                ret
            }
            Err(e) => {
                info!("vm.init() failed, error is {:?}", e);
                panic!("error is {:?}", e)
            }
        };

        unsafe { libc::_exit(exitStatus) }
    }

    /// Root path for this sandbox on host fs, rootfs for containers running in this sandbox should be mount inside this dir
    fn MakeSandboxRootDirectory(&self) -> Result<()> {
        debug!(
            "Creating the sandboxRootDir at {}",
            self.SandboxRootDir.as_str()
        );
        match create_dir_all(self.SandboxRootDir.as_str()) {
            Ok(()) => (),
            Err(_e) => return Err(Error::Common(String::from("failed creating directory"))),
        }
        let rbindFlags = libc::MS_REC | libc::MS_BIND;

        // convert sandbox Root Dir to a mount point
        let ret = Util::Mount(
            &self.SandboxRootDir,
            &self.SandboxRootDir,
            "",
            rbindFlags | libc::MS_SHARED,
            "",
        );
        if ret < 0 {
            panic!("InitRootfs: mount sandboxRootDir fails, error is {}", ret);
        }
        let rootContainerPath = Join(&self.SandboxRootDir, &self.containerId);
        match create_dir_all(&rootContainerPath) {
            Ok(()) => (),
            Err(_e) => panic!("failed to create dir to mount containerrootPath"),
        };
        let ret = Util::Mount(
            &self.Rootfs,
            &rootContainerPath,
            "",
            rbindFlags | libc::MS_SHARED,
            "",
        );
        if ret < 0 {
            panic!("InitRootfs: mount rootfs fail, error is {}", ret);
        }

        return Ok(());
    }

    pub fn CollectNamespaces(&mut self) -> Result<()> {
        let mut cf = 0;
        let spec = &self.spec;
        let nss = &spec.linux.as_ref().unwrap().namespaces;

        for ns in nss {
            //don't use os pid namespace as there is pid namespace support in qkernel
            if ns.typ == LinuxNamespaceType::pid {
                continue;
            }

            let space = ns.typ as i32;

            if ns.path.len() == 0 {
                cf |= space;
            } else {
                let fd = Open(&ns.path, OFlag::empty(), Mode::empty())?;
                self.ToEnterNS.push((space, fd))
            }
        }

        //todo: handle mount ns separated, to avoid crash OS when pivot root
        cf |= LinuxNamespaceType::mount as i32;

        if cf & LinuxNamespaceType::user as i32 != 0 {
            self.UserNS = true;
        }

        self.CloneFlags = cf;
        return Ok(());
    }

    pub fn EnableNamespace(&self) -> Result<()> {
        let mut mountFd = -1;

        if self.UserNS {
            Unshare(CloneOp::CLONE_NEWUSER)?;
        }

        self.CCond.Notify()?;
        self.PCond.Wait()?;

        if self.UserNS {
            SetID(0, 0)?;
        }

        error!("EnableNamespace ToEnterNS is {:?}", &self.ToEnterNS);

        for &(space, fd) in &self.ToEnterNS {
            if space == LinuxNamespaceType::mount as i32 {
                // enter mount ns last
                mountFd = fd;
                continue;
            }

            SetNamespace(fd, space)?;
            Close(fd)?;
            if space == LinuxNamespaceType::user as i32 {
                SetID(0, 0)?;
            }
        }

        Unshare(self.CloneFlags & !(LinuxNamespaceType::user as i32))?;

        if self.CloneFlags & LinuxNamespaceType::mount as i32 != 0 {
            self.InitRootfs()?;
        }

        if mountFd != -1 {
            SetNamespace(mountFd, LinuxNamespaceType::mount as i32)?;
            Close(mountFd)?;
        }
        // Print mountinfo in quark log if the level is debug
        if QUARK_CONFIG.lock().DebugLevel >= DebugLevel::Debug {
            let proc = procfs::process::Process::myself().unwrap();
            debug!(
                "mountinfo from sandbox process: {:?}",
                proc.mountinfo()
                    .expect("failed to read mountinfo inside sandbox mountns")
            )
        }

        return Ok(());
    }

    pub fn InitRootfs(&self) -> Result<()> {
        let privateFlags = libc::MS_REC | libc::MS_SLAVE;
        let rbindFlags = libc::MS_REC | libc::MS_BIND;

        // convert the root mount on current host as private, so nothing will be propagated outside current mount ns
        if Util::Mount("", "/", "", privateFlags, "") < 0 {
            panic!("mount root fail")
        }
        // convert sandbox Root Dir to a mount point
        let ret = Util::Mount(
            &self.SandboxRootDir,
            &self.SandboxRootDir,
            "",
            rbindFlags,
            "",
        );
        if ret < 0 {
            panic!("InitRootfs: mount sandboxRootDir fails, error is {}", ret);
        }

        let spec = &self.spec;
        let linux = spec.linux.as_ref().unwrap();

        //these should also show up under rootContainerpath, as it's set as rbind in the parent mount.
        for m in &spec.mounts {
            // TODO: check for nasty destinations involving symlinks and illegal
            //       locations.
            // NOTE: this strictly is less permissive than runc, which allows ..
            //       as long as the resulting path remains in the rootfs. There
            //       is no good reason to allow this so we just forbid it
            if !m.destination.starts_with('/') || m.destination.contains("..") {
                let msg = format!("invalid mount destination: {}", m.destination);
                return Err(Error::Common(msg));
            }
            let (flags, data) = parse_mount(m);
            if m.typ == "cgroup" {
                //mount_cgroups(m, rootfs, flags, &data, &linux.mount_label, cpath)?;
                // won't mount cgroup
                continue;
            } else if m.destination == "/dev" {
                // dev can't be read only yet because we have to mount devices
                MountFrom(
                    m,
                    &self.Rootfs,
                    flags & !MsFlags::MS_RDONLY,
                    &data,
                    &linux.mount_label,
                )?;
            } else {
                MountFrom(m, &self.Rootfs, flags, &data, &linux.mount_label)?;
            }
        }

        // chdir into the rootfs so we can make devices with simpler paths
        let olddir = getcwd().map_err(|e| Error::IOError(format!("io error is {:?}", e)))?;

        if Util::Chdir(&self.Rootfs) < 0 {
            panic!("chdir fail")
        }

        //default_symlinks()?;
        create_devices(&linux.devices, false)?;
        //ensure_ptmx()?;

        if Util::Chdir(olddir.as_path().to_str().unwrap()) == -1 {
            panic!("chdir fail")
        }

        let rootContainerPath = Join(&self.SandboxRootDir, &self.containerId);
        match create_dir_all(&rootContainerPath) {
            Ok(()) => (),
            Err(_e) => panic!("failed to create dir to mount containerrootPath"),
        };
        let ret = Util::Mount(&self.Rootfs, &rootContainerPath, "", rbindFlags, "");
        if ret < 0 {
            panic!("InitRootfs: mount rootfs fail, error is {}", ret);
        }

        let tmpfolder = Join(&self.SandboxRootDir, "tmp");
        match create_dir_all(&tmpfolder) {
            Ok(()) => (),
            Err(_e) => panic!("failed to create dir to mount containerrootPath"),
        };
        let ret = Util::Mount(&self.Rootfs, &tmpfolder, "tmpfs", rbindFlags, "");
        if ret < 0 {
            panic!("InitRootfs: mount rootfs fail, error is {}", ret);
        }

        return Ok(());
    }

    pub fn CreatePipe() -> Result<(i32, i32)> {
        use libc::*;

        let mut fds: [i32; 2] = [0, 0];
        let ret = unsafe { pipe(&mut fds[0] as *mut i32) };

        if ret < 0 {
            return Err(Error::SysError(errno::errno().0));
        }

        return Ok((fds[0], fds[1]));
    }

    pub fn Execv(
        &self,
        terminal: bool,
        consoleSocket: &str,
        detach: bool,
    ) -> Result<(i32, Console)> {
        use libc::*;

        let mut cmd = Command::new(&ReadLink(EXE_PATH)?);
        cmd.arg("boot");

        let (fd0, fd1) = Self::CreatePipe()?;

        unsafe {
            //enable FD_CLOEXEC for pipefd1 so that it will auto close in child process
            let ret = fcntl(fd1, F_SETFD, FD_CLOEXEC);
            if ret < 0 {
                panic!("fcntl fail");
            }
        };

        let mut file1 = unsafe { File::from_raw_fd(fd1) };

        cmd.arg("--pipefd");
        cmd.arg(&format!("{}", fd0));

        let mut ptyMaster = None;

        if terminal {
            let (master, slave) = NewPty()?;

            unsafe {
                let tty = slave.dup()?;
                cmd.stdin(Stdio::from_raw_fd(tty));
                cmd.stdout(Stdio::from_raw_fd(tty));
                cmd.stderr(Stdio::from_raw_fd(tty));
            }
            if !detach {
                ptyMaster = Some(master);
            } else {
                assert!(consoleSocket.len() > 0);
                let client = UnixSocket::NewClient(consoleSocket)?;
                client.SendFd(master.as_raw_fd())?
            }
        } /*else {
              if !detach {
                  cmd.stdin(Stdio::piped());
                  cmd.stdout(Stdio::piped());
                  cmd.stderr(Stdio::piped());
              }
          }*/

        let child = cmd.spawn().expect("Boot command failed to start");

        {
            //close fd1
            let _file0 = unsafe { File::from_raw_fd(fd0) };
        }

        serde_json::to_writer(&mut file1, &self)
            .map_err(|e| Error::IOError(format!("To BootCmd io::error is {:?}", e)))?;

        //close files
        drop(file1);

        self.Parent(child.id() as i32)?;

        let console = if detach {
            Console::Detach
        } else {
            if terminal {
                let ptyConsole = PtyConsole::New(ptyMaster.unwrap());
                Console::PtyConsole(ptyConsole)
            } else {
                /*let stdin = child.stdin.take().unwrap().into_raw_fd();
                let stdout = child.stdout.take().unwrap().into_raw_fd();
                let stderr = child.stderr.take().unwrap().into_raw_fd();

                let stdioConsole = StdioConsole::New(stdin, stdout, stderr);
                Console::StdioConsole(stdioConsole)*/
                Console::Detach
            }
        };

        return Ok((child.id() as i32, console));
    }

    pub fn Execv1(&self, io: &ContainerIO) -> Result<i32> {
        use libc::*;

        let mut cmd = Command::new(&ReadLink(EXE_PATH)?);
        cmd.arg("boot");

        let (fd0, fd1) = Self::CreatePipe()?;

        unsafe {
            //enable FD_CLOEXEC for pipefd1 so that it will auto close in child process
            let ret = fcntl(fd1, F_SETFD, FD_CLOEXEC);
            if ret < 0 {
                panic!("fcntl fail");
            }
        };

        let mut file1 = unsafe { File::from_raw_fd(fd1) };

        cmd.arg("--pipefd");
        cmd.arg(&format!("{}", fd0));

        io.Set(&mut cmd)?;

        let child = cmd.spawn().expect("Boot command failed to start");

        {
            //close fd0
            let _file0 = unsafe { File::from_raw_fd(fd0) };
        }

        io.CloseAfterStart();

        serde_json::to_writer(&mut file1, &self)
            .map_err(|e| Error::IOError(format!("To BootCmd io::error is {:?}", e)))?;

        //close files
        drop(file1);

        self.Parent(child.id() as i32)?;

        return Ok(child.id() as i32);
    }

    pub fn StartLog(&self) {
        std::fs::remove_file(&self.conf.DebugLog).ok();

        CombinedLogger::init(vec![
            TermLogger::new(LevelFilter::Error, Config::default(), TerminalMode::Mixed).unwrap(),
            WriteLogger::new(
                self.conf.DebugLevel.ToLevelFilter(),
                Config::default(),
                File::create(&self.conf.DebugLog).unwrap(),
            ),
        ])
        .unwrap();
    }

    pub fn Child(&self) -> Result<()> {
        //self.StartLog();

        // set rlimits (before entering user ns)
        for rlimit in &self.RLimits {
            SetRLimit(rlimit.typ as u32, rlimit.soft, rlimit.hard)?;
        }

        let addr = ControlSocketAddr(&self.containerId);
        let controlSock = USocket::CreateServerSocket(&addr).expect("can't create control sock");
        let mut rdmaSvcCliSock = 0;
        if QUARK_CONFIG.lock().EnableRDMA {
            rdmaSvcCliSock = unix_socket::UnixSocket::NewClient("/var/quarkrdma/rdma_srv_socket").unwrap();
        }
        self.MakeSandboxRootDirectory()?;
        self.EnableNamespace()?;

        self.Run(controlSock, rdmaSvcCliSock);
        panic!("Child: should never reach here");
    }

    pub fn Parent(&self, child: i32) -> Result<()> {
        let linux = self.spec.linux.as_ref().unwrap();

        self.CCond.Wait()?;

        if self.UserNS {
            // write uid/gid map
            WriteIDMapping(&format!("/proc/{}/uid_map", child), &linux.uid_mappings)?;
            WriteIDMapping(&format!("/proc/{}/gid_map", child), &linux.gid_mappings)?;
        }

        self.PCond.Notify()?;

        return Ok(());
    }
}

fn MountFrom(m: &Mount, rootfs: &str, flags: MsFlags, data: &str, label: &str) -> Result<()> {
    let d;
    if !label.is_empty() && m.typ != "proc" && m.typ != "sysfs" {
        if data.is_empty() {
            d = format! {"context=\"{}\"", label};
        } else {
            d = format! {"{},context=\"{}\"", data, label};
        }
    } else {
        d = data.to_string();
    }

    let dest = format! {"{}{}", rootfs, &m.destination};

    debug!(
        "mounting {} to {} as {} with data '{}'",
        &m.source, &m.destination, &m.typ, &d
    );

    let src = if m.typ == "bind" {
        let src =
            canonicalize(&m.source).map_err(|e| Error::IOError(format!("io error is {:?}", e)))?;
        let dir = if src.is_file() {
            Path::new(&dest).parent().unwrap()
        } else {
            Path::new(&dest)
        };
        if let Err(e) = create_dir_all(&dir) {
            debug!("ignoring create dir fail of {:?}: {}", &dir, e)
        }
        // make sure file exists so we can bind over it
        if src.is_file() {
            if let Err(e) = OpenOptions::new().create(true).write(true).open(&dest) {
                debug!("ignoring touch fail of {:?}: {}", &dest, e)
            }
        }
        src
    } else {
        if let Err(e) = create_dir_all(&dest) {
            debug!("ignoring create dir fail of {:?}: {}", &dest, e)
        }
        PathBuf::from(&m.source)
    };

    let ret = Util::Mount(
        src.as_path().to_str().unwrap(),
        &dest,
        &m.typ,
        flags.bits(),
        &d,
    );
    if ret < 0 {
        if ret == -SysErr::EINVAL {
            return Err(Error::SysError(-ret as i32));
        }

        // try again without mount label
        let ret = Util::Mount(
            src.as_path().to_str().unwrap(),
            &dest,
            &m.typ,
            flags.bits(),
            "",
        );
        if ret < 0 {
            return Err(Error::SysError(-ret as i32));
        }

        if let Err(e) = setfilecon(&dest, label) {
            warn! {"could not set mount label of {} to {}: {:?}",
            &m.destination, &label, e};
        }
    }

    // remount bind mounts if they have other flags (like MsFlags::MS_RDONLY)
    if flags.contains(MsFlags::MS_BIND)
        && flags.intersects(
            !(MsFlags::MS_REC
                | MsFlags::MS_REMOUNT
                | MsFlags::MS_BIND
                | MsFlags::MS_PRIVATE
                | MsFlags::MS_SHARED
                | MsFlags::MS_SLAVE),
        )
    {
        let ret = Util::Mount(&dest, &dest, "", (flags | MsFlags::MS_REMOUNT).bits(), "");
        if ret < 0 {
            return Err(Error::SysError(-ret as i32));
        }
    }
    Ok(())
}
