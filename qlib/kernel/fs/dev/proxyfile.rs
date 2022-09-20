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

use crate::qlib::mutex::*;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::ops::Deref;

use super::super::super::super::auth::*;
use super::super::super::super::common::*;
use super::super::super::super::linux_def::*;
use super::super::super::kernel::time::*;
use super::super::super::kernel::waiter::qlock::*;
use super::super::super::kernel::waiter::*;
use super::super::super::socket::unix::transport::unix::*;
use super::super::super::task::*;
use super::super::super::uid::*;
use super::super::host::hostinodeop::*;
use super::super::host::util::*;

use super::super::attr::*;
use super::super::dentry::*;
use super::super::dirent::*;
use super::super::file::*;
use super::super::flags::*;
use super::super::fsutil::file::*;
use super::super::fsutil::inode::*;
use super::super::inode::*;
use super::super::mount::*;
use crate::qlib::kernel::fs::filesystems::*;
use crate::qlib::kernel::fs::host::fs::*;
use crate::qlib::kernel::fs::host::diriops::*;

use core::sync::atomic::{AtomicI32, Ordering};
use super::super::super::Kernel::HostSpace;
use alloc::collections::btree_map::BTreeMap;

pub type NvHandle = u32;

#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Default, Copy, Clone)]
pub struct NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS {
    pub sizeOfStrings: u32,
    pub pDriverVersionBuffer: u64,
    pub pVersionBuffer: u64,
    pub pTitleBuffer: u64,
    pub changelistNumber: u32,
    pub officialChangelistNumber: u32
}


#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Default, Copy, Clone)]
pub struct NVOS21_PARAMETERS {
    pub hRoot: NvHandle,
    pub hObjectParent: NvHandle,
    pub hObjectNew: NvHandle,
    pub hClass: u32,
    pub pAllocParms: u64,
    pub status: u32
}

#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Default, Copy, Clone)]
pub struct NVOS64_PARAMETERS {
    pub hRoot: NvHandle,
    pub hObjectParent: NvHandle,
    pub hObjectNew: NvHandle,
    pub hClass: u32,
    pub pAllocParms: u64,
    pub pRightsRequested: u64,
    pub status: u32
}

#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Default, Copy, Clone)]
pub struct NVOS54_PARAMETERS {
    pub hClient: NvHandle,
    pub hObject: NvHandle,
    pub cmd: u32,
    pub flags: u32,
    pub params: u64,
    pub paramsSize: u32,
    pub status: u32
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct nv_ioctl_register_fd {
    pub ctl_fd: i32
}

#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Default, Copy, Clone)]
pub struct NV0080_CTRL_HOST_GET_CAPS_PARAMS {
    pub capsTblSize: u32,
    pub capsTbl: u64
}

#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Default, Copy, Clone)]
pub struct NV0080_CTRL_GPU_GET_CLASSLIST_PARAMS {
    pub numClasses: u32,
    pub classList: u64
}

#[derive(Clone)]
pub struct ProxyDevice(pub Arc<QRwLock<InodeSimpleAttributesInternal>>);

impl Default for ProxyDevice {
    fn default() -> Self {
        return Self(Arc::new(QRwLock::new(Default::default())));
    }
}

impl Deref for ProxyDevice {
    type Target = Arc<QRwLock<InodeSimpleAttributesInternal>>;

    fn deref(&self) -> &Arc<QRwLock<InodeSimpleAttributesInternal>> {
        &self.0
    }
}

impl ProxyDevice {
    pub fn New(task: &Task, owner: &FileOwner, mode: &FileMode) -> Self {
        let attr = InodeSimpleAttributesInternal::New(
            task,
            owner,
            &FilePermissions::FromMode(*mode),
            FSMagic::TMPFS_MAGIC,
        );
        return Self(Arc::new(QRwLock::new(attr)));
    }
}

impl InodeOperations for ProxyDevice {
    fn as_any(&self) -> &Any {
        return self;
    }

    fn IopsType(&self) -> IopsType {
        return IopsType::ProxyDevice;
    }

    fn InodeType(&self) -> InodeType {
        return InodeType::CharacterDevice;
    }

    fn InodeFileType(&self) -> InodeFileType {
        return InodeFileType::Null;
    }

    fn WouldBlock(&self) -> bool {
        return true;
    }

    fn Lookup(&self, _task: &Task, _dir: &Inode, _name: &str) -> Result<Dirent> {
        return Err(Error::SysError(SysErr::ENOTDIR));
    }

    fn Create(
        &self,
        _task: &Task,
        _dir: &mut Inode,
        _name: &str,
        _flags: &FileFlags,
        _perm: &FilePermissions,
    ) -> Result<File> {
        return Err(Error::SysError(SysErr::ENOTDIR));
    }

    fn CreateDirectory(
        &self,
        _task: &Task,
        _dir: &mut Inode,
        _name: &str,
        _perm: &FilePermissions,
    ) -> Result<()> {
        return Err(Error::SysError(SysErr::ENOTDIR));
    }

    fn CreateLink(
        &self,
        _task: &Task,
        _dir: &mut Inode,
        _oldname: &str,
        _newname: &str,
    ) -> Result<()> {
        return Err(Error::SysError(SysErr::ENOTDIR));
    }

    fn CreateHardLink(
        &self,
        _task: &Task,
        _dir: &mut Inode,
        _target: &Inode,
        _name: &str,
    ) -> Result<()> {
        return Err(Error::SysError(SysErr::ENOTDIR));
    }

    fn CreateFifo(
        &self,
        _task: &Task,
        _dir: &mut Inode,
        _name: &str,
        _perm: &FilePermissions,
    ) -> Result<()> {
        return Err(Error::SysError(SysErr::ENOTDIR));
    }

    fn Remove(&self, _task: &Task, _dir: &mut Inode, _name: &str) -> Result<()> {
        return Err(Error::SysError(SysErr::ENOTDIR));
    }

    fn RemoveDirectory(&self, _task: &Task, _dir: &mut Inode, _name: &str) -> Result<()> {
        return Err(Error::SysError(SysErr::ENOTDIR));
    }

    fn Rename(
        &self,
        _task: &Task,
        _dir: &mut Inode,
        _oldParent: &Inode,
        _oldname: &str,
        _newParent: &Inode,
        _newname: &str,
        _replacement: bool,
    ) -> Result<()> {
        return Err(Error::SysError(SysErr::EINVAL));
    }

    fn Bind(
        &self,
        _task: &Task,
        _dir: &Inode,
        _name: &str,
        _data: &BoundEndpoint,
        _perms: &FilePermissions,
    ) -> Result<Dirent> {
        return Err(Error::SysError(SysErr::ENOTDIR));
    }

    fn BoundEndpoint(&self, _task: &Task, _inode: &Inode, _path: &str) -> Option<BoundEndpoint> {
        return None;
    }

    fn GetFile(
        &self,
        task: &Task,
        _dir: &Inode,
        dirent: &Dirent,
        flags: FileFlags,
    ) -> Result<File> {
        let rootInode = task.mountNS.root.Inode();
        let rootIops = rootInode.lock().InodeOp.clone();
        let devDirent = rootIops.Lookup(task, &rootInode, "dev")?;

        let devInode = devDirent.Inode();
        let deviops = devInode.lock().InodeOp.clone();
        error!("deviops type is {:?}", deviops.IopsType());
        let hostiops = deviops
            .as_any()
            .downcast_ref::<HostDirOp>()
            .expect("targetIops convert fail")
            .clone();

        let devfd = hostiops.FD();

        let (fd, fstat) = OpenAt(devfd, "nvidiactl", flags.ToLinux())?;

        let fops = ProxyFileOperations::NewFromfd(task, fd, &fstat)?;

        let f = FileInternal {
            UniqueId: NewUID(),
            Dirent: dirent.clone(),
            flags: QMutex::new((flags, None)),
            offset: QLock::New(0),
            FileOp: Arc::new(fops.into()),
        };

        return Ok(File(Arc::new(f)));
    }

    fn UnstableAttr(&self, _task: &Task) -> Result<UnstableAttr> {
        let u = self.read().unstable;
        return Ok(u);
    }

    fn Getxattr(&self, _dir: &Inode, _name: &str, _size: usize) -> Result<Vec<u8>> {
        return Err(Error::SysError(SysErr::EOPNOTSUPP));
    }

    fn Setxattr(&self, _dir: &mut Inode, _name: &str, _value: &[u8], _flags: u32) -> Result<()> {
        return Err(Error::SysError(SysErr::EOPNOTSUPP));
    }

    fn Listxattr(&self, _dir: &Inode, _size: usize) -> Result<Vec<String>> {
        return Err(Error::SysError(SysErr::EOPNOTSUPP));
    }

    fn Check(&self, task: &Task, inode: &Inode, reqPerms: &PermMask) -> Result<bool> {
        return ContextCanAccessFile(task, inode, reqPerms);
    }

    fn SetPermissions(&self, task: &Task, _dir: &mut Inode, p: FilePermissions) -> bool {
        self.write().unstable.SetPermissions(task, &p);
        return true;
    }

    fn SetOwner(&self, task: &Task, _dir: &mut Inode, owner: &FileOwner) -> Result<()> {
        self.write().unstable.SetOwner(task, owner);
        return Ok(());
    }

    fn SetTimestamps(&self, task: &Task, _dir: &mut Inode, ts: &InterTimeSpec) -> Result<()> {
        self.write().unstable.SetTimestamps(task, ts);
        return Ok(());
    }

    fn Truncate(&self, _task: &Task, _dir: &mut Inode, _size: i64) -> Result<()> {
        return Ok(());
    }

    fn Allocate(&self, _task: &Task, _dir: &mut Inode, _offset: i64, _length: i64) -> Result<()> {
        return Ok(());
    }

    fn ReadLink(&self, _task: &Task, _dir: &Inode) -> Result<String> {
        return Err(Error::SysError(SysErr::ENOLINK));
    }

    fn GetLink(&self, _task: &Task, _dir: &Inode) -> Result<Dirent> {
        return Err(Error::SysError(SysErr::ENOLINK));
    }

    fn AddLink(&self, _task: &Task) {
        self.write().unstable.Links += 1;
    }

    fn DropLink(&self, _task: &Task) {
        self.write().unstable.Links -= 1;
    }

    fn IsVirtual(&self) -> bool {
        return true;
    }

    fn Sync(&self) -> Result<()> {
        return Err(Error::SysError(SysErr::ENOSYS));
    }

    fn StatFS(&self, _task: &Task) -> Result<FsInfo> {
        return Err(Error::SysError(SysErr::ENOSYS));
    }

    fn Mappable(&self) -> Result<MMappable> {
        return Err(Error::SysError(SysErr::ENODEV));
    }
}

pub struct ProxyFileOperations {
    pub InodeOp: HostInodeOp,
}

impl ProxyFileOperations {
    pub fn NewFromfd(task: &Task, fd: i32, fstat: &LibcStat) -> Result<Self> {
        let fileOwner = task.FileOwner();

        //let fileFlags = File::GetFileFlags(fd)?;
        
        let msrc = MountSource::NewHostMountSource(
            &"/".to_string(),
            &fileOwner,
            &WhitelistFileSystem::New(),
            &MountSourceFlags::default(),
            false,
        );

        let iops = HostInodeOp::New(
            &msrc.MountSourceOperations.clone(),
            fd,
            fstat.WouldBlock(),
            &fstat,
            true,
            false
        );

        return Ok(Self {
            InodeOp: iops
        })
    }
    
    pub fn Fd(&self) -> i32 {
        return self.InodeOp.FD();
    }
}

impl Waitable for ProxyFileOperations {
    fn Readiness(&self, _task: &Task, mask: EventMask) -> EventMask {
        return mask;
    }

    fn EventRegister(&self, _task: &Task, _e: &WaitEntry, _mask: EventMask) {}

    fn EventUnregister(&self, _task: &Task, _e: &WaitEntry) {}
}

impl SpliceOperations for ProxyFileOperations {}

impl FileOperations for ProxyFileOperations {
    fn as_any(&self) -> &Any {
        return self;
    }

    fn FopsType(&self) -> FileOpsType {
        return FileOpsType::ProxyFileOperations;
    }

    fn Seekable(&self) -> bool {
        return true;
    }

    fn Seek(&self, task: &Task, f: &File, whence: i32, current: i64, offset: i64) -> Result<i64> {
        return SeekWithDirCursor(task, f, whence, current, offset, None);
    }

    fn ReadDir(
        &self,
        _task: &Task,
        _f: &File,
        _offset: i64,
        _serializer: &mut DentrySerializer,
    ) -> Result<i64> {
        return Err(Error::SysError(SysErr::ENOTDIR));
    }

    fn ReadAt(
        &self,
        task: &Task,
        f: &File,
        dsts: &mut [IoVec],
        offset: i64,
        blocking: bool,
    ) -> Result<i64> {
        let hostIops = self.InodeOp.clone();

        error!("read at proxy ...1");
        let ret = hostIops.ReadAt(task, f, dsts, offset, blocking);
        error!("read at proxy ...2");
        return ret;
    }

    fn WriteAt(
        &self,
        task: &Task,
        f: &File,
        srcs: &[IoVec],
        offset: i64,
        blocking: bool,
    ) -> Result<i64> {
        let hostIops = self.InodeOp.clone();

        hostIops.WriteAt(task, f, srcs, offset, blocking)
    }

    fn Append(&self, task: &Task, f: &File, srcs: &[IoVec]) -> Result<(i64, i64)> {
        let n = self.WriteAt(task, f, srcs, 0, false)?;
        return Ok((n, 0));
    }

    fn Fsync(
        &self,
        _task: &Task,
        _f: &File,
        _start: i64,
        _end: i64,
        _syncType: SyncType,
    ) -> Result<()> {
        return Ok(());
    }

    fn Flush(&self, _task: &Task, _f: &File) -> Result<()> {
        return Ok(());
    }

    fn UnstableAttr(&self, task: &Task, f: &File) -> Result<UnstableAttr> {
        let inode = f.Dirent.Inode();
        return inode.UnstableAttr(task);
    }

    fn Ioctl(&self, task: &Task, _f: &File, fd: i32, request: u64, val: u64) -> Result<()> {
        if fd <= 2 {
            return Err(Error::SysError(SysErr::ENOTTY));
        }

        static CTL_HOST_FD: AtomicI32 = AtomicI32::new(0);

        let mut size: u32 = ((request >> 16) as u32) & 16383;
        if request == 0x30000001 { size = 16; }
        if request == 0x27 { size = 8; }

        error!("LOOKATHERE!!! fd {}, request {:x}, val {:x}, size: {}", fd, request, val, size);

        let hostIops = self.InodeOp.clone();
        let hostfd = hostIops.HostFd();

        if request == 0xc04846d2 {
            CTL_HOST_FD.store(hostfd, Ordering::Relaxed);
            error!("CONTROL fd/host_fd {}/{}", fd, hostfd);
        }

        if request == 0xc00446c9 {
            let mut data: nv_ioctl_register_fd = task.CopyInObj(val)?;
            error!("BEFORE, fd: {}", data.ctl_fd);
            data.ctl_fd = CTL_HOST_FD.load(Ordering::Relaxed);
            error!("AFTER, fd: {}", data.ctl_fd);
            let res = HostSpace::IoCtl(hostfd, request, &mut data as *const _ as u64);
        
            if res < 0 {
                error!("IOCTL failed!!! res {} ", res);
                return Err(Error::SysError(-res as i32));
            }
            return Ok(());
        }

        let _x: BTreeMap<u32, u32> = [
            (0, 4),
            (1, 4),
            (128, 56),
        ].iter().cloned().collect();

        if request == 0xc020462b {
            if size == 32 {
                let mut data: NVOS21_PARAMETERS = task.CopyInObj(val)?;
                let _res = HostSpace::IoCtl(hostfd, request, &mut data as *const _ as u64);
                task.CopyOutObj(&data, val)?;
                return Ok(());
                //let a = x.get(&data.hClass);
                //let mut data1: Vec<u8> = task.CopyInVec(data.pAllocParms, a as usize)?;
                //data.pAllocParms = data1;
            }
        }
        else if request == 0xc028462b {
            let mut data: NVOS64_PARAMETERS = task.CopyInObj(val)?;
            match _x.get(&data.hClass) {
                Some(sz) => {
                    error!("FOUND size for {}: {}", data.hClass, sz);
                    let tmp = data.pAllocParms;
                    let buffer: Vec<u8> = task.CopyInVec(data.pAllocParms, *sz as usize)?;
                    data.pAllocParms = &buffer[0] as *const _ as u64;
            
                    let res = HostSpace::IoCtl(hostfd, request, &mut data as *const _ as u64);
                
                    if res < 0 {
                        error!("IOCTL failed!!! res {} ", res);
                        return Err(Error::SysError(-res as i32));
                    }

                    task.CopyOutSlice(&buffer, tmp, *sz as usize)?;
                    data.pAllocParms = tmp;
                    task.CopyOutObj(&data, val)?;
                    return Ok(());
                },
                None => {
                    error!("Cannot find pAllocParms size!!!");
                }
            }
        }
        else if request == 0xc020462a {
            let mut data: NVOS54_PARAMETERS = task.CopyInObj(val)?;
            error!("NVOS54_PARAMETERS, BEFORE cmd={:x}, params={:x}, status={}", data.cmd, data.params, data.status);

            if data.cmd == 0x101 {
                let mut versions: NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS = task.CopyInObj(data.params)?;
                error!("sizeOfStrings={}, pDriverVersionBuffer={:x}, pVersionBuffer={:x}, pTitleBuffer={:x}",
                versions.sizeOfStrings, versions.pDriverVersionBuffer, versions.pVersionBuffer, versions.pTitleBuffer);
                let usrAddr1 = versions.pDriverVersionBuffer;
                let usrAddr2 = versions.pVersionBuffer;
                let usrAddr3 = versions.pTitleBuffer;
                let buf1: Vec<u8> = task.CopyInVec(versions.pDriverVersionBuffer, versions.sizeOfStrings as usize)?;
                let buf2: Vec<u8> = task.CopyInVec(versions.pVersionBuffer, versions.sizeOfStrings as usize)?;
                let buf3: Vec<u8> = task.CopyInVec(versions.pTitleBuffer, versions.sizeOfStrings as usize)?;
                versions.pDriverVersionBuffer = &buf1[0] as *const _ as u64;
                versions.pVersionBuffer = &buf2[0] as *const _ as u64;
                versions.pTitleBuffer = &buf3[0] as *const _ as u64;
                let tmp = data.params;
                data.params = &versions as *const _ as u64;
                let res = HostSpace::IoCtl(hostfd, request, &mut data as *const _ as u64);

                if res < 0 {
                    error!("IOCTL failed!!! res {} ", res);
                    return Err(Error::SysError(-res as i32));
                }

                task.CopyOutSlice(&buf1, usrAddr1, versions.sizeOfStrings as usize)?;
                task.CopyOutSlice(&buf2, usrAddr2, versions.sizeOfStrings as usize)?;
                task.CopyOutSlice(&buf3, usrAddr3, versions.sizeOfStrings as usize)?;
                versions.pDriverVersionBuffer = usrAddr1;
                versions.pVersionBuffer = usrAddr2;
                versions.pTitleBuffer = usrAddr3;

                data.params = tmp;
                task.CopyOutObj(&versions, data.params)?;
                task.CopyOutObj(&data, val)?;
                return Ok(());
            }
            else if data.cmd == 0x801401 {
                let mut caps: NV0080_CTRL_HOST_GET_CAPS_PARAMS = task.CopyInObj(data.params)?;
                let tbl = caps.capsTbl;
                let buf: Vec<u8> = task.CopyInVec(caps.capsTbl, 3)?;
                caps.capsTbl = &buf[0] as *const _ as u64;
                let tmp = data.params;
                data.params = &caps as *const _ as u64;
                let res = HostSpace::IoCtl(hostfd, request, &mut data as *const _ as u64);

                if res < 0 {
                    error!("IOCTL failed!!! res {} ", res);
                    return Err(Error::SysError(-res as i32));
                }

                task.CopyOutSlice(&buf, tbl, 3)?;
                caps.capsTbl = tbl;

                data.params = tmp;
                task.CopyOutObj(&caps, data.params)?;
                task.CopyOutObj(&data, val)?;
                return Ok(());
            }
            else if data.cmd == 0x800201 {
                let mut cl: NV0080_CTRL_GPU_GET_CLASSLIST_PARAMS = task.CopyInObj(data.params)?;
                let tbl = cl.classList;
                if tbl != 0 {
                    let buf: Vec<u8> = task.CopyInVec(tbl, 4*cl.numClasses as usize)?;
                    cl.classList = &buf[0] as *const _ as u64;
                    let tmp = data.params;
                    data.params = &cl as *const _ as u64;
                    let res = HostSpace::IoCtl(hostfd, request, &mut data as *const _ as u64);

                    if res < 0 {
                        error!("IOCTL failed!!! res {} ", res);
                        return Err(Error::SysError(-res as i32));
                    }

                    task.CopyOutSlice(&buf, tbl, 4*cl.numClasses as usize)?;
                    cl.classList = tbl;

                    data.params = tmp;
                    task.CopyOutObj(&cl, data.params)?;
                    task.CopyOutObj(&data, val)?;
                    return Ok(());
                }
            }
            
            //let mut data: NVOS54_PARAMETERS = task.CopyInObj(val)?;
            let tmp = data.params;
            let buffer: Vec<u8> = task.CopyInVec(data.params, data.paramsSize as usize)?;
                
            data.params = &buffer[0] as *const _ as u64;
                
            let res = HostSpace::IoCtl(hostfd, request, &mut data as *const _ as u64);
                
            if res < 0 {
                error!("IOCTL failed!!! res {} ", res);
                return Err(Error::SysError(-res as i32));
            }

            task.CopyOutSlice(&buffer, tmp, data.paramsSize as usize)?;
            data.params = tmp;
            error!("NVOS54_PARAMETERS, AFTER cmd={:x}, params={:x}, status={}", data.cmd, data.params, data.status);
            task.CopyOutObj(&data, val)?;
            return Ok(());
        }

        let mut data: Vec<u8> = task.CopyInVec(val, size as usize)?;
        let res = HostSpace::IoCtl(hostfd, request, &mut data[0] as *const _ as u64);
        
        if res < 0 {
            error!("IOCTL failed!!! res {} ", res);
            return Err(Error::SysError(-res as i32));
        }

        task.CopyOutSlice(&data, val, size as usize)?;
        
        return Ok(());
    }

    fn IterateDir(
        &self,
        _task: &Task,
        _d: &Dirent,
        _dirCtx: &mut DirCtx,
        _offset: i32,
    ) -> (i32, Result<i64>) {
        return (0, Err(Error::SysError(SysErr::ENOTDIR)));
    }

    fn Mappable(&self) -> Result<MMappable> {
        return Err(Error::SysError(SysErr::ENODEV));
    }
}

impl SockOperations for ProxyFileOperations {}
