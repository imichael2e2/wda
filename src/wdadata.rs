// Copyright (C) 2023 Michael Lee <imichael2e2@proton.me/...@gmail.com>
//
// Licensed under the MIT License <LICENSE-MIT or
// https://opensource.org/license/mit> or the GNU General Public License,
// Version 3.0 or any later version <LICENSE-GPL or
// https://www.gnu.org/licenses/gpl-3.0.txt>, at your option.
//
// This file may not be copied, modified, or distributed except except in
// compliance with either of the licenses.
//

use crate::error::Result;
use crate::error::WdaError;

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use std::fs;
use std::fs::create_dir_all;

// lock //

#[cfg(target_family = "unix")]
mod lock {
    use std::fs::File;
    use std::os::fd::AsRawFd;

    fn flock(file: &File, flag: libc::c_int) -> std::io::Result<()> {
        let ret = unsafe { libc::flock(file.as_raw_fd(), flag) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn acquire(lock: &File) -> Result<(), u8> {
        flock(lock, libc::LOCK_EX).unwrap();

        Ok(())
    }

    pub fn release(lock: &File) -> Result<(), u8> {
        flock(lock, libc::LOCK_UN).unwrap();

        Ok(())
    }
}

pub(crate) use lock::release as lock_release;

#[cfg(target_family = "windows")]
mod lock {
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;

    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::fileapi::LockFileEx;
    use winapi::um::fileapi::UnlockFileEx;
    use winapi::um::minwinbase::LOCKFILE_EXCLUSIVE_LOCK;
    use winapi::um::minwinbase::LOCKFILE_FAIL_IMMEDIATELY;
    use winapi::um::minwinbase::OVERLAPPED;

    const LOCKED_LEN: u32 = 2; // sizeof u16

    pub fn acquire(lock: &File) -> Result<(), u8> {
        let mut ol = OVERLAPPED::default();
        unsafe {
            let is_success = LockFileEx(
                lock.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                LOCKED_LEN,
                0,
                &mut ol,
            );
            if is_success == 0 {
                panic!("lock fail: lasterror {}", GetLastError());
            }
        }

        Ok(())
    }

    pub fn release(lock: &File) -> Result<(), u8> {
        let mut ol = OVERLAPPED::default();
        unsafe {
            let is_success = UnlockFileEx(lock.as_raw_handle(), 0, LOCKED_LEN, 0, &mut ol);
            if is_success == 0 {
                panic!("unlock fail: lasterror {}", GetLastError());
            }
        }
        Ok(())
    }
}

const LCK_GECREND: &str = "gecrend";
const LCK_CHRREND: &str = "chrrend";
const LCK_DLREND: &str = "dlrend";
const LCK_BPROF: &str = "bprof";

//

#[derive(Debug, Clone, Copy)]
pub(crate) enum BrowserFamily {
    #[cfg(feature = "firefox")]
    Firefox,
    #[cfg(feature = "chromium")]
    Chromium,
}

impl BrowserFamily {
    ///
    /// Prefixes are `str` with length 3.
    fn profile_prefix(&self) -> &'static str {
        #[allow(clippy::needless_late_init)]
        let ret;

        match self {
            #[cfg(feature = "firefox")]
            BrowserFamily::Firefox => ret = "fox",
            #[cfg(feature = "chromium")]
            BrowserFamily::Chromium => ret = "chr",
        };

        if ret.len() != 3 {
            panic!("bug");
        }

        ret
    }
}

// WdaWorkingdir //

#[derive(Debug)]
pub(crate) struct WdaWorkingDir {
    pub(crate) home_pbuf: PathBuf,
    pub(crate) data_root: &'static str,
    pub(crate) sver: &'static str, // structure version
    pub(crate) rend_dir: &'static str,
    pub(crate) lock_dir: &'static str,
    pub(crate) log_dir: &'static str,
    pub(crate) cache_dir: &'static str,
    pub(crate) bprof_dir: &'static str,
}

impl WdaWorkingDir {
    pub(crate) fn zero_log(&self, log_name: &str) -> File {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(
                self.home_pbuf
                    .join(self.data_root)
                    .join(self.sver)
                    .join(self.log_dir)
                    .join(log_name),
            )
            .expect("failed to open zero writable file")
    }

    pub(crate) fn rend_as_command(&self, rend_id: &str) -> Command {
        Command::new(self.rend_file_pbuf(rend_id))
    }

    pub(crate) fn download(&self, rend_id: &str, dl_proxy: Option<&str>) -> Result<()> {
        // if exists, we are done
        if let Ok(flag) = Path::new(&self.rend_file_pbuf(rend_id)).try_exists() {
            if flag {
                return Ok(());
            }
        } else {
            return Err(WdaError::Buggy);
        }

        check_dl_tools()?;

        let mut map = HashMap::<&str, Vec<&str>>::new();

        map.insert(
        "geckodriver-v0.32.2-linux64",
        vec!["https://github.com/mozilla/geckodriver/releases/download/v0.32.2/geckodriver-v0.32.2-linux64.tar.gz","geckodriver-v0.32.2-linux64.tar.gz","geckodriver"],
    );
        map.insert(
        "geckodriver-v0.30.0-linux64",
        vec!["https://github.com/mozilla/geckodriver/releases/download/v0.30.0/geckodriver-v0.30.0-linux64.tar.gz","geckodriver-v0.30.0-linux64.tar.gz","geckodriver"],
    );
        map.insert(
	    "geckodriver-v0.30.0-win64.exe",
        vec![
            "https://github.com/mozilla/geckodriver/releases/download/v0.30.0/geckodriver-v0.30.0-win64.zip",
            "geckodriver-v0.30.0-win64.zip",
            "geckodriver.exe",
        ],
    );
        map.insert(
        "geckodriver-v0.30.0-macos",
        vec!["https://github.com/mozilla/geckodriver/releases/download/v0.30.0/geckodriver-v0.30.0-macos.tar.gz","geckodriver-v0.30.0-macos.tar.gz","geckodriver"],
    );
        map.insert(
            "chromedriver-v112-linux64",
            vec![
            "https://chromedriver.storage.googleapis.com/112.0.5615.49/chromedriver_linux64.zip"
                ,
            "chromedriver-v112-linux64.zip",
            "chromedriver",
        ],
        );
        map.insert(
            "chromedriver-v112-win32.exe",
            vec![
                "https://chromedriver.storage.googleapis.com/112.0.5615.49/chromedriver_win32.zip",
                "chromedriver-v112-win32.zip",
                "chromedriver.exe",
            ],
        );
        map.insert(
            "chromedriver-v112-mac64",
            vec![
                "https://chromedriver.storage.googleapis.com/112.0.5615.49/chromedriver_mac64.zip",
                "chromedriver-v112-mac64.zip",
                "chromedriver",
            ],
        );

        let vals = map.get(rend_id);
        if vals.is_none() {
            return Err(WdaError::RendNotSupported);
        }
        let vals = vals.unwrap();
        let url = vals[0];
        let tarfile = vals[1];
        let rend_file_in_tar = vals[2];

        dbgmsg!("downloading '{}'...", rend_id);

        let _lck = self.try_lock(LCK_DLREND)?;

        #[allow(unused_assignments)]
        let mut operation_failed = true;

        // Download //
        let mut curl_args = vec!["--location"];
        if let Some(v) = dl_proxy {
            curl_args.push("--socks5");
            curl_args.push(v);
        }
        curl_args.push(url);
        curl_args.push("--output");
        let dest_tar = &self
            .cache_file_pbuf(tarfile)
            .into_os_string()
            .into_string()
            .unwrap();
        curl_args.push(dest_tar);
        let status = Command::new("curl")
            .args(curl_args)
            .stdout(self.zero_log(&format!("fetch-out.{}.log", rend_id)))
            .stderr(self.zero_log(&format!("fetch-err.{}.log", rend_id)))
            .status()
            .expect("failed to download ");

        // Extract //
        if !status.success() {
            let excode = status.code().unwrap();
            return Err(WdaError::FetchWebDriver(excode));
        }

        let _status = if tarfile.contains(".tar.gz") {
            Command::new("tar")
                .args(["--extract", "--file", dest_tar, rend_file_in_tar])
                .stdout(self.zero_log(&format!("tar-out.{}.log", rend_id)))
                .stderr(self.zero_log(&format!("tar-err.{}.log", rend_id)))
                .status()
                .expect("failed to extract")
        } else if tarfile.contains(".zip") {
            Command::new("unzip")
                .args([dest_tar, rend_file_in_tar])
                .stdout(self.zero_log(&format!("extract-out.{}.log", rend_id)))
                .stderr(self.zero_log(&format!("extract-err.{}.log", rend_id)))
                .status()
                .expect("failed to extract")
        } else {
            panic!("unsupported archive")
        };

        // Permit //

        // permit before rename bc chmod on win cannot apply on any file path
        // with '\', its bug
        let status = Command::new("chmod")
            .args(["+x", rend_file_in_tar])
            .stdout(self.zero_log(&format!("permit-out.{}.log", rend_id)))
            .stderr(self.zero_log(&format!("permit-err.{}.log", rend_id)))
            .status()
            .expect("permit");
        if !status.success() {
            let excode = status.code().unwrap();
            return Err(WdaError::PermitWebDriver(excode));
        }

        // Rename //
        let rend_file_renamed = self
            .rend_file_pbuf(rend_id)
            .into_os_string()
            .into_string()
            .unwrap();
        if !status.success() {
            let excode = status.code().unwrap();
            return Err(WdaError::ExtractWebDriver(excode));
        }
        let status = Command::new("mv")
            .args([rend_file_in_tar, &rend_file_renamed])
            .stdout(self.zero_log(&format!("extract-out.{}.log", rend_id)))
            .stderr(self.zero_log(&format!("extract-err.{}.log", rend_id)))
            .status()
            .expect("extract");
        if !status.success() {
            let excode = status.code().unwrap();
            return Err(WdaError::PlaceWebDriver(excode));
        }

        // done //
        dbgmsg!("downloading '{}'...done", rend_id);
        operation_failed = false;

        self.try_unlock(LCK_DLREND)?;

        if operation_failed {
            Err(WdaError::Buggy)
        } else {
            Ok(())
        }
    }

    ///
    /// note: returning `File` makes lock long lived.
    pub(crate) fn try_lock(&self, lck_name: &str) -> Result<File> {
        let f = self.existing_lock(lck_name)?;
        lock::acquire(&f).expect("bug");

        Ok(f)
    }

    pub(crate) fn try_unlock(&self, lck_name: &str) -> Result<()> {
        let f = self.existing_lock(lck_name)?;
        lock::release(&f).expect("bug");

        Ok(())
    }

    ///
    /// Create a fresh browser profile(directory), and return it if successful.
    pub(crate) fn fresh_bprof(&self, bfam: BrowserFamily) -> Result<PathBuf> {
        let _lck = self.try_lock(LCK_BPROF)?; // cannot be _, but _xxx is ok

        let prefix = bfam.profile_prefix();

        let mut dirs = Vec::<String>::new();

        match Path::new(&self.bprof_dir()).try_exists() {
            Ok(flag) => {
                if !flag {
                    return Err(WdaError::BrowserProfileRootNotFound);
                }
            }
            Err(_) => {
                return Err(WdaError::Buggy);
            }
        }

        #[allow(clippy::manual_flatten)]
        for may_entry in std::fs::read_dir(self.bprof_dir()).expect("bug") {
            if let Ok(entry) = may_entry {
                let fname = entry.file_name().into_string().expect("bug");
                if &fname[0..3] == prefix {
                    dirs.push(fname);
                }
            }
        }

        #[allow(clippy::needless_late_init)]
        let new_bpname: String;

        #[allow(clippy::len_zero)]
        if dirs.len() > 0 {
            dirs.sort();
            let lelem = dirs.last().expect("bug");
            let npart = &lelem[3..].parse::<u16>().expect("bug");
            let nnpart = npart + 1;
            new_bpname = if nnpart < 10 {
                format!("{}0{}", prefix, nnpart)
            } else if nnpart < 100 {
                format!("{}{}", prefix, nnpart)
            } else {
                let bp_pbuf = self
                    .home_pbuf
                    .join(self.data_root)
                    .join(self.sver)
                    .join(self.bprof_dir);
                std::fs::remove_dir_all(&bp_pbuf).expect("bug");
                create_dir_all(&bp_pbuf).expect("bug");
                format!("{}00", prefix)
            };
        } else {
            new_bpname = format!("{}00", prefix);
        }

        let pbuf = self
            .home_pbuf
            .join(self.data_root)
            .join(self.sver)
            .join(self.bprof_dir)
            .join(new_bpname);
        create_dir_all(&pbuf).expect("bug");
        // dbgg!((&new_bpname, &pbuf));

        self.try_unlock(LCK_BPROF)?;

        Ok(pbuf)
    }

    ///
    /// Grab the most recently used browser profile(directory). In
    /// cases where there is no existing browser profiles, `None` is returned.
    pub(crate) fn last_bprof(&self, bfam: BrowserFamily) -> Result<Option<PathBuf>> {
        match Path::new(&self.bprof_dir()).try_exists() {
            Ok(flag) => {
                if !flag {
                    return Err(WdaError::BrowserProfileRootNotFound);
                }
            }
            Err(_) => {
                return Err(WdaError::Buggy);
            }
        }

        let prefix = bfam.profile_prefix();

        let mut dirs = Vec::<OsString>::new();
        #[allow(clippy::manual_flatten)]
        for may_entry in fs::read_dir(self.bprof_dir()).expect("buggy") {
            if let Ok(entry) = may_entry {
                let fname = entry.file_name().into_string().expect("bug");
                if &fname[0..3] == prefix {
                    dirs.push(entry.file_name());
                }
            }
        }

        #[allow(clippy::len_zero)]
        if dirs.len() > 0 {
            dirs.sort();

            Ok(Some(
                self.home_pbuf
                    .join(self.data_root)
                    .join(self.sver)
                    .join(self.bprof_dir)
                    .join(dirs.last().expect("bug")),
            ))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn find_bprof(
        &self,
        bfam: BrowserFamily,
        bprof_id: &str,
    ) -> Result<Option<PathBuf>> {
        match Path::new(&self.bprof_dir()).try_exists() {
            Ok(flag) => {
                if !flag {
                    return Err(WdaError::BrowserProfileRootNotFound);
                }
            }
            Err(_) => {
                return Err(WdaError::Buggy);
            }
        }

        let prefix = bfam.profile_prefix();

        let mut dir_found: Option<String> = None;

        #[allow(clippy::manual_flatten)]
        for may_entry in fs::read_dir(self.bprof_dir()).expect("buggy") {
            if let Ok(entry) = may_entry {
                let fname = entry.file_name().into_string().expect("bug");
                if &fname[0..3] == prefix && &fname[3..] == bprof_id {
                    dir_found = Some(fname);
                }
            }
        }

        if let Some(v) = dir_found {
            Ok(Some(
                self.home_pbuf
                    .join(self.data_root)
                    .join(self.sver)
                    .join(self.bprof_dir)
                    .join(v),
            ))
        } else {
            Ok(None)
        }
    }

    ///
    /// Get a existing lock name for browser profile.
    ///
    /// Note that this does NOT do the lock job.
    pub(crate) fn bprof_sub_lock(&self, bfam: BrowserFamily, bprof_pbuf: &Path) -> Result<String> {
        let lelem = bprof_pbuf.iter().last();
        if lelem.is_none() {
            return Err(WdaError::BrowserProfileRootNotFound);
        }
        let lelem = lelem.expect("bug").to_str().expect("bug");
        if lelem.len() <= 3 {
            return Err(WdaError::InvalidBrowserProfileSub);
        }
        if &lelem[0..3] != bfam.profile_prefix() {
            return Err(WdaError::BrowserProfileSubNotFound);
        }

        let _lck = self.new_lock_file(lelem)?;

        Ok(lelem.to_string())
    }

    // private //

    fn existing_lock(&self, lock_name: &str) -> Result<File> {
        if let Ok(flag) = Path::new(&self.lock_file_pbuf(lock_name)).try_exists() {
            if !flag {
                return Err(WdaError::WdaLockNotFound);
            }
        } else {
            return Err(WdaError::Buggy);
        }

        Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .open(
                self.home_pbuf
                    .join(self.data_root)
                    .join(self.sver)
                    .join(self.lock_dir)
                    .join(lock_name),
            )
            .unwrap())
    }

    fn new_droot_lock(&self, lock_name: &str) -> Result<File> {
        OpenOptions::new()
            .create(true)
            .write(true)
            .open(self.home_pbuf.join(lock_name))
            .map_err(|_| WdaError::Buggy)
    }

    fn new_lock_file(&self, lock_name: &str) -> Result<File> {
        OpenOptions::new()
            .create(true)
            .write(true)
            .open(
                self.home_pbuf
                    .join(self.data_root)
                    .join(self.sver)
                    .join(self.lock_dir)
                    .join(lock_name),
            )
            .map_err(|_| WdaError::Buggy)
    }

    fn cache_file_pbuf(&self, fname: &str) -> PathBuf {
        self.home_pbuf
            .join(self.data_root)
            .join(self.sver)
            .join(self.cache_dir)
            .join(fname)
    }

    fn rend_file_pbuf(&self, fname: &str) -> PathBuf {
        self.home_pbuf
            .join(self.data_root)
            .join(self.sver)
            .join(self.rend_dir)
            .join(fname)
    }

    fn lock_file_pbuf(&self, fname: &str) -> PathBuf {
        self.home_pbuf
            .join(self.data_root)
            .join(self.sver)
            .join(self.lock_dir)
            .join(fname)
    }

    fn bprof_dir(&self) -> PathBuf {
        self.home_pbuf
            .join(self.data_root)
            .join(self.sver)
            .join(self.bprof_dir)
    }
}

// misc //

fn check_dl_tools() -> Result<()> {
    // curl
    let curl_cmd = Command::new("curl")
        .args(["--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match curl_cmd {
        Ok(exstat) => {
            if !exstat.success() {
                dbgmsg!("'curl' is buggy");
                return Err(WdaError::FetchToolBuggy);
            } else {
                dbgmsg!("program `curl` is ready!");
            }
        }
        Err(io_err) => match io_err.kind() {
            std::io::ErrorKind::NotFound => {
                dbgmsg!("'curl' is not found");
                return Err(WdaError::FetchToolNotFound);
            }
            _e => {
                dbgmsg!("{:?}", _e);
            }
        },
    }

    // unzip
    let unzip_cmd = Command::new("unzip")
        .args(["--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match unzip_cmd {
        Ok(exstat) => {
            if !exstat.success() {
                dbgmsg!("'unzip' is buggy");
                return Err(WdaError::ExtractToolBuggy);
            } else {
                dbgmsg!("program `unzip` is ready!");
            }
        }
        Err(io_err) => match io_err.kind() {
            std::io::ErrorKind::NotFound => {
                dbgmsg!("'unzip' is not found");
                return Err(WdaError::ExtractToolNotFound);
            }
            _e => {
                dbgmsg!("{:?}", _e);
            }
        },
    }

    // tar
    let tar_cmd = Command::new("tar")
        .args(["--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match tar_cmd {
        Ok(exstat) => {
            if !exstat.success() {
                dbgmsg!("'tar' is buggy");
                return Err(WdaError::ExtractToolBuggy);
            } else {
                dbgmsg!("program `tar` is ready!");
            }
        }
        Err(io_err) => match io_err.kind() {
            std::io::ErrorKind::NotFound => {
                dbgmsg!("'tar' is not found");
                return Err(WdaError::ExtractToolNotFound);
            }
            _e => {
                dbgmsg!("{:?}", _e);
            }
        },
    }

    // mv
    let mv_cmd = Command::new("which")
        .args(["mv"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match mv_cmd {
        Ok(exstat) => {
            if !exstat.success() {
                dbgmsg!("`mv` is buggy");
                return Err(WdaError::RenameToolBuggy);
            } else {
                dbgmsg!("program `mv` is ready!");
            }
        }
        Err(io_err) => match io_err.kind() {
            std::io::ErrorKind::NotFound => {
                dbgmsg!("`mv` is not found");
                return Err(WdaError::RenameToolNotFound);
            }
            _e => {
                dbgmsg!("{:?}", _e);
            }
        },
    }

    Ok(())
}

#[cfg(target_family = "unix")]
fn get_home_dir() -> String {
    use std::env;
    for (k, v) in env::vars() {
        if k == "HOME" {
            return v;
        }
    }

    "".to_owned()
}

#[cfg(target_family = "windows")]
fn get_home_dir() -> String {
    use std::env;
    for (k, v) in env::vars() {
        if k == "HOME" {
            return v;
        }
    }

    "".to_owned()
}

// a cannot-fail operation
fn create_wda_workdirs(
    reset: bool,
    predef_home: Option<&'static str>,
    predef_root: Option<&'static str>,
) -> WdaWorkingDir {
    let real_home = get_home_dir();

    // DOUBLE CHECK!!!
    let home_dir = if let Some(v) = predef_home {
        v
    } else {
        &real_home
    };

    let data_root = if let Some(v) = predef_root { v } else { ".wda" };

    let sver = "v1"; // currently v1 structure in use
    let rend_dir = "rend";
    let lock_dir = "lock";
    let log_dir = "log";
    let cache_dir = "cache";
    let bprof_dir = "bprof";

    // manually delete data_root to reset all setting

    let home_pbuf = PathBuf::new().join(home_dir);

    if reset {
        #[allow(clippy::redundant_pattern_matching)]
        if let Err(_) = fs::remove_dir_all(
            /* double check!!! */
            home_pbuf.join(data_root), /* double check!!! */
        ) {}
    }

    // create itself and its all subs
    fs::create_dir_all(home_pbuf.join(data_root).join(sver)).unwrap();
    fs::create_dir_all(home_pbuf.join(data_root).join(sver).join(rend_dir)).unwrap();
    fs::create_dir_all(home_pbuf.join(data_root).join(sver).join(lock_dir)).unwrap();
    fs::create_dir_all(home_pbuf.join(data_root).join(sver).join(cache_dir)).unwrap();
    fs::create_dir_all(home_pbuf.join(data_root).join(sver).join(log_dir)).unwrap();
    fs::create_dir_all(home_pbuf.join(data_root).join(sver).join(bprof_dir)).unwrap();

    WdaWorkingDir {
        home_pbuf,
        data_root,
        sver,
        rend_dir,
        lock_dir,
        log_dir,
        cache_dir,
        bprof_dir,
    }
}

///
/// Prepare essential data for Wda instances.
///
/// Typically it consists of following steps:
///
/// 1. All well-organized directories are in place.
/// 2. Ensure that plock file is not corrupt.
/// 3. Ensure a reasonable number of Wda instances do not interfere with
/// each other.
///
/// After prepared, Wda instances can be readily created, and be
/// multi-threadly safely used.
///
/// Note: if `reset` is `true`, work dir would be removed forcibly before
/// prepare. Use with caution!
pub(crate) fn prepare_wdir(
    reset: bool,
    predef_home: Option<&'static str>,
    predef_root: Option<&'static str>,
) -> Result<WdaWorkingDir> {
    let wda_wdir = create_wda_workdirs(reset, predef_home, predef_root);

    let droot_lock = wda_wdir.new_droot_lock(".wda.lock")?;

    // ---
    lock::acquire(&droot_lock).expect("bug");

    // for testing purpose, simulate massive tasks on exclusive occupation
    // sleep(Duration::from_secs(1));

    let mut plock;

    plock = LCK_GECREND;
    ensure_valid_plock(&wda_wdir, plock, 4445)?;
    plock = LCK_CHRREND;
    ensure_valid_plock(&wda_wdir, plock, 9516)?;

    // dlrend lock
    let _ = wda_wdir.new_lock_file(LCK_DLREND)?;

    // bprof lock
    let _ = wda_wdir.new_lock_file(LCK_BPROF)?;

    lock::release(&droot_lock).expect("bug");
    // ---

    Ok(wda_wdir)
}

fn ensure_valid_plock(wdir: &WdaWorkingDir, plock: &str, default: u16) -> Result<()> {
    match wdir.existing_lock(plock) {
        Ok(mut f) => {
            let mut buf = [0u8; 2];
            if let Err(_e) = f.read_exact(&mut buf) {
                dbgg!(_e);
                return Err(WdaError::WdaDataNotFound);
            }
            let nport = u16::from_le_bytes(buf);
            dbgg!(nport);
            if nport < default {
                Err(WdaError::PlockDataCorrupt)
            } else {
                Ok(())
            }
        }

        Err(e) => match e {
            WdaError::WdaLockNotFound => {
                let mut f = wdir.new_lock_file(plock)?;
                let port = default.to_le_bytes();
                f.write_all(&port).unwrap();
                Ok(())
            }
            _e => {
                dbgg!(_e);
                Err(WdaError::Buggy)
            }
        },
    }
}

// unit tests //

// note: these are not strictly unit ones, but integrated ones, placing them
//       here is bc this is crate-public module

#[cfg(test)]
mod utst_singl_thread {
    use super::*;

    #[allow(non_snake_case)]
    fn _0(
        HOME_DIR: &'static str,
        DATAROOT_DIR: &'static str,
        TESTING_PREFIX: &'static str,
        BFAM: BrowserFamily,
    ) {
        let wdir = prepare_wdir(
            true, /* means delete all */
            Some(HOME_DIR),
            Some(DATAROOT_DIR),
        )
        .expect("bug");

        // is empty dir
        assert_eq!(wdir.last_bprof(BFAM).expect("bug"), None);

        // make 100 fresh ones
        for i in 0..100 {
            let pbuf = wdir.fresh_bprof(BFAM).expect("bug");
            let expected_pbuf = if i < 10 {
                PathBuf::new()
                    .join(wdir.bprof_dir())
                    .join(format!("{}0{}", TESTING_PREFIX, i))
            } else {
                PathBuf::new()
                    .join(wdir.bprof_dir())
                    .join(format!("{}{}", TESTING_PREFIX, i))
            };

            // only predictable on single-thread env
            assert_eq!(pbuf, expected_pbuf);
            assert!(wdir.last_bprof(BFAM).expect("bug").is_some());
            assert_eq!(wdir.last_bprof(BFAM).expect("bug").unwrap(), expected_pbuf);
        }
        assert_eq!(
            wdir.last_bprof(BFAM).expect("bug"),
            Some(
                PathBuf::new()
                    .join(wdir.bprof_dir())
                    .join(format!("{}99", TESTING_PREFIX))
            )
        );

        // make one more fresh, cause previous 99 removed
        for _ in 0..1 {
            let pbuf = wdir.fresh_bprof(BFAM).expect("bug");
            assert_eq!(
                pbuf,
                PathBuf::new()
                    .join(wdir.bprof_dir())
                    .join(format!("{}00", TESTING_PREFIX))
            );
        }
        assert_eq!(
            wdir.last_bprof(BFAM).expect("bug"),
            Some(
                PathBuf::new()
                    .join(wdir.bprof_dir())
                    .join(format!("{}00", TESTING_PREFIX))
            )
        );
    }

    #[test]
    #[cfg(feature = "firefox")]
    fn fox() {
        _0("/tmp", ".tstwda1", "fox", BrowserFamily::Firefox);
    }

    #[test]
    #[cfg(feature = "chromium")]
    fn chr() {
        _0("/tmp", ".tstwda2", "chr", BrowserFamily::Chromium);
    }
}

#[cfg(test)]
mod utst_multi_thread {
    use super::*;

    #[allow(non_snake_case)]
    fn _0(
        _THREAD_ID: &str,
        HOME_DIR: &'static str,
        DATAROOT_DIR: &'static str,
        BFAM: BrowserFamily,
        TIMES: usize,
    ) {
        let wdir = prepare_wdir(false, Some(HOME_DIR), Some(DATAROOT_DIR)).expect("bug");

        // could be none or some
        let may_last_profile = wdir.last_bprof(BFAM);
        assert!(may_last_profile.is_ok());
        let last_profile = may_last_profile.unwrap();
        assert!(last_profile.is_some() || last_profile.is_none());

        // make N fresh ones
        for _i in 0..TIMES {
            let _res = wdir.fresh_bprof(BFAM).expect("bug");
            // dbg!((THREAD_ID, i, res));
        }
    }

    #[test]
    #[cfg(feature = "firefox")]
    fn fox() {
        // test fresh_bprof's multi-threaded safety

        let wdir = prepare_wdir(
            true, /* means delete all */
            Some("/tmp"),
            Some(".tstwda3"),
        )
        .expect("bug");

        let th1 = std::thread::spawn(|| {
            _0("th1", "/tmp", ".tstwda3", BrowserFamily::Firefox, 60);
        });
        let th2 = std::thread::spawn(|| {
            _0("th2", "/tmp", ".tstwda3", BrowserFamily::Firefox, 60);
        });

        th1.join().unwrap();
        th2.join().unwrap();

        let last_profile = wdir.last_bprof(BrowserFamily::Firefox).expect("bug");
        assert!(last_profile.is_some());
        assert_eq!(
            last_profile.unwrap(),
            PathBuf::new().join(wdir.bprof_dir()).join("fox19") // 120-100
        );
    }

    #[test]
    #[cfg(feature = "chromium")]
    fn chr() {
        // test fresh_bprof's multi-threaded safety

        let wdir = prepare_wdir(
            true, /* means delete all */
            Some("/tmp"),
            Some(".tstwda4"),
        )
        .expect("bug");

        let th1 = std::thread::spawn(|| {
            _0("th1", "/tmp", ".tstwda4", BrowserFamily::Chromium, 60);
        });
        let th2 = std::thread::spawn(|| {
            _0("th2", "/tmp", ".tstwda4", BrowserFamily::Chromium, 60);
        });

        th1.join().unwrap();
        th2.join().unwrap();

        let last_profile = wdir.last_bprof(BrowserFamily::Chromium).expect("bug");
        assert!(last_profile.is_some());
        assert_eq!(
            last_profile.unwrap(),
            PathBuf::new().join(wdir.bprof_dir()).join("chr19") // 120-100
        );
    }
}
