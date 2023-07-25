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

use std::borrow::Cow;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::PathBuf;
use std::process::Child;
use std::thread::sleep;
use std::time::Duration;

use std::sync::Arc;
use std::sync::Mutex;

use crate::error::Result;
use crate::error::WdaError;

use crate::wdadata;
use crate::wdadata::BrowserFamily;
use crate::wdadata::WdaWorkingDir;

use crate::misc;

use crate::BasicAutomation;
#[cfg(feature = "extra_auto")]
use crate::ExtraAutomation;

use wdc::wdcmd::session::W3cCapaSetter;

use wdc::CreateW3cSession;
use wdc::CreateWebDrvClient;
use wdc::WdcError;
use wdc::WebDrvClient;

#[cfg(feature = "chromium")]
use wdc::{
    wdcmd::session::{ChromiumCapa, ChromiumCapaSetter},
    ChromeDriver,
};
#[cfg(feature = "firefox")]
use wdc::{
    wdcmd::session::{FirefoxCapa, FirefoxCapaSetter},
    GeckoDriver,
};

#[derive(Debug, PartialEq)]
pub enum WdaSett<'a> {
    // prepare
    PrepareUseSocksProxy(Cow<'a, str>),
    // drv
    DrvLogVerbose,
    // browser
    NoGui,
    Socks5Proxy(Cow<'a, str>),
    ScriptTimeout(u32),
    PageLoadTimeout(u32),
    ///
    /// Indicate Wda which browser profile to use.
    ///
    /// Note that the ID should be a string that only consists of alphabets,
    /// number, underscores, hyphens.
    ///
    /// Note that if this setting is not present, ID `profile-0` will be
    /// in use.
    BrowserProfileId(Cow<'a, str>),
    // ff only
    ProxyDnsSocks5,
    BrowserUrlBarPlhrName(&'a str),
}

#[derive(Debug)]
struct MaySpawnedChild(Option<Arc<Mutex<Child>>>);

impl Drop for MaySpawnedChild {
    fn drop(&mut self) {
        if let Some(chp) = self.0.as_ref() {
            chp.lock().unwrap().kill().expect("buggy");
            self.0 = None;
        }
    }
}

#[derive(Debug)]
struct LockGuard(File);

impl Drop for LockGuard {
    fn drop(&mut self) {
        wdadata::lock_release(&self.0).expect("bug");
    }
}

// WebDrvAstn //

#[derive(Debug)]
pub struct WebDrvAstn<D>
where
    D: CreateWebDrvClient,
    for<'de, 'c1, 'c2> D: CreateW3cSession<'de, 'c1, 'c2>,
{
    wdc: WebDrvClient<D>, // should be first field
    wdir: WdaWorkingDir,
    ppick: u16,
    plock: String,
    lck_bp: String,
    rend_id: String,
    rproc: MaySpawnedChild,
    bp_guard: Option<LockGuard>,
}

impl<D> WebDrvAstn<D>
where
    D: CreateWebDrvClient,
    for<'de, 'c1, 'c2> D: CreateW3cSession<'de, 'c1, 'c2>,
{
    ///
    /// Get the ID of browser profile being used.
    pub fn profile_id(&self) -> Result<&str> {
        if self.lck_bp.len() <= 4 {
            return Err(WdaError::Buggy);
        }

        Ok(&self.lck_bp[4..])
    }

    fn pick_port(&mut self) -> Result<()> {
        let work_dir = &self.wdir;

        let mut f = work_dir.try_lock(&self.plock)?; // LOCK!

        let mut buf = [0u8; 2];

        if let Err(_e) = f.read_exact(&mut buf) {
            dbgg!(_e);
            return Err(WdaError::WdaDataNotFound);
        }

        let p = u16::from_le_bytes([buf[0], buf[1]]);

        let new_p = p + 1;

        if let Err(_e) = f.rewind() {
            dbgg!(_e);
            return Err(WdaError::WdaDataNotFound);
        }

        if let Err(_e) = f.write_all(&new_p.to_le_bytes()) {
            dbgg!(_e);
            return Err(WdaError::WdaDataNotFound);
        }

        work_dir.try_unlock(&self.plock)?;

        self.ppick = p;

        Ok(())
    }

    fn pick_bprof<'a>(
        &self,
        bfam: BrowserFamily,
        bprof_id: Option<Cow<'a, str>>,
    ) -> Result<PathBuf> {
        if let Some(v) = bprof_id {
            Ok(self.wdir.find_bprof_id(bfam, &v)?)
        } else {
            Ok(self.wdir.find_bprof_id(bfam, "profile-0")?)
        }
    }
}

#[cfg(feature = "firefox")]
impl WebDrvAstn<GeckoDriver> {
    pub fn new(settings: Vec<WdaSett>) -> Result<Self>
    where
        Self: Sized,
    {
        let wdir;
        run_diag!("prepare_wdir", {
            wdir = wdadata::prepare_wdir(false, None, None)?;
        });

        let mut wda = WebDrvAstn {
            wdir,
            rproc: MaySpawnedChild(None),
            wdc: WebDrvClient::default(), // a bare, useless client
            plock: "gecrend".to_string(),
            lck_bp: "_".to_string(),
            ppick: 0u16,
            #[cfg(target_os = "linux")]
            rend_id: "geckodriver-v0.32.2-linux64".to_string(),
            #[cfg(target_os = "windows")]
            rend_id: "geckodriver-v0.32.2-win64.exe".to_string(),
            #[cfg(target_os = "macos")]
            rend_id: "geckodriver-v0.32.2-macos".to_string(),
            bp_guard: None,
        };

        run_diag!("pick_port", {
            wda.pick_port()?;
        });

        dbgmsg!("{} pick for rend '{}'!", wda.ppick, wda.rend_id);

        wda.enable_rend_moz(settings)?;

        Ok(wda)
    }

    fn enable_rend_moz<'a>(&mut self, setts: Vec<WdaSett<'a>>) -> Result<()> {
        let mut dl_proxy: Option<Cow<'a, str>> = None;
        let mut is_drv_log_v = false;
        let mut capa = FirefoxCapa::default();
        let mut is_fresh_profile = false;
        let mut is_last_profile = true;
        let mut cust_profile_id: Option<String> = None;
        let mut bprof_id: Option<Cow<'a, str>> = None;

        for sett in setts {
            match sett {
                WdaSett::PrepareUseSocksProxy(hostport) => {
                    dl_proxy = Some(hostport);
                }
                WdaSett::DrvLogVerbose => {
                    is_drv_log_v = true;
                }
                //
                WdaSett::NoGui => {
                    capa.add_args("--headless");
                }
                WdaSett::Socks5Proxy(hostport) => {
                    capa.set_proxy_type("manual");
                    capa.set_socks_version(5);
                    capa.set_socks_proxy_owned(&hostport);
                }
                WdaSett::PageLoadTimeout(tout) => {
                    capa.set_timeouts_page_load(tout);
                }
                WdaSett::ScriptTimeout(tout) => {
                    capa.set_timeouts_script(tout);
                }
                WdaSett::BrowserProfileId(v) => {
                    bprof_id = Some(v);
                }
                //
                WdaSett::ProxyDnsSocks5 => {
                    capa.add_prefs("network.proxy.socks_remote_dns", "true");
                }
                WdaSett::BrowserUrlBarPlhrName(cust_name) => {
                    capa.add_prefs("browser.urlbar.placeholderName", cust_name);
                }
                #[allow(unreachable_patterns)]
                _ => {
                    // do nothing
                }
            }
        }

        let work_dir = &self.wdir;

        // download rend
        work_dir.download(&self.rend_id, dl_proxy.as_deref())?;

        // prepare spawn rend
        let mut prog = work_dir.rend_as_command(&self.rend_id);
        prog.args(["--port", &self.ppick.to_string()]);
        if is_drv_log_v {
            prog.args(["--log", "trace"]);
        } else {
            prog.args(["--log", "error"]);
        }
        prog.stdout(work_dir.zero_log(&format!("{}-out.log", &self.rend_id)))
            .stderr(work_dir.zero_log(&format!("{}-err.log", &self.rend_id)));
        let chp = prog.spawn().unwrap();

        // take child process
        self.rproc = MaySpawnedChild(Some(Arc::new(Mutex::new(chp))));

        // firefox --profile
        let bprof_pbuf: PathBuf = self.pick_bprof(BrowserFamily::Firefox, bprof_id)?;

        // lock profile in advance
        let bprof_lock = work_dir.bprof_sub_lock(BrowserFamily::Firefox, &bprof_pbuf)?;
        let guard = self.wdir.try_lock(&bprof_lock)?;
        self.bp_guard = Some(LockGuard(guard));
        self.lck_bp = bprof_lock;

        let bprof_s = bprof_pbuf.into_os_string().into_string().expect("bug");
        capa.add_args("--profile");
        capa.add_args(&bprof_s);

        // make sure rend connected and got session
        let mut conn_try_times = 5000u16;
        let wait_time = 1; // nanos
        let mut goon_try = true;
        run_diag!("init_wdc", {
            let mut wdc_err = WdcError::Buggy;
            while goon_try && conn_try_times > 0 {
                match wdc::init_singl_ff("127.0.0.1", self.ppick, &capa, 1) {
                    Ok(wdc) => {
                        self.wdc = wdc;
                        goon_try = false;
                    }
                    Err(e) => {
                        conn_try_times -= 1;
                        wdc_err = e;
                    }
                }
                sleep(Duration::from_nanos(wait_time));
            }

            if goon_try {
                return Err(WdaError::WdcNotReady(wdc_err, self.ppick));
            }
            dbgmsg!(
                "try {} times to enable rend '{}'",
                5000 - conn_try_times,
                self.rend_id,
            );
        });

        Ok(())
    }
}

#[cfg(feature = "chromium")]
impl WebDrvAstn<ChromeDriver> {
    pub fn new(settings: Vec<WdaSett>) -> Result<Self>
    where
        Self: Sized,
    {
        let wdir;
        run_diag!("prepare_wdir", {
            wdir = wdadata::prepare_wdir(false, None, None)?;
        });

        let mut wda = WebDrvAstn {
            wdir,
            rproc: MaySpawnedChild(None),
            wdc: WebDrvClient::default(), // a bare, useless client
            plock: "chrrend".to_string(),
            lck_bp: "_".to_string(),
            ppick: 0u16,
            #[cfg(target_os = "linux")]
            rend_id: "chromedriver-v114-linux64".to_string(),
            #[cfg(target_os = "windows")]
            rend_id: "chromedriver-v114-win32.exe".to_string(),
            #[cfg(target_os = "macos")]
            rend_id: "chromedriver-v114-mac64".to_string(),
            bp_guard: None,
        };

        run_diag!("pick_port", {
            wda.pick_port()?;
        });

        dbgmsg!("{} pick for rend '{}'!", wda.ppick, wda.rend_id);

        wda.enable_rend_goog(settings)?;

        Ok(wda)
    }

    fn enable_rend_goog<'a>(&mut self, setts: Vec<WdaSett<'a>>) -> Result<()> {
        let mut dl_proxy: Option<Cow<'a, str>> = None;
        let mut is_drv_log_v = false;
        let mut capa = ChromiumCapa::default();
        let mut is_fresh_profile = false;
        let mut is_last_profile = true;
        let mut cust_profile_id: Option<String> = None;
        let mut bprof_id: Option<Cow<'a, str>> = None;

        for sett in setts {
            match sett {
                WdaSett::PrepareUseSocksProxy(hostport) => {
                    dl_proxy = Some(hostport);
                }
                WdaSett::DrvLogVerbose => {
                    is_drv_log_v = true;
                }
                //
                WdaSett::NoGui => {
                    capa.add_args("--headless");
                }
                WdaSett::Socks5Proxy(hostport) => {
                    capa.set_proxy_type("manual");
                    capa.set_socks_version(5);
                    capa.set_socks_proxy_owned(&hostport);
                }
                WdaSett::PageLoadTimeout(tout) => {
                    capa.set_timeouts_page_load(tout);
                }
                WdaSett::ScriptTimeout(tout) => {
                    capa.set_timeouts_script(tout);
                }
                WdaSett::BrowserProfileId(v) => {
                    bprof_id = Some(v);
                }
                _ => {
                    // do nothing
                }
            }
        }

        let work_dir = &self.wdir;

        // download rend
        work_dir.download(&self.rend_id, dl_proxy.as_deref())?;

        // prepare spawn rend
        let mut prog = work_dir.rend_as_command(&self.rend_id);
        prog.args([format!("--port={}", self.ppick)]);
        if is_drv_log_v {
            prog.args(["--log-level=ALL"]);
        } else {
            prog.args(["--log-level=SEVERE"]);
        }
        prog.stdout(work_dir.zero_log(&format!("{}-out.log", &self.rend_id)))
            .stderr(work_dir.zero_log(&format!("{}-err.log", &self.rend_id)));
        let chp = prog.spawn().unwrap();

        // take child process
        self.rproc = MaySpawnedChild(Some(Arc::new(Mutex::new(chp))));

        // chromium --user-data
        let bprof_pbuf: PathBuf = self.pick_bprof(BrowserFamily::Chromium, bprof_id)?;

        // lock profile in advance
        let bprof_lock = work_dir.bprof_sub_lock(BrowserFamily::Chromium, &bprof_pbuf)?;
        let guard = self.wdir.try_lock(&bprof_lock)?;
        self.bp_guard = Some(LockGuard(guard));
        self.lck_bp = bprof_lock;

        let bprof_s = bprof_pbuf.into_os_string().into_string().expect("bug");
        let arg_s = format!("--user-data-dir={}", &bprof_s);
        capa.add_args(&arg_s);

        // make sure rend connected
        let mut conn_try_times = 5000u16;
        let wait_time = 1; // nanos
        let mut goon_try = true;
        run_diag!("init_wdc", {
            let mut wdc_err = WdcError::Buggy;
            while goon_try && conn_try_times > 0 {
                match wdc::init_singl_ch("127.0.0.1", self.ppick, &capa, 1) {
                    Ok(wdc) => {
                        self.wdc = wdc;
                        goon_try = false;
                    }
                    Err(e) => {
                        conn_try_times -= 1;
                        wdc_err = e;
                    }
                }
                sleep(Duration::from_nanos(wait_time));
            }

            if goon_try {
                return Err(WdaError::WdcNotReady(wdc_err, self.ppick));
            }
            dbgmsg!(
                "try {} times to enable rend '{}'",
                5000 - conn_try_times,
                self.rend_id,
            );
        });

        Ok(())
    }
}

// WebDrvAstn impls //

impl<D> BasicAutomation for WebDrvAstn<D>
where
    D: CreateWebDrvClient,
    for<'de, 'c1, 'c2> D: CreateW3cSession<'de, 'c1, 'c2>,
{
    fn go_url(&self, url: &str) -> Result<()> {
        let wdc = &self.wdc;

        #[allow(clippy::if_same_then_else)]
        let url2 = if url.len() >= 6 && "about:" == &url[0..6] {
            url.to_string()
        } else if url.len() >= 7 && "chrome:" == &url[0..7] {
            url.to_string()
        } else if (url.len() > 7 && "http://" == &url[0..7])
            || (url.len() > 8 && "https://" == &url[0..8])
        {
            url.to_string()
        } else {
            format!("http://{}", url)
        };

        match wdc.navi_to(&url2) {
            Ok(_) => Ok(()),
            Err(_e) => {
                dbgg!(&_e);
                Err(WdaError::WdcFail(_e))
            }
        }
    }

    fn get_url(&self) -> Result<String> {
        let wdc = &self.wdc;

        match wdc.get_url() {
            Ok(url) => Ok(String::from_utf8(url).unwrap()),
            Err(_e) => {
                dbgg!(&_e);
                Err(WdaError::WdcFail(_e))
            }
        }
    }

    fn page_src(&self, save_to: Option<&str>) -> Result<Option<Vec<u8>>> {
        let wdc = &self.wdc;

        match wdc.page_src(save_to) {
            Ok(ret) => Ok(ret),
            Err(_e) => {
                dbgg!(&_e);
                Err(WdaError::WdcFail(_e))
            }
        }
    }

    fn print_page(&self, save_to: &str) -> Result<()> {
        let wdc = &self.wdc;

        let save_to_temp = format!("{}.b64", save_to);

        match wdc.print_page(&save_to_temp) {
            Ok(_) => {
                misc::decode_b64_file(&save_to_temp, save_to).expect("decode file");
                Ok(())
            }
            Err(_e) => {
                dbgg!(&_e);
                Err(WdaError::WdcFail(_e))
            }
        }
    }

    fn sshot_page(&self, save_to: &str) -> Result<()> {
        let wdc = &self.wdc;

        let save_to_temp = format!("{}.b64", save_to);

        match wdc.screenshot(&save_to_temp) {
            Ok(_) => {
                misc::decode_b64_file(&save_to_temp, save_to).expect("decode file");
                Ok(())
            }
            Err(_e) => {
                dbgg!(&_e);
                Err(WdaError::WdcFail(_e))
            }
        }
    }

    fn sshot_elem(&self, elem_id: &str, save_to: &str) -> Result<()> {
        let wdc = &self.wdc;

        match wdc.screenshot_elem(elem_id, save_to) {
            Ok(_) => Ok(()),
            Err(_e) => {
                dbgg!(&_e);
                Err(WdaError::WdcFail(_e))
            }
        }
    }

    fn find_elem_by_css(&self, selector: &str) -> Result<String> {
        let wdc = &self.wdc;

        match wdc.find_elem_css(selector) {
            Ok(elem_id) => Ok(String::from_utf8(elem_id).unwrap()),
            Err(_e) => {
                dbgg!(&_e);
                Err(WdaError::WdcFail(_e))
            }
        }
    }

    fn find_elems_by_css(&self, selector: &str) -> Result<Vec<String>> {
        let wdc = &self.wdc;

        match wdc.find_elems_css(selector) {
            Ok(elem_ids) => Ok(elem_ids),
            Err(_e) => {
                dbgg!(&_e);
                Err(WdaError::WdcFail(_e))
            }
        }
    }

    fn eval(&self, script: &str, args: Vec<&str>) -> Result<String> {
        let wdc = &self.wdc;

        match wdc.exec_sync(script, args) {
            Ok(eval_ret) => Ok(String::from_utf8(eval_ret).unwrap()),
            Err(_e) => {
                dbgg!(&_e);
                Err(WdaError::WdcFail(_e))
            }
        }
    }

    fn eval_async(&self, script: &str, args: Vec<&str>) -> Result<String> {
        let wdc = &self.wdc;

        match wdc.exec_async(script, args) {
            Ok(eval_ret) => Ok(String::from_utf8(eval_ret).unwrap()),
            Err(_e) => {
                dbgg!(&_e);
                Err(WdaError::WdcFail(_e))
            }
        }
    }
}

#[cfg(feature = "extra_auto")]
impl<D> ExtraAutomation for WebDrvAstn<D>
where
    D: CreateWebDrvClient,
    for<'de, 'c1, 'c2> D: CreateW3cSession<'de, 'c1, 'c2>,
{
    fn sshot_page_allv(&self, url: &str, save_to: &str) -> Result<()> {
        self.go_url(url).expect("go url");

        #[derive(Debug, serde::Deserialize)]
        struct Heights {
            one: u32,
            whole: u32,
        }

        let jsout = self
            .eval(
                "return {whole: document.body.scrollHeight, one: window.innerHeight};",
                vec![],
            )
            .expect("exec_sync");

        dbg!(&jsout);

        let heights = serde_json::from_slice::<Heights>(jsout.as_bytes()).expect("deser");

        dbg!(&heights);

        let mut img_list = vec![];

        let mut nscroll = 0;
        let mut prev_y_offset = u32::MAX;
        loop {
            let arg = nscroll.to_string();
            let jsout = self.eval( "var n_inner_h=arguments[0];window.scroll(0,window.innerHeight*n_inner_h);return parseInt(window.pageYOffset);", vec![&arg])
		.expect("exec_sync");
            let y_offset = jsout.parse::<u32>().unwrap();
            dbgg!(y_offset);
            if y_offset == prev_y_offset {
                // nscroll -= 1; // FIXME: useless?
                break; // meaning check only once
            } else {
                let part_name = format!("{}.b64.{}.png", save_to, nscroll);
                // FIXTHEM: image recognize png depends merely on file extension
                self.sshot_page(&part_name).unwrap();
                img_list.push(image::open(&part_name).unwrap());
                prev_y_offset = y_offset;
                nscroll += 1;
            }
        }

        misc::png_v_concat(heights.one, heights.whole, &img_list)
            .save(save_to)
            .unwrap();

        Ok(())
    }

    fn sshot_curr_allv(&self, save_to: &str) -> Result<()> {
        #[derive(Debug, serde::Deserialize)]
        struct Heights {
            one: u32,
            whole: u32,
        }

        let jsout = self
            .eval(
                "return {whole: document.body.scrollHeight, one: window.innerHeight};",
                vec![],
            )
            .expect("exec_sync");

        dbg!(&jsout);

        let heights = serde_json::from_slice::<Heights>(jsout.as_bytes()).expect("deser");

        dbg!(&heights);

        let mut img_list = vec![];

        let mut nscroll = 0;
        let mut prev_y_offset = u32::MAX;
        loop {
            let arg = nscroll.to_string();
            let jsout = self.eval( "var n_inner_h=arguments[0];window.scroll(0,window.innerHeight*n_inner_h);return parseInt(window.pageYOffset);", vec![&arg])
		.expect("exec_sync");
            let y_offset = jsout.parse::<u32>().unwrap();
            dbgg!(y_offset);
            if y_offset == prev_y_offset {
                // nscroll -= 1; // FIXME: useless?
                break; // meaning check only once
            } else {
                let part_name = format!("{}.b64.{}.png", save_to, nscroll);
                // FIXTHEM: image recognize png depends merely on file extension
                self.sshot_page(&part_name).unwrap();
                img_list.push(image::open(&part_name).unwrap());
                prev_y_offset = y_offset;
                nscroll += 1;
            }
        }

        misc::png_v_concat(heights.one, heights.whole, &img_list)
            .save(save_to)
            .unwrap();

        Ok(())
    }
}

// unit tests //

#[cfg(test)]
mod utst_conc_init {
    use super::*;
    use std::net::TcpStream;
    use std::thread;
    use std::thread::JoinHandle;

    #[cfg(feature = "firefox")]
    mod gecko {
        use super::*;
        type DRV = GeckoDriver;

        #[test]
        fn _1() {
            // single thread
            let pxy = if let Ok(v) = std::env::var("SOCKS5_PROXY") {
                v
            } else {
                "".to_string()
            };

            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
            ])
            .expect("new wda instance");

            dbg!(&wda);

            assert_eq!(wda.rproc.0.is_some(), true);

            let port_in_use = wda.ppick;

            assert_eq!(is_local_port_open(port_in_use), true, "rend is up");

            assert_eq!(is_bprof_lck_present(&wda), true, "lock created");
            assert_eq!(is_bprof_present(&wda), true, "browser profile not empty");

            drop(wda);

            // signal needs time to arrive its home
            std::thread::sleep(std::time::Duration::from_millis(500));

            // this indicates rproc is actually None
            assert_eq!(is_local_port_open(port_in_use), false, "{}", port_in_use);
            // -----
        }

        #[test]
        fn _2() {
            // multiple threads

            const N_THREAD: usize = 8;
            let mut th_grp: [Option<JoinHandle<()>>; N_THREAD] =
                [None, None, None, None, None, None, None, None];

            for i in 0..N_THREAD {
                th_grp[i] = Some(
                    thread::Builder::new()
                        .name(format!("thread{}", i))
                        .spawn(|| {
                            let pxy = if let Ok(v) = std::env::var("SOCKS5_PROXY") {
                                v
                            } else {
                                "".to_string()
                            };

                            // -----
                            let wda = WebDrvAstn::<DRV>::new(vec![
                                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                                WdaSett::NoGui,
                            ])
                            .expect("new wda instance");

                            assert_eq!(wda.rproc.0.is_some(), true);

                            let port_in_use = wda.ppick;

                            assert_eq!(is_local_port_open(port_in_use), true, "rend is up");

                            assert_eq!(is_bprof_lck_present(&wda), true, "lock created");
                            assert_eq!(is_bprof_present(&wda), true, "browser profile not empty");

                            drop(wda);

                            // signal needs time to arrive its home
                            std::thread::sleep(std::time::Duration::from_millis(500));

                            // this indicates rproc is actually None
                            assert_eq!(is_local_port_open(port_in_use), false, "{}", port_in_use);
                            // -----
                        })
                        .unwrap(),
                )
            }

            for i in 0..N_THREAD {
                if th_grp[i].is_some() {
                    th_grp[i].take().expect("take").join().expect("join");
                }
            }
        }
    }

    #[cfg(feature = "chromium")]
    mod chrom {
        use super::*;
        type DRV = ChromeDriver;

        #[test]
        fn _1() {
            // single thread

            let pxy = if let Ok(v) = std::env::var("SOCKS5_PROXY") {
                v
            } else {
                "".to_string()
            };

            // -----
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
            ])
            .expect("new wda instance");

            dbg!(&wda);

            assert_eq!(wda.rproc.0.is_some(), true);

            let port_in_use = wda.ppick;

            assert_eq!(is_local_port_open(port_in_use), true, "rend is up");

            assert_eq!(is_bprof_lck_present(&wda), true, "lock created");
            assert_eq!(is_bprof_present(&wda), true, "browser profile not empty");

            drop(wda);

            // signal needs time to arrive its home
            std::thread::sleep(std::time::Duration::from_millis(500));

            // this indicates rproc is actually None
            assert_eq!(is_local_port_open(port_in_use), false, "{}", port_in_use);
            // -----
        }

        #[test]
        fn _2() {
            // multiple threads

            const N_THREAD: usize = 8;
            let mut th_grp: [Option<JoinHandle<()>>; N_THREAD] =
                [None, None, None, None, None, None, None, None];

            for i in 0..N_THREAD {
                th_grp[i] = Some(
                    thread::Builder::new()
                        .name(format!("thread{}", i))
                        .spawn(|| {
                            let pxy = if let Ok(v) = std::env::var("SOCKS5_PROXY") {
                                v
                            } else {
                                "".to_string()
                            };
                            // -----
                            let wda = WebDrvAstn::<DRV>::new(vec![
                                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                                WdaSett::NoGui,
                            ])
                            .expect("new wda instance");

                            assert_eq!(wda.rproc.0.is_some(), true);

                            let port_in_use = wda.ppick;

                            assert_eq!(is_local_port_open(port_in_use), true, "rend is up");

                            assert_eq!(is_bprof_lck_present(&wda), true, "lock created");
                            assert_eq!(is_bprof_present(&wda), true, "browser profile not empty");

                            drop(wda);

                            // signal needs time to arrive its home
                            std::thread::sleep(std::time::Duration::from_millis(500));

                            // this indicates rproc is actually None
                            assert_eq!(is_local_port_open(port_in_use), false, "{}", port_in_use);
                            // -----
                        })
                        .unwrap(),
                )
            }

            for i in 0..N_THREAD {
                if th_grp[i].is_some() {
                    th_grp[i].take().expect("take").join().expect("join");
                }
            }
        }
    }

    fn is_local_port_open(p: u16) -> bool {
        match TcpStream::connect(format!("127.0.0.1:{}", p)) {
            Ok(_) => true,
            Err(_e) => false,
        }
    }

    fn is_bprof_lck_present<D>(wda: &WebDrvAstn<D>) -> bool
    where
        D: CreateWebDrvClient,
        for<'de, 'c1, 'c2> D: CreateW3cSession<'de, 'c1, 'c2>,
    {
        let wdir = &wda.wdir;
        let lck_name = &wda.lck_bp;

        let pbuf = wdir
            .home_pbuf
            .join(wdir.data_root)
            .join(wdir.sver)
            .join(wdir.lock_dir)
            .join(lck_name);

        let is_exist = pbuf.try_exists();
        assert!(is_exist.is_ok());
        let is_exist = is_exist.unwrap();

        is_exist
    }

    fn is_bprof_present<D>(wda: &WebDrvAstn<D>) -> bool
    where
        D: CreateWebDrvClient,
        for<'de, 'c1, 'c2> D: CreateW3cSession<'de, 'c1, 'c2>,
    {
        let wdir = &wda.wdir;
        let bprof_name = &wda.lck_bp;

        let pbuf = wdir
            .home_pbuf
            .join(wdir.data_root)
            .join(wdir.sver)
            .join(wdir.bprof_dir)
            .join(bprof_name);

        dbg!(&pbuf);

        let is_exist = pbuf.try_exists();
        assert!(is_exist.is_ok());
        let is_exist = is_exist.unwrap();

        is_exist
    }
}
