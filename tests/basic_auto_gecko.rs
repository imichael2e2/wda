#[cfg(feature = "firefox")]
mod tst {

    use wda::BasicAutomation;
    use wda::WdaError;
    use wda::WdaSett;
    use wda::WdcError;
    use wda::WebDrvAstn;
    type DRV = wda::GeckoDriver;

    const OUTPUT_FILE_PREFIX: &str = "tstfile_gecko_basic_auto";
    fn tst_only_fname(fname: &str) -> String {
        #[cfg(target_family = "unix")]
        let tmp_dir = "/tmp/wdatst";
        #[cfg(target_family = "windows")]
        let tmp_dir = "./tsttmp";
        // let _ = std::fs::remove_dir_all(tmp_dir); // do not unwrap
        std::fs::create_dir_all(tmp_dir).unwrap();
        format!("{}/{}-{}", tmp_dir, OUTPUT_FILE_PREFIX, fname)
    }

    fn socks5_proxy_from_env() -> String {
        let pxy = if let Ok(v) = std::env::var("SOCKS5_PROXY") {
            v
        } else {
            "".to_string()
        };
        pxy
    }

    // tests //

    #[test]
    fn go_url() {
        use BasicAutomation;

        let pxy = socks5_proxy_from_env();

        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy(pxy.into()),
            WdaSett::NoGui,
            WdaSett::FreshProfile,
        ])
        .expect("new wda");

        wda.go_url("about:rights").expect("go url");
    }

    #[test]
    fn get_url() {
        let pxy = socks5_proxy_from_env();

        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy(pxy.into()),
            WdaSett::NoGui,
            WdaSett::FreshProfile,
        ])
        .expect("new wda");

        wda.go_url("about:rights").expect("go url");

        let ret = wda.get_url().expect("go url");

        assert_eq!(&ret, "about:rights");
    }

    #[test]
    fn page_src() {
        let pxy = socks5_proxy_from_env();
        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy(pxy.into()),
            WdaSett::NoGui,
            WdaSett::FreshProfile,
        ])
        .expect("new wda");

        wda.go_url("about:rights").expect("go url");

        let save_to = tst_only_fname("page_src.html");

        wda.page_src(Some(&save_to)).expect("get page source..");

        let src = std::fs::read_to_string(save_to).expect("read file");

        // std::thread::sleep(std::time::Duration::from_secs(30));

        assert_eq!(src.contains("</html>"), true);
    }

    #[test]
    fn print_page() {
        use std::fs::OpenOptions;
        use std::io::Read;
        use std::path::Path;

        let pxy = socks5_proxy_from_env();

        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy(pxy.into()),
            WdaSett::NoGui,
            WdaSett::FreshProfile,
        ])
        .expect("new wda");

        wda.go_url("about:rights").expect("go url");

        let save_to = tst_only_fname("print_page.pdf");

        wda.print_page(&save_to).expect("print page");

        match Path::new(&save_to).try_exists() {
            Ok(flag) => {
                if !flag {
                    assert!(false);
                }
                let mut f = OpenOptions::new()
                    .read(true)
                    .open(&save_to)
                    .expect("open file");
                let mut buf = [0u8; 8];
                f.read_exact(&mut buf).expect("read io");
                assert_eq!(&buf, b"%PDF-1.5");
            }
            Err(e) => {
                dbg!(e);
                assert!(false);
            }
        }
    }

    #[test]
    fn sshot_page() {
        use std::fs::OpenOptions;
        use std::io::Read;
        use std::path::Path;

        let pxy = socks5_proxy_from_env();

        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy(pxy.into()),
            WdaSett::NoGui,
            WdaSett::FreshProfile,
        ])
        .expect("new wda");

        wda.go_url("about:rights").expect("go url");

        let save_to = tst_only_fname("sshot_page.png");

        wda.sshot_page(&save_to).expect("sshot page");

        match Path::new(&save_to).try_exists() {
            Ok(flag) => {
                if !flag {
                    assert!(false);
                }
                let mut f = OpenOptions::new()
                    .read(true)
                    .open(&save_to)
                    .expect("open file");
                let mut buf = [0u8; 8];
                f.read_exact(&mut buf).expect("read io");
                assert_eq!(&buf, &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
            }
            Err(e) => {
                dbg!(e);
                assert!(false);
            }
        }
    }

    #[test]
    fn err_new_1_th1() {
        // ensure error is predictable, and if any, cleanup is ensured as well.
        //
        // note that, chromedrv is more unpredictable than geckodrv, in terms of
        // webdriver errors, thus no alike tests for chromedrv.

        let pxy = socks5_proxy_from_env();

        let may_wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy(pxy.into()),
            WdaSett::NoGui,
            WdaSett::FreshProfile,
            WdaSett::Socks5Proxy("10.0.2.2:108xxx".into()),
        ]);

        let mut server_port = 0u16;

        match may_wda {
            Ok(_) => assert!(false),
            Err(e) => match e {
                WdaError::WdcNotReady(WdcError::BadDrvCmd(ref err, ref msg), p) => {
                    let expected_err = "invalid argument";
                    let expected_msg = "socksProxy is not a valid URL: 10.0.2.2:108xxx";
                    if err == expected_err && msg == expected_msg {
                        server_port = p;
                    } else {
                        assert!(false, "unexpected error {:?}", e);
                    }
                }
                _ => assert!(false, "unexpected error {:?}", e),
            },
        }

        let ps_out_bytes = std::process::Command::new("ps")
            .args(["-ef"])
            .output()
            .expect("buggy")
            .stdout;

        let ps_out = String::from_utf8_lossy(&ps_out_bytes);

        let ptn = format!(".*geckodriver.* --port {}.*", server_port);

        dbg!(&ptn);

        let re = regex::Regex::new(&ptn).expect("buggy");

        assert_eq!(re.is_match(&ps_out), false, "zombie process found");
    }

    #[test]
    fn err_new_1_th2() {
        // identical to _1, simulating thread2

        let pxy = socks5_proxy_from_env();

        let may_wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy(pxy.into()),
            WdaSett::NoGui,
            WdaSett::FreshProfile,
            WdaSett::Socks5Proxy("10.0.2.2:108xxx".into()),
        ]);

        let mut server_port = 0u16;

        match may_wda {
            Ok(_) => assert!(false),
            Err(e) => match e {
                WdaError::WdcNotReady(WdcError::BadDrvCmd(ref err, ref msg), p) => {
                    let expected_err = "invalid argument";
                    let expected_msg = "socksProxy is not a valid URL: 10.0.2.2:108xxx";
                    if err == expected_err && msg == expected_msg {
                        server_port = p;
                    } else {
                        assert!(false, "unexpected error {:?}", e);
                    }
                }
                _ => assert!(false, "unexpected error {:?}", e),
            },
        }

        let ps_out_bytes = std::process::Command::new("ps")
            .args(["-ef"])
            .output()
            .expect("buggy")
            .stdout;

        let ps_out = String::from_utf8_lossy(&ps_out_bytes);

        let ptn = format!(".*geckodriver.* --port {}.*", server_port);

        dbg!(&ptn);

        let re = regex::Regex::new(&ptn).expect("buggy");

        assert_eq!(re.is_match(&ps_out), false, "zombie process found");
    }

    #[test]
    fn err_new_1_th3() {
        // identical to _1, simulating thread3

        let pxy = socks5_proxy_from_env();

        let may_wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy(pxy.into()),
            WdaSett::NoGui,
            WdaSett::FreshProfile,
            WdaSett::Socks5Proxy("10.0.2.2:108xxx".into()),
        ]);

        let mut server_port = 0u16;

        match may_wda {
            Ok(_) => assert!(false),
            Err(e) => match e {
                WdaError::WdcNotReady(WdcError::BadDrvCmd(ref err, ref msg), p) => {
                    let expected_err = "invalid argument";
                    let expected_msg = "socksProxy is not a valid URL: 10.0.2.2:108xxx";
                    if err == expected_err && msg == expected_msg {
                        server_port = p;
                    } else {
                        assert!(false, "unexpected error {:?}", e);
                    }
                }
                _ => assert!(false, "unexpected error {:?}", e),
            },
        }

        let ps_out_bytes = std::process::Command::new("ps")
            .args(["-ef"])
            .output()
            .expect("buggy")
            .stdout;

        let ps_out = String::from_utf8_lossy(&ps_out_bytes);

        let ptn = format!(".*geckodriver.* --port {}.*", server_port);

        dbg!(&ptn);

        let re = regex::Regex::new(&ptn).expect("buggy");

        assert_eq!(re.is_match(&ps_out), false, "zombie process found");
    }

    #[test]
    fn fresh_profile() {
        // both fresh profiles, very unlikely lead to identical results,
        // except there are many other wda(as many as ==100) trying to
        // create fresh profiles and succeed, at the point between these
        // two. so this test is nearly completely reliable.

        use BasicAutomation;

        let got_profile1: String;
        let got_profile2: String;

        let pxy = socks5_proxy_from_env();

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
                WdaSett::FreshProfile,
            ])
            .expect("new wda");

            wda.go_url("about:support").expect("go url");

            got_profile1 = wda
                .eval(
                    "return document.getElementById('profile-row').innerText;",
                    vec![],
                )
                .expect("bug");
        }

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.into()),
                WdaSett::NoGui,
                WdaSett::FreshProfile,
            ])
            .expect("new wda");

            wda.go_url("about:support").expect("go url");

            got_profile2 = wda
                .eval(
                    "return document.getElementById('profile-row').innerText;",
                    vec![],
                )
                .expect("bug");
        }

        assert!(got_profile1 != got_profile2);

        // std::thread::sleep(std::time::Duration::from_secs(1000));
    }
}
