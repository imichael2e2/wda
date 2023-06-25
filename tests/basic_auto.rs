#[cfg(feature = "firefox")]
mod gecko {
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

    #[test]
    fn go_url() {
        use BasicAutomation;
        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
            // WdaSett::Socks5Proxy("127.0.0.1:10801".into()),
        ])
        .expect("new wda");

        wda.go_url("about:rights").expect("go url");
    }

    #[test]
    fn get_url() {
        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
            // WdaSett::Socks5Proxy("127.0.0.1:10801".into()),
        ])
        .expect("new wda");

        wda.go_url("about:rights").expect("go url");

        let ret = wda.get_url().expect("go url");

        assert_eq!(&ret, "about:rights");
    }

    #[test]
    fn page_src() {
        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
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

        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
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

        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
            // WdaSett::Socks5Proxy("127.0.0.1:10801".into()),
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

        let may_wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
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

        let may_wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
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

        let may_wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
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
}

#[cfg(feature = "chromium")]
mod chrom {
    use wda::BasicAutomation;
    use wda::WdaSett;
    use wda::WebDrvAstn;
    type DRV = wda::ChromeDriver;

    const OUTPUT_FILE_PREFIX: &str = "tstfile_chrome_basic_auto";
    fn tst_only_fname(fname: &str) -> String {
        #[cfg(target_family = "unix")]
        let tmp_dir = "/tmp/wdatst";
        #[cfg(target_family = "windows")]
        let tmp_dir = "./tsttmp";
        // let _ = std::fs::remove_dir_all(tmp_dir); // do not unwrap
        std::fs::create_dir_all(tmp_dir).unwrap();
        format!("{}/{}-{}", tmp_dir, OUTPUT_FILE_PREFIX, fname)
    }

    #[test]
    fn go_url() {
        use BasicAutomation;
        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
            // WdaSett::Socks5Proxy("127.0.0.1:10801".into()),
        ])
        .expect("new wda");

        wda.go_url("about:rights").expect("go url");
    }

    #[test]
    fn get_url() {
        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
            // WdaSett::Socks5Proxy("127.0.0.1:10801".into()),
        ])
        .expect("new wda");

        wda.go_url("about:rights").expect("go url");

        let ret = wda.get_url().expect("go url");

        assert_eq!(&ret, "about:rights");
    }

    #[test]
    fn page_src() {
        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
        ])
        .expect("new wda");

        wda.go_url("about:rights").expect("go url");

        let save_to = tst_only_fname("page_src.html");

        wda.page_src(Some(&save_to)).expect("get page source..");

        let src = std::fs::read_to_string(save_to).expect("read file");

        // std::thread::sleep(std::time::Duration::from_secs(30));

        assert_eq!(src.contains("html"), true);
    }

    #[test]
    fn print_page() {
        use std::fs::OpenOptions;
        use std::io::Read;
        use std::path::Path;

        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
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
                assert_eq!(&buf, b"%PDF-1.4"); // chrome use 1.4, older than ff
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

        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
            // WdaSett::Socks5Proxy("127.0.0.1:10801".into()),
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
}
