#[cfg(feature = "firefox")]
mod itst {
    use wda::BasicAutomation;
    use wda::WdaSett;
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

        // fresh profile
        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
            ])
            .expect("new wda");

            wda.go_url("about:rights").expect("go url");
        }

        // reuse profile(could be any, not only created above )
    }

    #[test]
    fn get_url() {
        let pxy = socks5_proxy_from_env();

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
            ])
            .expect("new wda");

            wda.go_url("about:rights").expect("go url");

            let ret = wda.get_url().expect("go url");

            assert_eq!(&ret, "about:rights");
        }
    }

    #[test]
    fn page_src() {
        let pxy = socks5_proxy_from_env();

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
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
    }

    #[test]
    fn print_page() {
        use std::fs::OpenOptions;
        use std::io::Read;
        use std::path::Path;

        let pxy = socks5_proxy_from_env();

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
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

                    #[cfg(target_os = "linux")]
                    assert_eq!(&buf, b"%PDF-1.5");
                    #[cfg(target_os = "macos")]
                    assert_eq!(&buf, b"%PDF-1.3");
                }
                Err(e) => {
                    dbg!(e);
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn sshot_page() {
        use std::fs::OpenOptions;
        use std::io::Read;
        use std::path::Path;

        let pxy = socks5_proxy_from_env();

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
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
}
