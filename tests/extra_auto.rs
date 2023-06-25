#[cfg(all(feature = "extra_auto", feature = "firefox"))]
mod gecko {
    use wda::ExtraAutomation;
    use wda::WdaSett;
    use wda::WebDrvAstn;
    type DRV = wda::GeckoDriver;

    const OUTPUT_FILE_PREFIX: &str = "tstfile_gecko_extra_auto";
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
    fn sshot_page_allv() {
        use std::fs::OpenOptions;
        use std::io::Read;
        use std::path::Path;

        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
        ])
        .expect("new wda");

        let save_to = tst_only_fname("sshot-page-allv.png");

        // "about:license"'s output is about 44MB+, 5min+
        // wda.sshot_page_allv("about:license", &save_to)
        // .expect("sshot page allv");

        // "about::suport" is about 4M+, 25secs+
        // wda.sshot_page_allv("about:support", &save_to)
        // .expect("sshot page allv");

        wda.sshot_page_allv("about:rights", &save_to)
            .expect("sshot page allv");

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

#[cfg(all(feature = "extra_auto", feature = "chromium"))]
mod chrom {
    use wda::ExtraAutomation;
    use wda::WdaSett;
    use wda::WebDrvAstn;
    type DRV = wda::ChromeDriver;

    const OUTPUT_FILE_PREFIX: &str = "tstfile_chrome_extra_auto";
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
    fn sshot_page_allv() {
        use std::fs::OpenOptions;
        use std::io::Read;
        use std::path::Path;

        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy("127.0.0.1:10801".into()),
            WdaSett::NoGui,
        ])
        .expect("new wda");

        let save_to = tst_only_fname("sshot-page-allv.png");

        // "about:license"'s output is about 44MB+, 5min+
        // wda.sshot_page_allv("about:license", &save_to)
        // .expect("sshot page allv");

        // "about::suport" is about 4M+, 25secs+
        // wda.sshot_page_allv("about:support", &save_to)
        // .expect("sshot page allv");

        wda.sshot_page_allv("about:rights", &save_to)
            .expect("sshot page allv");

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
