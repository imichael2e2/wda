#[cfg(feature = "firefox")]
mod itst {
    use std::borrow::Cow;
    use wda::WdaError;
    use wda::WdaSett;
    use wda::WdcError;
    use wda::WebDrvAstn;
    type DRV = wda::GeckoDriver;

    #[test]
    fn err_new_1_th1() {
        // ensure error is predictable, and if any, cleanup is ensured as well.
        //
        // note that, chromedrv is more unpredictable than geckodrv, in terms of
        // webdriver errors, thus no alike tests for chromedrv.

        let pxy = socks5_proxy_from_env();

        let may_wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
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

        let pxy = socks5_proxy_from_env();

        let may_wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
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

        let pxy = socks5_proxy_from_env();

        let may_wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
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
    fn profile_id_1() {
        // not giving profile id means use `profile-0`

        let got_profile1: String;
        let got_profile2: String;

        let pxy = socks5_proxy_from_env();

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
            ])
            .expect("new wda");

            got_profile1 = wda.profile_id().expect("bug").to_string();
        }

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
            ])
            .expect("new wda");

            got_profile2 = wda.profile_id().expect("bug").to_string();
        }

        assert_eq!(got_profile1, "profile-0");
        assert_eq!(got_profile2, "profile-0");
    }

    #[test]
    fn profile_id_2() {
        // one default, one custom

        let got_profile1: String;
        let got_profile2: String;
        let all_profiles: Vec<String>;

        let pxy = socks5_proxy_from_env();

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
            ])
            .expect("new wda");

            got_profile1 = wda.profile_id().expect("bug").to_string();
        }

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
                WdaSett::BrowserProfileId("profile-test-web-ui".into()),
            ])
            .expect("new wda");

            got_profile2 = wda.profile_id().expect("bug").to_string();
            all_profiles = wda.existing_profiles().expect("bug");
        }

        assert_eq!(got_profile1, "profile-0");
        assert_eq!(got_profile2, "profile-test-web-ui");
        assert_eq!(all_profiles, vec!["profile-0", "profile-test-web-ui"]);
    }

    #[test]
    fn profile_id_3() {
        // invalid profile id

        let wda = WebDrvAstn::<DRV>::new(vec![
            WdaSett::NoGui,
            WdaSett::BrowserProfileId("profile-1_".into()),
        ]);

        if let Err(err) = wda {
            match err {
                WdaError::InvalidBrowserProfileId => {}
                _e => {
                    assert!(false);
                }
            }
        } else {
            assert!(false);
        }
    }

    fn socks5_proxy_from_env() -> String {
        let pxy = if let Ok(v) = std::env::var("SOCKS5_PROXY") {
            v
        } else {
            "".to_string()
        };
        pxy
    }
}
