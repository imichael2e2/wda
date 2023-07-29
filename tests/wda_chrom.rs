#[cfg(feature = "chromium")]
mod itst {
    use std::borrow::Cow;
    use wda::WdaSett;
    use wda::WebDrvAstn;
    type DRV = wda::ChromeDriver;

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
        }

        assert_eq!(got_profile1, "profile-0");
        assert_eq!(got_profile2, "profile-test-web-ui");
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
