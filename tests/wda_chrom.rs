#[cfg(feature = "chromium")]
mod itst {
    use std::borrow::Cow;
    use wda::WdaError;
    use wda::WdaSett;
    use wda::WdcError;
    use wda::WebDrvAstn;
    type DRV = wda::ChromeDriver;

    #[test]
    fn fresh_profile_1() {
        // both fresh profiles, very unlikely lead to identical results,
        // except there are many other wda(as many as ==100) trying to
        // create fresh profiles and succeed, at the point between these
        // two. so this test is nearly completely reliable.

        let got_profile1: String;
        let got_profile2: String;

        let pxy = socks5_proxy_from_env();

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
                WdaSett::CustomBrowserProfileId(None),
            ])
            .expect("new wda");

            got_profile1 = wda.profile_id().expect("bug").to_string();
        }

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
                WdaSett::CustomBrowserProfileId(None),
            ])
            .expect("new wda");

            got_profile2 = wda.profile_id().expect("bug").to_string();
        }

        assert!(got_profile1 != got_profile2);
    }

    #[test]
    fn fresh_profile_2() {
        // one fresh, one reuse it

        let got_profile1: String;
        let got_profile2: String;

        let pxy = socks5_proxy_from_env();

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
                WdaSett::CustomBrowserProfileId(None),
            ])
            .expect("new wda");

            got_profile1 = wda.profile_id().expect("bug").to_string();
        }

        {
            let wda = WebDrvAstn::<DRV>::new(vec![
                WdaSett::PrepareUseSocksProxy(pxy.clone().into()),
                WdaSett::NoGui,
                WdaSett::CustomBrowserProfileId(Some(Cow::from(&got_profile1))),
            ])
            .expect("new wda");

            got_profile2 = wda.profile_id().expect("bug").to_string();
        }

        assert!(got_profile1 == got_profile2);
    }

    #[test]
    fn fresh_profile_3() {
        // both defaul, which means use the latest one, results in
        // two may same or may different results, this is actually
        // untestable.

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

        dbg!(&got_profile1, &got_profile2);

        // they two could be anything under "cargo test",
        // which is multi-threaded env,
        //for example, 1 is "15", 2 is "19"
        assert!(u32::from_str_radix(&got_profile1, 10).expect("bug") < 100);
        assert!(u32::from_str_radix(&got_profile2, 10).expect("bug") < 100);
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
