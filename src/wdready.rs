enum WebDrvServer {
    Gecko_0_32_0,
    Gecko_0_32_2,
}

enum WebBrowser {
    Firefox_115_3_0esr,
    Firefox_115_3_1esr,
    Firefox_115_4_0esr,
    Firefox_115_5_0esr,
}

enum Platform {
    Linux_x86_64,
}

struct DrvChain {
    server: WebDrvServer,
    browser: WebBrowser,
    platform: Platform,
}

impl DrvChain {
    fn new(server: WebDrvServer, browser: WebBrowser, platform: Platform) -> Self {
        Self {
            server,
            browser,
            platform,
        }
    }
}

enum WdaError {
    XXX,
}

struct WdaData;

impl WdaData {
    fn prepare_drvchain(drvchain: &DrvChain) -> Result<(), WdaError> {
        Ok(())
    }
}
fn main() {
    println!("wdready");

    let pick_drv_chain = DrvChain::new(
        WebDrvServer::Gecko_0_32_2,
        WebBrowser::Firefox_115_5_0esr,
        Platform::Linux_x86_64,
    );

    match WdaData::prepare_drvchain(&pick_drv_chain) {
        Ok(_) => {
            println!("downloaded");
        }
        Err(_) => {
            println!("X downloaded");
        }
    }
}
