// Copyright (C) 2023 Michael Lee <imichael2e2@proton.me OR ...@gmail.com>
//
// Licensed under the MIT License <LICENSE-MIT or
// https://opensource.org/license/mit> or the GNU General Public License,
// Version 3.0 or any later version <LICENSE-GPL or
// https://www.gnu.org/licenses/gpl-3.0.txt>, at your option.
//
// This file may not be copied, modified, or distributed except except in
// compliance with either of the licenses.
//

use wdc::WdcError;

#[derive(Debug)]
pub enum WdaError {
    RendNotSupported,
    //
    FetchToolBuggy,
    FetchToolNotFound,
    ExtractToolBuggy,
    ExtractToolNotFound,
    RenameToolBuggy,
    RenameToolNotFound,
    //
    FetchWebDriver(i32),
    ExtractWebDriver(i32),
    PlaceWebDriver(i32),
    PermitWebDriver(i32),
    PlockDataCorrupt,
    WdaDataNotFound,
    BrowserProfileRootNotFound,
    ///
    /// Webdriver client is not ready for automation, element 0 is the original
    /// error thrown by client, element 1 is the TCP port used by
    /// corresponding server.
    WdcNotReady(WdcError, u16),
    WdcFail(WdcError),
    Base64DataCorrupt(base64::DecodeSliceError),
    InternetConnection,
    InvalidUrl,
    UnsupportedAutomation,
    Buggy,
}

pub type Result<T> = core::result::Result<T, WdaError>;
