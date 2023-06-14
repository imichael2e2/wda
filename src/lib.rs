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

#![cfg_attr(doc_cfg, feature(doc_cfg))]

#[macro_use]
mod private_dbg;

#[cfg(feature = "chromium")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "chromium")))]
pub use wdc::ChromeDriver;
#[cfg(feature = "firefox")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "firefox")))]
pub use wdc::GeckoDriver;
pub use wdc::WdcError;

mod error;

pub use error::Result;
pub use error::WdaError;

mod wdadata;

mod wda_private;

pub use wda_private::BasicAutomation;
#[cfg(feature = "extra_auto")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "extra_auto")))]
pub use wda_private::ExtraAutomation;
pub use wda_private::WdaSett;
pub use wda_private::WebDrvAstn;
