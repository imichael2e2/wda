// Copyright (C) 2023 Michael Lee <imichael2e2@proton.me/...@gmail.com>
//
// Licensed under the MIT License <LICENSE-MIT or
// https://opensource.org/license/mit> or the GNU General Public License,
// Version 3.0 or any later version <LICENSE-GPL or
// https://www.gnu.org/licenses/gpl-3.0.txt>, at your option.
//
// This file may not be copied, modified, or distributed except except in
// compliance with either of the licenses.
//

macro_rules! dbgmsg {
    ($fmtstr:expr) => {
        #[cfg(feature = "dev")]
        let dbgmsg = format!($fmtstr);
        #[cfg(feature = "dev")]
        dbg!(dbgmsg);
    };
    ($fmtstr:expr, $($val:expr),+ $(,)?) => {
        #[cfg(feature = "dev")]
        let dbgmsg = format!($fmtstr, $($val),+);
        #[cfg(feature = "dev")]
        dbg!(dbgmsg);
    };
}

macro_rules! dbgg {
    () => {
        #[cfg(feature = "dev")]
        dbg!();
    };
    ($val:expr $(,)?) => {
        #[cfg(feature = "dev")]
        dbg!($val);
    };
    ($($val:expr),+ $(,)?) => {
        #[cfg(feature = "dev")]
        ($(dbg!($val)),+);
    };
}

macro_rules! run_diag {
    ($phase:expr, $blk:block) => {
        #[cfg(feature = "diag")]
        let start = std::time::Instant::now();

        $blk;

        #[cfg(feature = "diag")]
        let dura = start.elapsed();
        #[cfg(feature = "diag")]
        let diag_msg = format!("{}: {:?}", $phase, dura);
        #[cfg(feature = "diag")]
        dbg!(diag_msg);
    };
}
