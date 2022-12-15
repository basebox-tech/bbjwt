/*!
 * Common code for integration  tests.
 *
 * Some parts inspired by/taken from (openidconnect-rs)[https://github.com/ramosbugs/openidconnect-rs].
 *
 * Author: markus.thielen@basebox.health
 * (c) Copyright 2022 by basebox GmbH. All rights reserved.
 */

/* ---- uses ------------------------------------------------------------------------------------ */

extern crate color_backtrace;
extern crate env_logger;

use std::sync::Once;
use std::cell::RefCell;
use std::path::Path;
use std::env;

/* ---- statics --------------------------------------------------------------------------------- */

static INIT_LOG: Once = Once::new();

thread_local! {
  static TEST_ID: RefCell<&'static str> = RefCell::new("UNINITIALIZED_TEST_ID");
}


///
/// Store the current test's ID in the thread local RefCell
///
pub fn set_test_id(test_id: &'static str) {
  TEST_ID.with(|id| *id.borrow_mut() = test_id);
}

///
/// Retrieve current test's ID from thread local RefCell
///
pub fn get_test_id() -> &'static str {
  TEST_ID.with(|id| *id.borrow())
}


/* ---- macros ---------------------------------------------------------------------------------- */

///
/// Log error; syntax is the same as for println!()
///
#[macro_export]
macro_rules! log_error {
  ($($args:tt)+) => {
    error!("[{}] {}", crate::bb_common::get_test_id(), format!($($args)+))
  }
}


///
/// Log info; syntax is the same as for println!()
///
#[macro_export]
macro_rules! log_info {
  ($($args:tt)+) => {
    info!("[{}] {}", crate::bb_common::get_test_id(), format!($($args)+));
  }
}

///
/// Log debug; syntax is the same as for println!()
///
#[macro_export]
macro_rules! log_debug {
  ($($args:tt)+) => {
    debug!("[{}] {}", crate::bb_common::get_test_id(), format!($($args)+));
  }
}

///
/// Internal log initialization.
///
fn _init_log() {
  color_backtrace::install();
  env_logger::init();
}

///
///  Initialize logging in a test function.
///
/// # Arguments
///
/// * `test_id` - name/id of the current test.
///
pub fn init_log(test_id: &'static str) {
  INIT_LOG.call_once(_init_log);
  set_test_id(test_id);
}

///
/// Return fully qualified path and file name to a file in the /tests/assets folder.
///
/// # Arguments
///
/// * `asset_name` - path and file name of the file, relative to the "assets" folder.
///
/// # Returns
///
/// Absolute path to the asset file.
///
pub fn path_to_asset_file(asset_name: &str) -> String {
  let path = Path::new(env::var("CARGO_MANIFEST_DIR")
    .expect("CARGO_MANIFEST_DIR not set").as_str()
  ).join(format!("tests/assets/{}", asset_name));

  String::from(path.to_str().unwrap())
}
