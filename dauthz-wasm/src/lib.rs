use wasm_bindgen::prelude::*;

pub mod client;
pub mod server;
pub mod store;
pub mod transport;
pub mod types;

pub use client::DauthzClient;
pub use server::DauthzService;
pub use types::*;

#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}
