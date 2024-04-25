/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// LIBRARY WARNINGS
#![warn(
    clippy::default_trait_access,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::unimplemented,
    clippy::use_self,
    missing_copy_implementations,
    missing_docs,
    non_snake_case,
    non_upper_case_globals,
    rust_2018_idioms,
    unreachable_pub
)]
#![allow(
    clippy::single_component_path_imports,
    clippy::upper_case_acronyms, // can be removed on a major release boundary
)]
#![recursion_limit = "2048"]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Hickory DNS is intended to be a fully compliant domain name server and client library.
//!
//! # Goals
//!
//! * Only safe Rust
//! * All errors handled
//! * Simple to manage servers
//! * High level abstraction for clients
//! * Secure dynamic update
//! * New features for securing public information

pub use hickory_proto as proto;
#[cfg(feature = "hickory-recursor")]
#[cfg_attr(docsrs, doc(cfg(feature = "recursor")))]
pub use hickory_recursor as recursor;
#[cfg(feature = "hickory-resolver")]
#[cfg_attr(docsrs, doc(cfg(feature = "resolver")))]
pub use hickory_resolver as resolver;

mod access;
pub mod authority;
pub mod config;
pub mod error;
pub mod server;
pub mod store;

pub use self::server::ServerFuture;

pub(crate) struct NoHasher;

impl std::hash::Hasher for NoHasher {
    fn write(&mut self, _bytes: &[u8]) {}
    
    fn finish(&self) -> u64 {
        0
    }
}

#[derive(Default)]
pub(crate) struct BuildNoHasher;

impl std::hash::BuildHasher for BuildNoHasher {
    type Hasher = NoHasher;
    fn build_hasher(&self) -> NoHasher {
        NoHasher
    }
}

/// Returns the current version of Hickory DNS
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
