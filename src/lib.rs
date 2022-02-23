// Copyright (c) 2020 Apple Inc.
// SPDX-License-Identifier: MPL-2.0

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Libprio-rs
//!
//! Implementation of the [Prio](https://crypto.stanford.edu/prio/) private data aggregation
//! protocol. For now we only support 0 / 1 vectors.

#[macro_use]
extern crate static_assertions;

pub mod benchmarked;
pub mod client;
mod fft;
pub mod field;
mod fp;
pub mod pcp;
mod polynomial;
mod prng;
pub mod server;
pub mod util;
pub mod vdaf;
