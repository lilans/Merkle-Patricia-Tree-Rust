#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#[cfg(test)]
extern crate rand;

extern crate bincode;
extern crate rustc_serialize;
extern crate crypto;

pub mod merkle_tree;
