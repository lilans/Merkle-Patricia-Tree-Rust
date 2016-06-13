extern crate rand;

extern crate bincode;
extern crate rustc_serialize;
extern crate crypto;

pub mod merkle_tree;

#[test]
fn check_print () {
    let example: merkle_tree::MerklePatriciaTree<String> = merkle_tree::MerklePatriciaTree::new();
    //merkle_tree::MerklePatriciaTree::print_hello();
}
