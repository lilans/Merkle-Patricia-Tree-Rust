extern crate crypto;
extern crate rustc_serialize;
extern crate bincode;

use std::collections::BTreeMap;
use std::mem;
use std::clone::Clone;

use rustc_serialize::Encodable;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use bincode::rustc_serialize::encode;
use bincode::SizeLimit;

/// Merkle Patricia Tree
/// The Merkle Patricia tree provides a persistent data structure to map between arbitrary-length
/// binary data. The core of the trie, and its sole requirement in terms of the protocol
/// specification is to provide a single 32-byte value that identifies a given set of key-value pairs.
///
/// Public Functios:
/// new() create new node
/// get(&self, key: &[u8]) -> Option<&T> return value with a given key
/// insert(&mut self, key: &[u8], vlaue: T) insert given value with key into tree
/// remove(&mut self, key: &[u8]) -> Option<T> remove (functions return None when value not exist)

pub trait Merkle<'a, T> where T: Encodable {
    fn new() -> &'a MerklePatriciaTree<'a, T>;
    fn insert(&mut self, key: &'a Option<&Vec<u8>>, value: &'a Option<T>);
    fn get(&self, key: &Option<Vec<u8>>) -> Option<&T>;
    fn remove(&mut self, key: &'a Option<Vec<u8>>) -> Option<T>;
}

pub struct MerklePatriciaTree<'a, T> where T: Encodable + 'a {
    value: &'a Option<T>,
    key: &'a Vec<u8>,
    hash: &'a [u8; 32],
    children: &'a BTreeMap<&'a u8, MerklePatriciaTree<'a, T>>
}

impl<'a, T> Merkle<'a, T> for MerklePatriciaTree<'a, T> where T: Encodable + 'a {
    fn new() -> &'a MerklePatriciaTree<'a, T> {
        &MerklePatriciaTree::<'a, T> {
            value: &None,
            key: &Vec::<u8>::new(),
            children: &BTreeMap::new(),
            hash: &[0; 32],
        }
    }

    fn get(&self, key: &Option<Vec<u8>>) -> Option<&T> {
        if self.key.is_empty() || key.as_ref().unwrap().as_slice().starts_with(&self.key) {
            if key.as_ref().unwrap().len() == self.key.len() {
                return self.value.as_ref();
            } else {
                let temp = &key.as_ref().unwrap()[self.key.len()..];
                let mut suffix: Vec<u8> = Vec::new();
                suffix.extend_from_slice(temp);
                return self.children[&suffix[0]].get(&Some(suffix));
            }
        }
        None
    }

    fn insert(&mut self, key: &'a Option<&Vec<u8>>, value: &'a Option<T>) {
        if self.is_empty() {
            self.key = *key.as_ref().unwrap();
            self.value = &Some(*value.as_ref().unwrap());
        } else {
            let max_matched_length = |a: &Option<&Vec<u8>>, b: &'a Option<&Vec<u8>>| {
                let mut count: usize = 0;
                while count < a.as_ref().unwrap().len() &&
                    count < b.as_ref().unwrap().len() && a.unwrap()[count] == b.unwrap()[count] {
                    count += 1;
                }
                count
            };

            let length = max_matched_length(&Some(&self.key), key);

            if length >= self.key.len()  {
                if length == key.unwrap().len() {
                    if self.value.is_some () {
                        panic!("key exists");
                    }

                self.value = &Some(*value.as_ref().unwrap());
                self.update_hash();
                } else {
                    let temp = &key.unwrap()[length..];
                    let mut suffix: Vec<u8> = Vec::new();
                    suffix.extend_from_slice(temp);
                    self.insert_predecessor(Some(suffix), *value.as_ref().unwrap());
                }
            } else {
                let suffix = self.key[length..].to_vec();
                let prefix = self.key[0..length].to_vec();

                self.key = &prefix;

                let mut node: &'a MerklePatriciaTree<'a, T> =
                    MerklePatriciaTree::<'a, T>::create_node_with_args(self.value,
                                                              &suffix, &[0; 32],
                                                              &BTreeMap::new());

                mem::swap(&mut node.children, &mut self.children);
                node.update_hash();

                self.children.clear();
                self.children.insert(&node.key[0], *node);

                if length == key.unwrap().len() {
                    self.value = &Some(*value.as_ref().unwrap());
                } else {
                    self.value = &None;
                    let temp = &key.unwrap()[length..];
                    let suffix: Vec<u8> = Vec::new();
                    suffix.extend_from_slice(temp);
                    self.insert_predecessor(Some(suffix), *value.as_ref().unwrap());
                }
            }
        }
        self.update_hash();
    }

    fn remove(&mut self, key: &Option<Vec<u8>>) -> Option<T> {
        if self.key.is_empty() || key.as_ref().unwrap().starts_with(&self.key) {
            if key.unwrap().len() == self.key.len() {
                let value = self.value.take();
                self.value = &None;
                self.try_to_compress();
                return value;
            } else if key.as_ref().unwrap().len() > self.key.len() {
                let temp = &key.unwrap()[self.key.len()..];
                let suffix: Vec<u8> = Vec::new();
                suffix.extend_from_slice(temp);
                let mut value = None;
                if let Some(mut node) = self.children.get_mut(&suffix[0]) {
                    value = node.remove(&Some(suffix));
                }

                if value.is_some() {
                    if self.children[&suffix[0]].is_empty() {
                        self.children.remove(&suffix[0]);
                    }
                    self.try_to_compress();
                    return value;
                }
            }
        }
        None
    }
}

impl<'a, T> MerklePatriciaTree<'a, T> where T: Encodable + 'a {
    fn create_node_with_args(value: &'a Option<T>, key: &'a Vec<u8>, hash: &'a [u8; 32],
                             children: &'a BTreeMap<&'a u8, MerklePatriciaTree<'a, T>>)
                             -> &'a MerklePatriciaTree<'a, T> {
        &MerklePatriciaTree::<'a, T> {
            value: value,
            key: key,
            hash: hash,
            children: children,
        }
    }

    fn add_hashed(&self, out: &mut Sha256, what: &str) {
        match what {
            "value" => {
                let input = encode(self.value.as_ref().unwrap(), SizeLimit::Infinite).unwrap();

                let mut hash = [0; 32];
                let mut hasher = Sha256::new();
                hasher.input(&input);
                hasher.result(&mut hash);

                out.input(&hash);
            }
            "key" => {
                let mut hash = [0; 32];
                let mut hasher = Sha256::new();
                hasher.input(&self.key);
                hasher.result(&mut hash);

                out.input(&hash);
            }
            _ => panic!("incorrect value")
        }
    }

    fn update_hash(&mut self) {
        if self.is_empty() {
            self.hash = &[0; 32];
        } else {
            let mut hasher = Sha256::new();

            self.add_hashed(&mut hasher, "key");
            if self.value.is_some() {
                self.add_hashed(&mut hasher, "value");
            }

            for child in self.children.values() {
                hasher.input(child.hash);
            }

            hasher.result(&mut *self.hash);
        }
    }

    fn try_to_compress(&mut self) {
        if self.is_empty() {
            self.key.clear();
        }
        else if self.value.is_none() && self.children.len() == 1 {
            let new_children: &mut &'a BTreeMap<&'a u8, MerklePatriciaTree<'a, T>>
                =  &mut &BTreeMap::<&'a u8, MerklePatriciaTree<'a, T>>::new();
            {
                let child;
                {
                    let (_, node) = self.children.iter_mut().next().unwrap();
                    child = node;
                }

                self.key.extend_from_slice(&child.key);
                self.value = &child.value.take();
                mem::swap(&mut new_children, &mut &mut child.children);
            }
            mem::swap(&mut self.children, new_children);
        }
        self.update_hash();
    }

        pub fn is_empty(&self) -> bool {
        self.children.is_empty() && self.value.is_none()
    }

    fn insert_predecessor(&mut self, suffix: Option<Vec<u8>>, value: T) {
        let child_to_push = match self.children.get_mut(&suffix.as_ref().unwrap()[0]) {
            Some(pred) => {
                pred.insert(&Some(suffix.as_ref().unwrap()), &Some(value));
                None
            }
            None => {
                let mut child = MerklePatriciaTree::new();
                child.insert(&Some(suffix.as_ref().unwrap()), &Some(value));
                Some(child)
            }
        };
        if let Some(child) = child_to_push {
            self.children.insert(&child.key[0], *child);
        }
    }

}

impl<'a, T> PartialEq for MerklePatriciaTree<'a, T>
    where T: Clone + Encodable
{
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl<'a, T> Eq for MerklePatriciaTree<'a, T> where T: Clone + Encodable {}

//private functions test
#[cfg(test)]
mod tests {
    extern crate rand;

    use merkle_tree::Merkle;
    use merkle_tree::MerklePatriciaTree;
    use std::collections::HashMap;
    use self::rand::Rng;

    #[test]
    fn hash_test() {
        let mut new_tree = MerklePatriciaTree::<u8>::new();

        new_tree.insert(b"q", 1);
        new_tree.insert(b"qw", 2);
        new_tree.insert(b"qwe", 3);
        new_tree.insert(b"qwer", 4);
        new_tree.insert(b"qwert", 5);
        new_tree.insert(b"qwerty", 6);


        let mut new_tree2 = MerklePatriciaTree::<u8>::new();

        new_tree2.insert(b"q", 1);
        new_tree2.insert(b"qw", 2);
        new_tree2.insert(b"qwe", 3);
        new_tree2.insert(b"qwer", 4);
        new_tree2.insert(b"qwert", 5);
        new_tree2.insert(b"qwerty", 6);

        assert_eq!(&new_tree.hash, &new_tree2.hash);

    }

    #[test]
    fn hash_test_different() {
        let mut new_tree = MerklePatriciaTree::<u8>::new();

        new_tree.insert(b"q", 1);
        new_tree.insert(b"qw", 2);
        new_tree.insert(b"qwe", 3);
        new_tree.insert(b"qwer", 4);
        new_tree.insert(b"qwert", 5);
        new_tree.insert(b"qwerty", 6);


        let mut new_tree2 = MerklePatriciaTree::<u8>::new();

        new_tree2.insert(b"q", 1);
        new_tree2.insert(b"qw", 2);
        new_tree2.insert(b"qwe", 3);
        new_tree2.insert(b"qwer", 4);
        new_tree2.insert(b"qwert", 5);
        new_tree2.insert(b"qqwerty", 6);

        assert!(&new_tree.hash != &new_tree2.hash);

    }

}
