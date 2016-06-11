extern crate bincode;
extern crate rustc_serialize;
extern crate crypto;

use std::collections::BTreeMap;
use std::mem;

use rustc_serialize::Encodable;
use bincode::rustc_serialize::encode;
use bincode::SizeLimit;
use crypto::digest::Digest;
use crypto::sha2::Sha256;

fn max_length(a: &[u8], b: &[u8]) -> usize {
    let mut i: usize = 0;

    while i < a.len() && i < b.len() && a[i] == b[i] {
        i += 1;
    }

    i
}

pub struct MerklePatriciaTree<T> where T: Encodable {
    value: Option<T>,
    key: Vec<u8>,
    hash: [u8; 32],
    children: BTreeMap<u8, MerklePatriciaTree<T>>
}

impl<T> MerklePatriciaTree<T> where T: Encodable {
    pub fn new() -> MerklePatriciaTree<T> {
        MerklePatriciaTree {
            value: None,
            key: Vec::new(),
            children: BTreeMap::new(),
            hash: [0; 32],
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<&T> {
        if self.key.is_empty() || key.starts_with(&self.key) {
            if key.len() == self.key.len() {
                return self.value.as_ref();
            }
            else {
                let suffix = &key[self.key.len()..];
                return self.children[&suffix[0]].get(suffix);
            }
        }
        None
    }

    pub fn insert(&mut self, key: &[u8], value: T) {
        if self.is_empty() {
            self.key.extend_from_slice(key);
            self.value = Some(value);
        }
        else {
            let length = max_length(&self.key, key);
            if length >= self.key.len() {
                if length == key.len() {
                    if self.value.is_some() {
                        panic!("Given key is already exists");
                    }
                    self.value = Some(value);
                    self.update_hash();
                } else {
                    let suffix = &key[length..];
                    self.insert_predecessor(suffix, value);
                }
            }
            else {
                let prefix = self.key[0..length].to_vec();
                let suffix = self.key[length..].to_vec();

                self.key = prefix;

                let mut node = MerklePatriciaTree {
                    key: suffix,
                    value: self.value.take(),
                    children: BTreeMap::new(),
                    hash: [0; 32],
                };

                mem::swap(&mut node.children, &mut self.children);
                node.update_hash();

                self.children.clear();
                self.children.insert(node.key[0], node);

                if length == key.len() {
                    self.value = Some(value);
                }
                else {
                    self.value = None;
                    let suffix = &key[length..];
                    self.insert_predecessor(suffix, value);
                }
            }
        }

        self.update_hash();
    }

    pub fn remove(&mut self, key: &[u8]) -> Option<T> {
        if self.key.is_empty() || key.starts_with(&self.key) {
            if key.len() == self.key.len() {
                let value = self.value.take();
                self.value = None;
                self.try_to_compress();
                return value;
            }
            else if key.len() > self.key.len() {
                let suffix = &key[self.key.len()..];
                let mut value = None;
                if let Some(mut node) = self.children.get_mut(&suffix[0]) {
                    value = node.remove(suffix);
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

    pub fn is_empty(&self) -> bool {
        self.children.is_empty() && self.value.is_none()
    }

    fn insert_predecessor(&mut self, suffix: &[u8], value: T) {
        let child_to_push = match self.children.get_mut(&suffix[0]) {
            Some(pred) => {
                pred.insert(suffix, value);
                None
            }
            None => {
                let mut child = MerklePatriciaTree::new();
                child.insert(suffix, value);
                Some(child)
            }
        };
        if let Some(child) = child_to_push {
            self.children.insert(child.key[0], child);
        }
    }

    fn add_hashed_value(&self, out: &mut Sha256) {
        let input = encode(self.value.as_ref().unwrap(), SizeLimit::Infinite).unwrap();

        let mut hash = [0; 32];
        let mut hasher = Sha256::new();
        hasher.input(&input);
        hasher.result(&mut hash);

        out.input(&hash);
    }

    fn add_hashed_key(&self, out: &mut Sha256) {
        let mut hash = [0; 32];
        let mut hasher = Sha256::new();
        hasher.input(&self.key);
        hasher.result(&mut hash);

        out.input(&hash);
    }

    fn update_hash(&mut self) {
        if self.is_empty() {
            self.hash = [0; 32];
        }
        else {
            let mut hasher = Sha256::new();

            self.add_hashed_key(&mut hasher);
            if self.value.is_some() {
                self.add_hashed_value(&mut hasher);
            }

            for child in self.children.values() {
                hasher.input(&child.hash);
            }

            hasher.result(&mut self.hash);
        }
    }

    fn try_to_compress(&mut self) {
        if self.is_empty() {
            self.key.clear();
        }
        else if self.value.is_none() && self.children.len() == 1 {
            let mut new_children = BTreeMap::new();
            {
                let child;
                {
                    let (_, node) = self.children.iter_mut().next().unwrap();
                    child = node;
                }

                self.key.extend_from_slice(&child.key);
                self.value = child.value.take();
                mem::swap(&mut new_children, &mut child.children);
            }
            mem::swap(&mut self.children, &mut new_children);
        }
        self.update_hash();
    }
}

impl<T> PartialEq for MerklePatriciaTree<T>
    where T: Clone + Encodable {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl<T> Eq for MerklePatriciaTree<T> where T: Clone + Encodable {}
