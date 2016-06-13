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

trait Merkle<T> where T: Encodable + Clone {
    fn new() -> MerklePatriciaTree<T>;
    fn insert(&mut self, key: &[u8], value: T);
    fn get(&self, key: &[u8]) -> Option<&T>;
    fn remove(&mut self, key: &[u8]) -> Option<T>;
}

struct MerklePatriciaTree<T> where T: Encodable + Clone {
    value: Option<T>,
    key: Vec<u8>,
    hash: [u8; 32],
    children: BTreeMap<u8, MerklePatriciaTree<T>>
}

impl<T> MerklePatriciaTree<T> where T: Encodable + Clone{
    fn create_node_with_args(value: Option<T>, key: Vec<u8>, hash: [u8; 32],
                             children: BTreeMap<u8, MerklePatriciaTree<T>>)
                             -> MerklePatriciaTree<T> {
        MerklePatriciaTree {
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
            self.hash = [0; 32];
        } else {
            let mut hasher = Sha256::new();

            self.add_hashed(&mut hasher, "key");
            if self.value.is_some() {
                self.add_hashed(&mut hasher, "value");
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

}

impl<T> Merkle<T> for MerklePatriciaTree<T> where T: Encodable + Clone {
    fn new() -> MerklePatriciaTree<T> {
        MerklePatriciaTree {
            value: None,
            key: Vec::new(),
            children: BTreeMap::new(),
            hash: [0; 32],
        }
    }

    fn get(&self, key: &[u8]) -> Option<&T> {
        if self.key.is_empty() || key.starts_with(&self.key) {
            if key.len() == self.key.len() {
                return self.value.as_ref();
            } else {
                let suffix = &key[self.key.len()..];
                return self.children[&suffix[0]].get(suffix);
            }
        }
        None
    }

    fn insert(&mut self, key: &[u8], value: T) {
        if self.is_empty() {
            self.key.extend_from_slice(key);
            self.value = Some(value.clone());
        } else {
            let max_matched_length = |a: &[u8], b: &[u8]| {
                let mut count: usize = 0;
                while count < a.len() && count < b.len() && a[count] == b[count] {
                    count += 1;
                }
                count
            };

            let length = max_matched_length(&self.key, key);

            if length >= self.key.len()  {
                if length == key.len() {
                    if self.value.is_some () {
                        panic!("key exists");
                    }

                self.value = Some(value);
                self.update_hash();
                } else {
                    let suffix = &key[length..];
                    self.insert_predecessor(suffix, value);
                }
            } else {
                let suffix = self.key[length..].to_vec();
                let prefix = self.key[0..length].to_vec();

                self.key = prefix;

                let mut node = MerklePatriciaTree::create_node_with_args(self.value.take(),
                                                                         suffix, [0; 32],
                                                                         BTreeMap::new());

                mem::swap(&mut node.children, &mut self.children);
                node.update_hash();

                self.children.clear();
                self.children.insert(node.key[0], node);

                if length == key.len() {
                    self.value = Some(value);
                } else {
                    self.value = None;
                    let suffix = &key[length..];
                    self.insert_predecessor(suffix, value);
                }
            }
        }
        self.update_hash();
    }

    fn remove(&mut self, key: &[u8]) -> Option<T> {
        if self.key.is_empty() || key.starts_with(&self.key) {
            if key.len() > self.key.len() {
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
}


impl<T> PartialEq for MerklePatriciaTree<T>
    where T: Clone + Encodable
{
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl<T> Eq for MerklePatriciaTree<T> where T: Clone + Encodable {}
