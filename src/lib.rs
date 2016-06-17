#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

extern crate bincode;
extern crate rustc_serialize;
extern crate crypto;

pub mod merkle_tree;

//public functions test
#[cfg(test)]
mod tests {
    extern crate rand;

    use merkle_tree::Merkle;
    use merkle_tree::MerklePatriciaTree;
    use std::collections::HashMap;
    use self::rand::Rng;


    fn random_data() -> HashMap<String, u32> {
        let mut index: u32 = 0;
        let mut map: HashMap<String, u32> = HashMap::<String, u32>::new();

        while index < 1000 {
            let rstr: String = rand::thread_rng()
                .gen_ascii_chars()
                .take(32)
                .collect();

            map.insert(rstr, index);
            index += 1;
        }
        map
    }

    #[test]
    fn insert_test() {
        let mut new_tree = MerklePatriciaTree::new();

        new_tree.insert(b"q", 1);
        new_tree.insert(b"qw", 2);
        new_tree.insert(b"qwe", 3);
        new_tree.insert(b"qwer", 4);
        new_tree.insert(b"qwert", 5);
        new_tree.insert(b"qwerty", 6);

        assert_eq!(new_tree.get(b"q"), Some(&1));
        assert_eq!(new_tree.get(b"qw"), Some(&2));
        assert_eq!(new_tree.get(b"qwe"), Some(&3));
        assert_eq!(new_tree.get(b"qwer"), Some(&4));
        assert_eq!(new_tree.get(b"qwert"), Some(&5));
        assert_eq!(new_tree.get(b"qwerty"), Some(&6));
    }

    #[test]
    #[should_panic]
    fn exists_value() {
        let mut new_tree = MerklePatriciaTree::new();

        new_tree.insert(b"exist", 1);
        new_tree.insert(b"exist", 2);
    }

    #[test]
    fn random_insert_test() {
        let random_map = random_data();
        let mut new_tree = MerklePatriciaTree::new();

        for (key, &value) in random_map.iter() {
            new_tree.insert(key.as_bytes(), value)
        }

        for (key, &value) in random_map.iter() {
            assert_eq!(new_tree.get(&key.as_bytes()), Some(&value))
        }
    }

    #[test]
    fn remove_test() {
        let mut new_tree = MerklePatriciaTree::new();

        new_tree.insert(b"q", 1);
        new_tree.insert(b"qw", 2);
        new_tree.insert(b"qwe", 3);
        new_tree.insert(b"qwer", 4);
        new_tree.insert(b"qwert", 5);
        new_tree.insert(b"qwerty", 6);

        assert_eq!(new_tree.remove(b"q"), Some(1));
        assert_eq!(new_tree.remove(b"qw"), Some(2));
        assert_eq!(new_tree.remove(b"qwe"), Some(3));
        assert_eq!(new_tree.remove(b"qwer"), Some(4));
        assert_eq!(new_tree.remove(b"qwert"), Some(5));
        assert_eq!(new_tree.remove(b"qwerty"), Some(6));


        assert_eq!(new_tree.remove(b"q"), None);
        assert_eq!(new_tree.remove(b"qw"), None);
        assert_eq!(new_tree.remove(b"qwe"), None);
        assert_eq!(new_tree.remove(b"qwer"), None);
        assert_eq!(new_tree.remove(b"qwert"), None);
        assert_eq!(new_tree.remove(b"qwerty"), None);
    }

    #[test]
    fn remove_random_test() {
        let random_map = random_data();
        let mut new_tree = MerklePatriciaTree::new();

        for (key, &value) in random_map.iter() {
            new_tree.insert(key.as_bytes(), value)
        }

        for (key, &value) in random_map.iter() {
            assert_eq!(new_tree.remove(&key.as_bytes()), Some(value))
        }


        for (key, &value) in random_map.iter() {
            assert_eq!(new_tree.remove(&key.as_bytes()), None)
        }
    }
}
