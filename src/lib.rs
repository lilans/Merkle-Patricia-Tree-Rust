#![feature(test)]
#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

extern crate bincode;
extern crate rustc_serialize;
extern crate crypto;

pub mod merkle_tree;


// public functions test
#[cfg(test)]
mod tests {
    extern crate test;
    extern crate rand;


    use merkle_tree::Merkle;
    use merkle_tree::MerklePatriciaTree;
    use self::rand::Rng;
    use std::collections::HashMap;
    use self::test::Bencher;

    fn random_data(count: u32) -> HashMap<String, u32> {
        let mut index: u32 = 0;
        let mut map: HashMap<String, u32> = HashMap::<String, u32>::new();

        while index < count {
            let rstr: String = rand::thread_rng()
                .gen_ascii_chars()
                .take(32)
                .collect();

            map.insert(rstr, index);
            index += 1;
        }
        map
    }

    #[bench]
    fn insert_random_bench_1(b: &mut Bencher) {
        b.iter(|| {
            let random_map = random_data(1);
            let mut new_tree = MerklePatriciaTree::new();

            for (key, &value) in random_map.iter() {
                new_tree.insert(key.as_bytes(), Some(value));
            }
        });
    }

    #[bench]
    fn insert_random_bench_10(b: &mut Bencher) {
        b.iter(|| {
            let random_map = random_data(10);
            let mut new_tree = MerklePatriciaTree::new();

            for (key, &value) in random_map.iter() {
                new_tree.insert(key.as_bytes(), Some(value));
            }
        });
    }

    #[bench]
    fn insert_random_bench_100(b: &mut Bencher) {
        b.iter(|| {
            let random_map = random_data(100);
            let mut new_tree = MerklePatriciaTree::new();

            for (key, &value) in random_map.iter() {
                new_tree.insert(key.as_bytes(), Some(value));
            }
        });
    }


    #[bench]
    fn insert_random_bench_1000(b: &mut Bencher) {
        b.iter(|| {
            let random_map = random_data(1000);
            let mut new_tree = MerklePatriciaTree::new();

            for (key, &value) in random_map.iter() {
                new_tree.insert(key.as_bytes(), Some(value));
            }
        });
    }


    #[bench]
    fn insert_random_bench_10000(b: &mut Bencher) {
        b.iter(|| {
            let random_map = random_data(10000);
            let mut new_tree = MerklePatriciaTree::new();

            for (key, &value) in random_map.iter() {
                new_tree.insert(key.as_bytes(), Some(value));
            }
        });
    }

    #[bench]
    fn remove_random_bench_1(b: &mut Bencher) {
        let random_map = random_data(1);
        let mut new_tree = MerklePatriciaTree::new();

        for (key, &value) in random_map.iter() {
            new_tree.insert(key.as_bytes(), Some(value));
        }

        b.iter(|| {
            for (key, &value) in random_map.iter() {
                new_tree.remove(&key.as_bytes());
            }
        });
    }

    #[bench]
    fn remove_random_bench_10(b: &mut Bencher) {
        let random_map = random_data(10);
        let mut new_tree = MerklePatriciaTree::new();

        for (key, &value) in random_map.iter() {
            new_tree.insert(key.as_bytes(), Some(value));
        }

        b.iter(|| {
            for (key, &value) in random_map.iter() {
                new_tree.remove(&key.as_bytes());
            }
        });
    }

    #[bench]
    fn remove_random_bench_100(b: &mut Bencher) {
        let random_map = random_data(100);
        let mut new_tree = MerklePatriciaTree::new();

        for (key, &value) in random_map.iter() {
            new_tree.insert(key.as_bytes(), Some(value));
        }

        b.iter(|| {
            for (key, &value) in random_map.iter() {
                new_tree.remove(&key.as_bytes());
            }
        });
    }

    #[bench]
    fn remove_random_bench_1000(b: &mut Bencher) {
        let random_map = random_data(1000);
        let mut new_tree = MerklePatriciaTree::new();

        for (key, &value) in random_map.iter() {
            new_tree.insert(key.as_bytes(), Some(value));
        }

        b.iter(|| {
            for (key, &value) in random_map.iter() {
                new_tree.remove(&key.as_bytes());
            }
        });
    }

    #[bench]
    fn remove_random_bench_10000(b: &mut Bencher) {
        let random_map = random_data(10000);
        let mut new_tree = MerklePatriciaTree::new();

        for (key, &value) in random_map.iter() {
            new_tree.insert(key.as_bytes(), Some(value));
        }

        b.iter(|| {
            for (key, &value) in random_map.iter() {
                new_tree.remove(&key.as_bytes());
            }
        });
    }


    #[test]
    fn insert_test() {
        let mut new_tree = MerklePatriciaTree::new();

        new_tree.insert(b"q", Some(1));
        new_tree.insert(b"qw", Some(2));
        new_tree.insert(b"qwe", Some(3));
        new_tree.insert(b"qwer", Some(4));
        new_tree.insert(b"qwert", Some(5));
        new_tree.insert(b"qwerty", Some(6));

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

        new_tree.insert(b"exist", Some(1));
        new_tree.insert(b"exist", Some(2));
    }

    #[test]
    fn random_insert_test() {
        let random_map = random_data(100);
        let mut new_tree = MerklePatriciaTree::new();

        for (key, &value) in random_map.iter() {
            new_tree.insert(key.as_bytes(), Some(value))
        }

        for (key, &value) in random_map.iter() {
            assert_eq!(new_tree.get(&key.as_bytes()), Some(&value))
        }
    }

    #[test]
    fn remove_test() {
        let mut new_tree = MerklePatriciaTree::new();

        new_tree.insert(b"q", Some(1));
        new_tree.insert(b"qw", Some(2));
        new_tree.insert(b"qwe", Some(3));
        new_tree.insert(b"qwer", Some(4));
        new_tree.insert(b"qwert", Some(5));
        new_tree.insert(b"qwerty", Some(6));

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
        let random_map = random_data(100);
        let mut new_tree = MerklePatriciaTree::new();

        for (key, &value) in random_map.iter() {
            new_tree.insert(key.as_bytes(), Some(value))
        }

        for (key, &value) in random_map.iter() {
            assert_eq!(new_tree.remove(&key.as_bytes()), Some(value))
        }


        for (key, &value) in random_map.iter() {
            assert_eq!(new_tree.remove(&key.as_bytes()), None)
        }
    }
}
