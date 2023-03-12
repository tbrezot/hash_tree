#![allow(dead_code)]

use tiny_keccak::{Hasher, Sha3};

#[derive(Debug)]
pub struct Error(String);

/// Hash the given value using Sha3-256.
///
/// The value of the hash is updated in place.
fn h(mut ancestor: [u8; 32], flag: u32) -> [u8; 32] {
    let mut hasher = Sha3::v256();
    hasher.update(&ancestor);
    hasher.update(&[flag as u8]);
    hasher.finalize(&mut ancestor);
    ancestor
}

/// Finds the degree of the closest ancestor of the given two integers.
pub fn find_kinship_degree(n1: u32, n2: u32) -> u8 {
    let mut ancestor = 0;
    let mut diff = n1 ^ n2;
    while diff != 0 {
        ancestor += 1;
        diff >>= 1;
    }
    ancestor
}

/// Computes the list of children hashes.
fn recursive_hash(
    ancestor: [u8; 32],
    depth: u8,
    start: u32,
    stop: u32,
) -> Result<Vec<[u8; 32]>, Error> {
    let children = if (start >> depth) % 2 == (stop >> depth) % 2 {
        vec![h(ancestor, (start >> depth) % 2)]
    } else if (start >> depth) % 2 < (stop >> depth) % 2 {
        vec![
            h(ancestor, (start >> depth) % 2),
            h(ancestor, (stop >> depth) % 2),
        ]
    } else {
        return Err(Error(format!(
            "start value's ({start}) {depth}th bit is greater than the stop value's ({stop}) one"
        )));
    };

    if depth == 0 {
        Ok(children)
    } else {
        if children.len() == 1 {
            // Branch does *not* fork.
            recursive_hash(children[0], depth - 1, start, stop)
        } else {
            // Branch forks.
            Ok([
                recursive_hash(children[0], depth - 1, start, u32::MAX)?,
                recursive_hash(children[1], depth - 1, 0, stop)?,
            ]
            .concat())
        }
    }
}

/// Computes the first ancestor hash.
fn compute_ancestor(
    seed: [u8; 32],
    graph_depth: u8,
    start: u32,
    stop: u32,
) -> Result<[u8; 32], Error> {
    if start > stop {
        return Err(Error(
            "start value cannot be greater than the stop value".to_string(),
        ));
    }
    let degree = find_kinship_degree(start, stop);
    let ancestor = recursive_hash(seed, graph_depth - degree, start >> degree, stop >> degree)?;
    if ancestor.len() != 1 {
        return Err(Error(format!(
            "wrong number of ancestors found: {}, should be 1",
            ancestor.len()
        )));
    }
    Ok(ancestor[0])
}

fn compute_children_hashes(
    ancestor: [u8; 32],
    start: u32,
    stop: u32,
) -> Result<Vec<[u8; 32]>, Error> {
    if start > stop {
        return Err(Error(
            "start value cannot be greater than the stop value".to_string(),
        ));
    }
    let degree = find_kinship_degree(start, stop);
    recursive_hash(ancestor, degree - 1, start, stop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;

    #[test]
    fn test_find_kinship_degree() {
        assert_eq!(find_kinship_degree(0, 0), 0);
        assert_eq!(find_kinship_degree(0, 1), 1);
        assert_eq!(find_kinship_degree(1, 2), 2);
        assert_eq!(find_kinship_degree(3, 4), 3);
        assert_eq!(find_kinship_degree(7, 8), 4);
    }

    #[test]
    fn test_recursive_hash() {
        // Check only one hash is returned when an only path is explored for a non null depth.
        assert_eq!(recursive_hash([0; 32], 3, 0, 0).unwrap().len(), 1);

        // Check the correct number of children is returned.
        const N: u32 = 256;
        for _ in 0..1000 {
            let n1 = rand::random::<u32>() % N;
            let n2 = rand::random::<u32>() % N;
            let depth = find_kinship_degree(n1, n2);
            let (min, max) = (n1.min(n2), n1.max(n2));
            let children = recursive_hash([0; 32], depth - 1, min, max).unwrap();
            assert_eq!(children.len() as u32, max - min + 1);
        }

        // Check some hash values.
        let expected_children = [
            h(h([0; 32], 0), 0),
            h(h([0; 32], 0), 1),
            h(h([0; 32], 1), 0),
            h(h([0; 32], 1), 1),
        ];
        let degree = find_kinship_degree(0, 3);
        let children = recursive_hash([0; 32], degree - 1, 0, 3).unwrap();
        assert_eq!(expected_children.len(), children.len());
        for (expected_child, child) in expected_children.iter().zip(children.iter()) {
            assert_eq!(expected_child, child);
        }
    }
}