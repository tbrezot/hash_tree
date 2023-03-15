use std::collections::HashSet;

use tiny_keccak::{Hasher, Sha3};

#[derive(Debug)]
pub struct Error(String);

/// Hash the given values using Sha3-256.
macro_rules! h {
    ($ancestor: expr $(, $bit: expr)?) => {{
        let mut hasher = Sha3::v256();
        hasher.update(&$ancestor);
        $(
            hasher.update(&[$bit as u8]);
        )?
        let mut output = [0; 32];
        hasher.finalize(&mut output);
        output
    }};
}

/// Computes the list of children hashes within the given range for the given
/// ancestor.
///
/// This is an adaptation of a simple recursive tree walking algorithm.
///
/// # Parameters
///
/// - `ancestor`    : value of the ancestor to compute the children for
/// - `depth`       : ancestor depth (0 is the leaf level)
/// - `start`       : leftmost branch to explore
/// - `stop`        : rightmost branch to explore
fn recursive_hash(
    ancestor: [u8; 32],
    depth: u8,
    start: u32,
    stop: u32,
) -> Result<Vec<[u8; 32]>, Error> {
    if depth == 0 {
        return Ok(vec![ancestor]);
    }

    // From now on, consider the depth of the children rather than the depth of
    // the ancestor.
    let depth = depth - 1;

    let children = if ((start ^ stop) >> depth) & 1 == 0 {
        Ok(vec![h!(ancestor, (start >> depth) & 1)])
    } else if (start >> depth) & 1 == 0 {
        Ok(vec![h!(ancestor, 0), h!(ancestor, 1)])
    } else {
        Err(Error(format!(
            "start value's ({start}) {depth}th bit is greater than the stop value's ({stop}) one"
        )))
    }?;

    if children.len() == 1 {
        recursive_hash(children[0], depth, start, stop)
    } else {
        Ok([
            // Walk through the left branch.
            // Do not limit the exploration of the rightmost branch.
            recursive_hash(children[0], depth, start, u32::MAX)?,
            // Walk through the right branch.
            // Do not limit the exploration of the leftmost branch.
            recursive_hash(children[1], depth, 0, stop)?,
        ]
        .concat())
    }
}

/// Computes the minimal ancestor cover for hashes between `start` and `stop`.
///
/// Returns the hash set of ancestors in the cover and their associated depth.
/// The hash set allows hiding the order of the ancestors.
///
/// # Description
///
/// The minimal ancestor cover are defined as being the minimum set of
/// ancestors allowing to generate the given children.
///
/// ```txt
///
///         H(seed)
///            |
///      -------------
///      0           1
///      |           |
///   -------     -------
///   0     1     0     1
///   |     |     |     |
/// ----  ----  ----  ----
/// 0  1  0  1  0  1  0  1
/// |  |  |  |  |  |  |  |
/// 0  1  2  3  4  5  6  7  <-- indice of the hash in the tree order
///
/// ```
///
/// In this example:
/// - the minimal ancestor cover of 6 and 7 is `{ H(H(H(seed) || 1) || 1) }`
/// - the minimal ancestor cover of 0 and 3 is `{ H(H(H(seed) || 1) || 1) }`
/// - the minimal ancestor cover of 4 and 4 is:
///
/// ```txt
/// {
///     H(H(H(H(seed) || 0) || 1) || 1),
///     H(H(H(H(seed) || 1) || 0) || 0)
/// }
/// ```
///
/// # Parameters
///
/// - `seed`    : secret seed used to generate the first hash of the chain
/// - `depth`   : depth of the tree to use
/// - `start`   : indice of the first hash to generate
/// - `stop`    : indice of the last hash to generate
pub fn compute_minimal_cover(
    seed: [u8; 32],
    depth: u8,
    start: u32,
    stop: u32,
) -> Result<HashSet<([u8; 32], u8)>, Error> {
    if ((start ^ stop) >> depth) & 1 == 0 {
        if depth == 0 {
            Ok(HashSet::from_iter([(
                h!(seed, (start >> depth) & 1),
                depth,
            )]))
        } else {
            // Only one path is possible. Follow it.
            compute_minimal_cover(h!(seed, (start >> depth) & 1), depth - 1, start, stop)
        }
    } else if (start >> depth) & 1 == 0 {
        if depth == 0 {
            return Err(Error(format!(
                "fork cannot happen at depth 0 ({start}, {stop})"
            )));
        }

        let mut left_results = if start == 0 {
            // All subgraphs are covered, this is the minimal ancestor.
            HashSet::from_iter([(h!(seed, 0), depth)])
        } else {
            // Follow left branch without limiting the exploration of the rightmost branch.
            compute_minimal_cover(h!(seed, 0), depth - 1, start, u32::MAX)?
        };

        let right_results = if stop == u32::MAX {
            // All subgraphs are covered, this is the minimal ancestor.
            HashSet::from_iter([(h!(seed, 1), depth)])
        } else {
            // Follow right branch without limiting the exploration of the leftmost branch.
            compute_minimal_cover(h!(seed, 1), depth - 1, 0, stop)?
        };

        left_results.extend(right_results);
        Ok(left_results)
    } else {
        Err(Error(format!(
            "start value's ({start}) {depth}th bit is greater than the stop value's ({stop}) one"
        )))
    }
}

pub fn derive_minimal_ancestor_cover(
    ancestors: HashSet<([u8; 32], u8)>,
) -> Result<HashSet<[u8; 32]>, Error> {
    let mut res = HashSet::with_capacity(ancestors.len());
    for (ancestor, depth) in ancestors {
        res.extend(recursive_hash(ancestor, depth, 0, u32::MAX)?);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;

    /// Finds the degree of the closest ancestor of the given two integers.
    fn find_kinship_degree(n1: u32, n2: u32) -> u8 {
        // Only bits that differ matter.
        let mut diff = n1 ^ n2;
        let mut degree = 0;
        while diff != 0 {
            degree += 1;
            diff >>= 1;
        }
        degree
    }

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
        let seed = h!([0; 32]);
        // Check only one hash is returned when an only path is explored for a non null depth.
        assert_eq!(recursive_hash(seed, 4, 0, 0).unwrap().len(), 1);

        // Check the correct number of children is returned.
        const N: u32 = 8;
        for _ in 0..1000 {
            let n1 = rand::random::<u32>() % N;
            let n2 = rand::random::<u32>() % N;
            let depth = find_kinship_degree(n1, n2);
            let (min, max) = (n1.min(n2), n1.max(n2));
            println!("{min} -> {max} ({depth})");
            let children = recursive_hash(seed, depth, min, max).unwrap();
            assert_eq!(children.len() as u32, (max - min + 1).min(1 << depth));
        }

        // Check some hash values.
        let expected_children = [
            h!(h!(seed, 0), 0),
            h!(h!(seed, 0), 1),
            h!(h!(seed, 1), 0),
            h!(h!(seed, 1), 1),
        ];
        let degree = find_kinship_degree(0, 3);
        let children = recursive_hash(seed, degree, 0, 3).unwrap();
        assert_eq!(expected_children.len(), children.len());
        for (expected_child, child) in expected_children.iter().zip(children.iter()) {
            assert_eq!(expected_child, child);
        }
    }

    #[test]
    fn test_compute_minimal_cover() {
        const DEPTH: u8 = 2;
        const SEED: [u8; 32] = [0; 32];
        let (n1, n2) = (1, 4);
        let ancestors = compute_minimal_cover(h!(SEED), DEPTH, n1, n2).unwrap();

        let expected_ancestors = [
            // (1, 0)
            (h!(h!(h!(h!([0; 32]), 0), 0), 1), 0),
            // (1, 1)
            (h!(h!(h!([0; 32]), 0), 1), 1),
            // (4, 0)
            (h!(h!(h!(h!([0; 32]), 1), 0), 0), 0),
        ];

        println!("ancestors: {ancestors:?}");
        println!("expected: {expected_ancestors:?}");

        assert_eq!(ancestors.len(), expected_ancestors.len());
        for ancestor in &expected_ancestors {
            assert!(ancestors.contains(ancestor));
        }
    }

    #[test]
    fn test_derive_minimal_ancestor_cover() {
        const DEPTH: u8 = 2;
        let seed = h!([0; 32]);
        let expected_children = [
            h!(h!(h!(seed, 0), 0), 1),
            h!(h!(h!(seed, 0), 1), 0),
            h!(h!(h!(seed, 0), 1), 1),
            h!(h!(h!(seed, 1), 0), 0),
        ];

        let ancestors = compute_minimal_cover(seed, DEPTH, 1, 4).unwrap();
        assert_eq!(ancestors.len(), 3);
        let children = derive_minimal_ancestor_cover(ancestors).unwrap();
        assert_eq!(expected_children.len(), children.len());
        for child in &expected_children {
            assert!(children.contains(child));
        }
    }
}
