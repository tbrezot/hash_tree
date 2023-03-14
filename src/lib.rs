use tiny_keccak::{Hasher, Sha3};

#[derive(Debug)]
pub struct Error(String);

/// Hash the given values using Sha3-256.
///
/// The value of the hash is updated in place.
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

/// Finds the degree of the closest ancestor of the given two integers.
///
/// # Complexity
///
/// All operations are additions or but shifting.
/// This algorithm runs in `O(ln max(n1, n2))`.
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

fn is_brother(n1: u32, n2: u32) -> bool {
    ((n1 ^ n2) >> 1) & 1 == 0
}

#[allow(dead_code)]
fn list_direct_ancestors(candidates: Vec<u32>) -> Result<Vec<Vec<u32>>, Error> {
    // Sort the candidates into two groups:
    // - when two candidates are brothers, add the parent;
    // - when a candidate has no brother, add it to the lonely children list.
    //
    // Ensure enough space is allocated to avoid reallocations.
    let mut parents = Vec::with_capacity(candidates.len() / 2);
    let mut lone_children = Vec::with_capacity(candidates.len() / 2);

    let mut pos = 0;
    let mut is_brother_found = false;
    while pos < (candidates.len() - 1) {
        if candidates[pos] >= candidates[pos + 1] {
            return Err(Error(
                "strict order must be maintained in the candidate list".to_string(),
            ));
        }

        if is_brother_found {
            // The brother has been found and the parent added.
            // A node cannot have more than one brother.
            is_brother_found = false;
        } else if is_brother(candidates[pos], candidates[pos + 1]) {
            is_brother_found = true;
            parents.push(candidates[pos] >> 1);
        } else {
            lone_children.push(candidates[pos]);
        }
        pos += 1;
    }

    // Deal with the last candidate.
    if candidates.len() == 1 || !is_brother_found {
        lone_children.push(candidates[candidates.len() - 1])
    }

    // Resize vector to avoid wasted space. This implies reallocating.
    lone_children.shrink_to_fit();
    let mut res = vec![lone_children];
    if !parents.is_empty() {
        res.append(&mut list_direct_ancestors(parents)?);
    }

    Ok(res)
}

/// Computes the list of children hashes.
///
/// This is an adaptation of a simple recursive tree walking algorithm.
///
/// # Parameters
///
/// - `ancestor`    : value of the direct ancestor
/// - `depth`       : current depth (0 is the leaf level)
/// - `start`       : leftmost branch to explore
/// - `stop`        : rightmost branch to explore
fn recursive_hash(
    ancestor: [u8; 32],
    depth: u8,
    start: u32,
    stop: u32,
) -> Result<Vec<[u8; 32]>, Error> {
    let children = if ((start ^ stop) >> depth) & 1 == 0 {
        vec![h!(ancestor, (start >> depth) & 1)]
    } else if (start >> depth) & 1 == 0 {
        vec![h!(ancestor, 0), h!(ancestor, 1)]
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
            Ok([
                // Walk through the left branch.
                // Do not limit the exploration of the rightmost branch.
                recursive_hash(children[0], depth - 1, start, u32::MAX)?,
                // Walk through the right branch.
                // Do not limit the exploration of the leftmost branch.
                recursive_hash(children[1], depth - 1, 0, stop)?,
            ]
            .concat())
        }
    }
}

/// Computes the first common ancestor hash of the `start`th and `stop`th hashes.
///
/// # Description
///
/// The first common ancestor is defined as being the last hash that allows to generate all hashes
/// between `start` and `stop`.
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
/// - the first common ancestor of 6 and 7 is `H(H(H(seed) || 1) || 1)`
/// - the first common ancestor of 0 and 3 is `H(H(seed) || 0)`
/// - the first common ancestor of 3 and 4 is `H(seed)`
///
/// # Parameters
///
/// - `seed`    : secret seed used to generate the first hash of the chain
/// - `depth`   : depth of the tree to use
/// - `start`   : indice of the first hash to generate
/// - `stop`    : indice of the last hash to generate
pub fn compute_ancestor(
    seed: [u8; 32],
    depth: u8,
    start: u32,
    stop: u32,
) -> Result<[u8; 32], Error> {
    if start > stop {
        return Err(Error(
            "start value cannot be greater than the stop value".to_string(),
        ));
    }
    let degree = find_kinship_degree(start, stop);
    let ancestor = recursive_hash(h!(seed), depth - degree, start >> degree, stop >> degree)?;
    if ancestor.len() != 1 {
        return Err(Error(format!(
            "wrong number of ancestors found: {}, should be 1",
            ancestor.len()
        )));
    }
    Ok(ancestor[0])
}

/// Computes all the hashes between the `start`th and `stop`th given the value of their first
/// common ancestor.
///
/// # Description
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
/// - generating hashes between 0 and 1 would produce:
///     + H(ancestor || 0)
///     + H(ancestor || 1)
/// - generating hashes between 3 and 4 would produce:
///     + H(H(H(ancestor || 0) || 1) || 1)
///     + H(H(H(ancestor || 1) || 0) || 0)
///
/// # Parameters
///
/// - `ancestor`    : value of the first common ancestor
/// - `start`       : indice of the first hash to generate
/// - `stop`        : indice of the last hash to generate
pub fn compute_children_hashes(
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
            h!(h!([0; 32], 0), 0),
            h!(h!([0; 32], 0), 1),
            h!(h!([0; 32], 1), 0),
            h!(h!([0; 32], 1), 1),
        ];
        let degree = find_kinship_degree(0, 3);
        let children = recursive_hash([0; 32], degree - 1, 0, 3).unwrap();
        assert_eq!(expected_children.len(), children.len());
        for (expected_child, child) in expected_children.iter().zip(children.iter()) {
            assert_eq!(expected_child, child);
        }
    }

    #[test]
    fn test_list_smallest_ancestors() {
        let (n1, n2) = (1, 4);
        let smallest_ancestors = list_direct_ancestors((n1..=n2).collect()).unwrap();
        println!("smallest ancestors of {n1}..{n2}:");
        println!("{smallest_ancestors:?}");
        panic!("I want to see my print");
    }
}
