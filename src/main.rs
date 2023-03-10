use rand;

pub fn find_kinship_degree(n1: u32, n2: u32) -> u8 {
    let mut ancestor = 0;
    let mut diff = n1 ^ n2;
    while diff != 0 {
        ancestor += 1;
        diff >>= 1;
    }
    ancestor
}

/// Returns the minimum number of bits needed to code the given `u32`.
pub fn get_bit_size(n: u32) -> u8 {
    // Values can't be encoded in less than one bit.
    let mut depth = 1;
    while depth < 32 {
        if n >> depth == 0 {
            break;
        }
        depth += 1;
    }
    depth
}

/// Computes the first ancestor hash.
///
/// This should be done on client side.
fn compute_start_hash(_seed: &[u8], max: u32, n1: u32, n2: u32) -> Vec<u8> {
    let degree = find_kinship_degree(n1, n2);
    let n_bits = get_bit_size(max);
    // Here compute root hash value instead.
    let mut res = Vec::with_capacity((n_bits - degree) as usize);
    for pos in (degree..n_bits).rev() {
        let bit = (n1 >> pos) % 2;
        // Here compute `Hash(h || bit)` instead of pushing
        res.push(bit as u8);
    }
    // Here return hash instead
    res
}

/// Compute the list of children hashes from an ancestor and following the given branches.
fn compute_children_hashes(ancestor: [u8; 32], start: u32, stop: u32) -> Vec<[u8; 32]> {
    Vec::new()
}

fn main() {
    const N: u32 = 16;
    find_kinship_degree(0, 15);
    for _ in 0..1 {
        let n1 = rand::random::<u32>() % N;
        let n2 = rand::random::<u32>() % N;
        println!(
            "Common ancestor of ({n1}, {n2}) is: {:?}",
            compute_start_hash(b"", N - 1, n1, n2)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_depth() {
        for i in 0..32u8 {
            assert_eq!(get_bit_size(2u32.pow(i as u32)), i + 1);
        }
        assert_eq!(get_bit_size(u32::MAX), 32);
    }

    #[test]
    fn test_find_kinship_degree() {
        assert_eq!(find_kinship_degree(0, 0), 0);
        assert_eq!(find_kinship_degree(0, 1), 1);
        assert_eq!(find_kinship_degree(1, 2), 2);
        assert_eq!(find_kinship_degree(3, 4), 3);
        assert_eq!(find_kinship_degree(7, 8), 4);
    }
}
