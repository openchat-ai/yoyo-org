use std::fs;
use std::io::Read;

// ── SHA-256 (FIPS 180-4, zero deps) ─────────────────────────────────

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
fn sig0(x: u32) -> u32 { x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22) }
fn sig1(x: u32) -> u32 { x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25) }
fn omg0(x: u32) -> u32 { x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3) }
fn omg1(x: u32) -> u32 { x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10) }

fn sha256_block(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[i*4], block[i*4+1], block[i*4+2], block[i*4+3]]);
    }
    for i in 16..64 {
        w[i] = omg1(w[i-2]).wrapping_add(w[i-7]).wrapping_add(omg0(w[i-15])).wrapping_add(w[i-16]);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

    for i in 0..64 {
        let t1 = hh.wrapping_add(sig1(e)).wrapping_add(ch(e, f, g)).wrapping_add(K[i]).wrapping_add(w[i]);
        let t2 = sig0(a).wrapping_add(maj(a, b, c));
        hh = g; g = f; f = e; e = d.wrapping_add(t1);
        d = c; c = b; b = a; a = t1.wrapping_add(t2);
    }

    h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
}

/// Compute SHA-256 of a byte slice.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let len_bits = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0u8);
    }
    padded.extend_from_slice(&len_bits.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut block = [0u8; 64];
        block.copy_from_slice(chunk);
        sha256_block(&mut h, &block);
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

/// Compute SHA-256 hex string of a file.
pub fn sha256_file(path: &str) -> Result<String, String> {
    let mut f = fs::File::open(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let mut data = Vec::new();
    f.read_to_end(&mut data).map_err(|e| format!("read error {path}: {e}"))?;
    let hash = sha256_bytes(&data);
    Ok(hash.iter().map(|b| format!("{b:02x}").to_lowercase()).collect())
}

/// DDC verification result.
#[derive(Debug, Clone)]
pub struct DdcReport {
    pub generation: u32,
    pub binary_path: String,
    pub computed_hash: String,
    pub expected_hash: String,
    pub pass: bool,
}

/// Verify that a binary's SHA-256 matches the expected hash.
pub fn verify(binary_path: &str, expected_hash: &str, generation: u32) -> Result<DdcReport, String> {
    let computed = sha256_file(binary_path)?;
    let pass = computed == expected_hash.to_lowercase();
    Ok(DdcReport {
        generation,
        binary_path: binary_path.to_string(),
        computed_hash: computed,
        expected_hash: expected_hash.to_string(),
        pass,
    })
}

/// Three-gen chain verification: gen1 → gen2 → gen3.
/// Returns the DDC report for each generation.
pub fn verify_three_gen(
    gen1_path: &str,
    gen1_expected: &str,
    gen2_path: &str,
    gen2_expected: &str,
    gen3_path: &str,
    gen3_expected: &str,
) -> Result<[DdcReport; 3], String> {
    Ok([
        verify(gen1_path, gen1_expected, 1)?,
        verify(gen2_path, gen2_expected, 2)?,
        verify(gen3_path, gen3_expected, 3)?,
    ])
}

/// Compare two binaries directly: compute both SHAs and report match/mismatch.
pub fn compare_binaries(path_a: &str, path_b: &str) -> Result<(String, String, bool), String> {
    let ha = sha256_file(path_a)?;
    let hb = sha256_file(path_b)?;
    Ok((ha.clone(), hb.clone(), ha == hb))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        let h = sha256_bytes(b"");
        let hex: String = h.iter().map(|b| format!("{b:02x}").to_lowercase()).collect();
        assert_eq!(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn sha256_hello() {
        let h = sha256_bytes(b"hello");
        let hex: String = h.iter().map(|b| format!("{b:02x}").to_lowercase()).collect();
        assert_eq!(hex, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn sha256_abc() {
        let h = sha256_bytes(b"abc");
        let hex: String = h.iter().map(|b| format!("{b:02x}").to_lowercase()).collect();
        assert_eq!(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn sha256_abcd() {
        // single-block test
        let h = sha256_bytes(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let hex: String = h.iter().map(|b| format!("{b:02x}").to_lowercase()).collect();
        assert_eq!(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    #[test]
    fn verify_match() {
        let tmp = std::env::temp_dir().join("ddc_test.bin");
        std::fs::write(&tmp, b"hello").unwrap();
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let report = verify(tmp.to_str().unwrap(), expected, 1).unwrap();
        assert!(report.pass);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn compare_identical() {
        let tmp = std::env::temp_dir().join("ddc_compare.bin");
        std::fs::write(&tmp, b"data").unwrap();
        let (ha, hb, same) = compare_binaries(tmp.to_str().unwrap(), tmp.to_str().unwrap()).unwrap();
        assert!(same);
        assert_eq!(ha, hb);
        let _ = std::fs::remove_file(&tmp);
    }
}
