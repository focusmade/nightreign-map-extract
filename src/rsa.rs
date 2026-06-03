use anyhow::{Context, Result, bail};
use base64::Engine;
use num_bigint::BigUint;

const INPUT_BLOCK_SIZE: usize = 256;  // 2048-bit RSA ciphertext block
const OUTPUT_BLOCK_SIZE: usize = 255; // BouncyCastle: (bitSize - 1) / 8 = (2048-1)/8 = 255

/// Raw RSA decrypt: m = c^e mod n (no padding scheme).
///
/// BouncyCastle's RsaCoreEngine.GetOutputBlockSize() returns (bitSize-1)/8 = 255 for 2048-bit
/// keys when decrypting. ProcessBlock returns the raw BigInteger bytes (variable length), and
/// the caller (CryptoUtil) pads each block to outputBlockSize (255) with leading zeros.
/// So each 256-byte ciphertext block yields exactly 255 bytes of plaintext.
pub fn rsa_decrypt(data: &[u8], n: &BigUint, e: &BigUint) -> Vec<u8> {
    let num_blocks = data.len() / INPUT_BLOCK_SIZE;
    let mut output = Vec::with_capacity(num_blocks * OUTPUT_BLOCK_SIZE);

    for chunk in data.chunks(INPUT_BLOCK_SIZE) {
        if chunk.len() == INPUT_BLOCK_SIZE {
            let c = BigUint::from_bytes_be(chunk);
            let m = c.modpow(e, n);
            let raw = m.to_bytes_be();
            // Pad to OUTPUT_BLOCK_SIZE (255) with leading zeros
            let pad = OUTPUT_BLOCK_SIZE.saturating_sub(raw.len());
            output.extend(std::iter::repeat(0u8).take(pad));
            // If raw is somehow longer than 255 (shouldn't happen), take last 255 bytes
            if raw.len() > OUTPUT_BLOCK_SIZE {
                output.extend_from_slice(&raw[raw.len() - OUTPUT_BLOCK_SIZE..]);
            } else {
                output.extend_from_slice(&raw);
            }
        }
    }
    output
}

/// Parse a PKCS#1 PEM-encoded RSA public key ("BEGIN RSA PUBLIC KEY") and extract (n, e)
pub fn parse_pkcs1_public_key(pem: &str) -> Result<(BigUint, BigUint)> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .context("Failed to decode PEM base64")?;

    // PKCS#1: RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    let (_, inner) = parse_asn1_sequence(&der).context("Failed to parse SEQUENCE")?;
    let (rest, n_bytes) = parse_asn1_integer(inner).context("Failed to parse modulus")?;
    let (_, e_bytes) = parse_asn1_integer(rest).context("Failed to parse exponent")?;

    Ok((
        BigUint::from_bytes_be(n_bytes),
        BigUint::from_bytes_be(e_bytes),
    ))
}

fn parse_asn1_length(data: &[u8]) -> Result<(usize, &[u8])> {
    if data.is_empty() {
        bail!("Empty data for ASN.1 length");
    }
    if data[0] < 0x80 {
        Ok((data[0] as usize, &data[1..]))
    } else {
        let num_bytes = (data[0] & 0x7F) as usize;
        if num_bytes > 4 || data.len() < 1 + num_bytes {
            bail!("Invalid ASN.1 length encoding");
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[1 + i] as usize;
        }
        Ok((len, &data[1 + num_bytes..]))
    }
}

fn parse_asn1_element(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.is_empty() {
        bail!("Empty ASN.1 element");
    }
    let _tag = data[0];
    let (len, rest) = parse_asn1_length(&data[1..])?;
    if rest.len() < len {
        bail!("ASN.1 element length exceeds data");
    }
    Ok((&rest[len..], &rest[..len]))
}

fn parse_asn1_sequence(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.is_empty() || data[0] != 0x30 {
        bail!("Expected SEQUENCE (0x30), got {:02x}", data.get(0).unwrap_or(&0));
    }
    parse_asn1_element(data)
}

fn parse_asn1_integer(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.is_empty() || data[0] != 0x02 {
        bail!("Expected INTEGER (0x02), got {:02x}", data.get(0).unwrap_or(&0));
    }
    let (rest, value) = parse_asn1_element(data)?;
    // Strip leading zero byte (sign byte for positive integers)
    let value = if value.len() > 1 && value[0] == 0 {
        &value[1..]
    } else {
        value
    };
    Ok((rest, value))
}
