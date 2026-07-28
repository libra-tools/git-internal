//! Shared readers for Git delta streams: length parsing, partial integer decoding, and VarInt helpers
//! that both encoder and decoder reuse.

use std::io::Read;

const VAR_INT_ENCODING_BITS: u8 = 7;
const VAR_INT_CONTINUE_FLAG: u8 = 1 << VAR_INT_ENCODING_BITS;

/// Read exactly `N` bytes from the stream into a fixed array.
#[inline]
pub fn read_bytes<R: Read, const N: usize>(stream: &mut R) -> std::io::Result<[u8; N]> {
    let mut bytes = [0; N];
    stream.read_exact(&mut bytes)?;

    Ok(bytes)
}

/// Read a Git-style varint (little-endian 7-bit chunks with msb as continue flag).
pub fn read_size_encoding<R: Read>(stream: &mut R) -> std::io::Result<usize> {
    let mut value = 0;
    let mut length = 0;

    loop {
        let (byte_value, more_bytes) = read_var_int_byte(stream)?;
        value |= (byte_value as usize) << length;
        if !more_bytes {
            return Ok(value);
        }

        length += VAR_INT_ENCODING_BITS;
    }
}

/// Read a partial integer according to presence bits (used by copy instructions):
/// for each bit set in `present_bytes`, consume one byte and accumulate into `value`, shifting per byte index.
pub fn read_partial_int<R: Read>(
    stream: &mut R,
    bytes: u8,
    present_bytes: &mut u8,
) -> std::io::Result<usize> {
    let mut value: usize = 0;

    // Iterate over the byte indices
    for byte_index in 0..bytes {
        // Check if the current bit is present
        if *present_bytes & 1 != 0 {
            // Read a byte from the stream
            let [byte] = read_bytes(stream)?;

            // Add the byte value to the integer value
            value |= (byte as usize) << (byte_index * 8);
        }

        // Shift the present bytes to the right
        *present_bytes >>= 1;
    }

    Ok(value)
}

/// Read one varint byte, returning (7-bit value, has_more flag).
pub fn read_var_int_byte<R: Read>(stream: &mut R) -> std::io::Result<(u8, bool)> {
    let [byte] = read_bytes(stream)?;
    let value = byte & !VAR_INT_CONTINUE_FLAG;
    let more_bytes = byte & VAR_INT_CONTINUE_FLAG != 0;

    Ok((value, more_bytes))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{read_bytes, read_partial_int, read_size_encoding, read_var_int_byte};

    /// Should read exactly N bytes into an array.
    #[test]
    fn test_read_bytes() {
        let mut cursor = Cursor::new(vec![1u8, 2, 3]);
        let bytes: [u8; 3] = read_bytes(&mut cursor).unwrap();
        assert_eq!(bytes, [1, 2, 3]);
    }

    /// Varint byte: lower 7 bits value, msb indicates continuation.
    #[test]
    fn test_read_var_int_byte() {
        let mut cursor = Cursor::new(vec![0b1000_0001, 0b0000_0010]);
        let (v1, more1) = read_var_int_byte(&mut cursor).unwrap();
        let (v2, more2) = read_var_int_byte(&mut cursor).unwrap();
        assert_eq!(v1, 0b0000_0001);
        assert!(more1);
        assert_eq!(v2, 0b0000_0010);
        assert!(!more2);
    }

    /// Full varint assembly: two-byte encoding of 300.
    #[test]
    fn test_read_size_encoding() {
        // Encode 300 (0b1 0010 1100) in Git varint: 0b1010_1100, 0b0000_0010
        let mut cursor = Cursor::new(vec![0b1010_1100, 0b0000_0010]);
        let v = read_size_encoding(&mut cursor).unwrap();
        assert_eq!(v, 300);
    }

    /// Partial int assembly based on presence bits (little-endian copy offsets).
    #[test]
    fn test_read_partial_int() {
        // present_bytes 0b0000_1111 means offset bytes [1,2,3,4]
        let mut present = 0b0000_1111;
        let mut cursor = Cursor::new(vec![1u8, 2, 3, 4]);
        let v = read_partial_int(&mut cursor, 4, &mut present).unwrap();
        // little-endian assembly: 0x04030201
        assert_eq!(v, 0x0403_0201);
    }
}
