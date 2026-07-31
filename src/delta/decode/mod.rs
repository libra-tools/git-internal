//! Decoder for Git-style delta instructions that rebuilds target objects from a base buffer and the
//! instruction stream produced by `delta::encode` (base size + result size + op codes).

use std::io::{ErrorKind, Read};

use super::{errors::GitDeltaError, utils};

const COPY_INSTRUCTION_FLAG: u8 = 1 << 7; // msb set => copy from base, otherwise inline data
const COPY_OFFSET_BYTES: u8 = 4;
const COPY_SIZE_BYTES: u8 = 3;
const COPY_ZERO_SIZE: usize = 0x10000;

/// Apply a delta stream to `base_info`, returning the reconstructed target bytes.
/// The stream format matches Git's delta encoding (see `delta::encode`):
/// - leading base size, then result size (varint)
/// - sequence of ops: data instructions (msb=0, lower 7 bits = literal length) or copy instructions
///   (msb=1, following bytes encode offset/size).
pub fn delta_decode(
    mut stream: &mut impl Read,
    base_info: &[u8],
) -> Result<Vec<u8>, GitDeltaError> {
    // Read declared base size and result size
    let base_size = utils::read_size_encoding(&mut stream).unwrap();
    if base_info.len() != base_size {
        return Err(GitDeltaError::DeltaDecoderError(
            "base object len is not equal".to_owned(),
        ));
    }

    let result_size = utils::read_size_encoding(&mut stream).unwrap();
    let mut buffer = Vec::with_capacity(result_size);
    loop {
        // Check if the stream has ended, meaning the new object is done
        let instruction = match utils::read_bytes(stream) {
            Ok([instruction]) => instruction,
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => break,
            Err(err) => {
                panic!("{}", format!("Wrong instruction in delta :{err}"));
            }
        };

        if instruction & COPY_INSTRUCTION_FLAG == 0 {
            // Data instruction; the instruction byte specifies the number of data bytes
            if instruction == 0 {
                // Appending 0 bytes doesn't make sense, so git disallows it
                panic!(
                    "{}",
                    GitDeltaError::DeltaDecoderError(String::from("Invalid data instruction"))
                );
            }

            // Append the provided bytes
            let mut data = vec![0; instruction as usize];
            stream.read_exact(&mut data).unwrap();
            buffer.extend_from_slice(&data);
        // result.extend_from_slice(&data);
        } else {
            // Copy instruction
            let mut nonzero_bytes = instruction;
            let offset =
                utils::read_partial_int(&mut stream, COPY_OFFSET_BYTES, &mut nonzero_bytes)
                    .unwrap();
            let mut size =
                utils::read_partial_int(&mut stream, COPY_SIZE_BYTES, &mut nonzero_bytes).unwrap();
            if size == 0 {
                // Copying 0 bytes doesn't make sense, so git assumes a different size
                size = COPY_ZERO_SIZE;
            }
            let data = base_info.get(offset..(offset + size)).ok_or_else(|| {
                GitDeltaError::DeltaDecoderError("Invalid copy instruction".to_string())
            })?;
            buffer.extend_from_slice(data);
        }
    }
    assert!(buffer.len() == result_size);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::delta_decode;
    use crate::delta::{encode::DeltaDiff, errors::GitDeltaError};

    /// Delta encode + decode should round-trip to the new buffer.
    #[test]
    fn round_trip_matches_source() {
        let old = b"hello world";
        let new = b"hello rust";
        let delta = DeltaDiff::new(old, new).encode();

        let mut cursor = Cursor::new(delta);
        let decoded = delta_decode(&mut cursor, old).expect("decode");
        assert_eq!(decoded, new);
    }

    /// Mismatched base length should return a decoder error.
    #[test]
    fn base_size_mismatch_returns_error() {
        let old = b"abcde";
        let new = b"abXYZ";
        let delta = DeltaDiff::new(old, new).encode();

        let mut cursor = Cursor::new(delta);
        // Provide a base buffer with a different length to trigger size mismatch.
        let err = delta_decode(&mut cursor, b"xx").unwrap_err();
        assert!(matches!(err, GitDeltaError::DeltaDecoderError(_)));
    }
}
