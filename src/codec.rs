// SPDX-License-Identifier: MPL-2.0

//! Module `codec` provides support for encoding and decoding messages to or from the wire encoding
//! of VDAF messages in TLS syntax, as specified in
//! [RFC 8446, Section 3](https://datatracker.ietf.org/doc/html/rfc8446#section-3). We provide
//! traits that can be implemented on values that need to be encoded or decoded, as well as utility
//! functions for encoding sequences of values.
//!
//! TLS syntax supports
//! [variable length vectors](https://datatracker.ietf.org/doc/html/rfc8446#section-3.4) of objects.
//! The wire encoding is to write the number of objects in the vector and then the concatenated
//! objects. TLS also defines an [`opaque`](https://datatracker.ietf.org/doc/html/rfc8446#section-3.2)
//! type for opaque bytes. The `encode_items_*` and `decode_items_*` functions encode or decode a
//! sequence of values of types which implement [`Encode`] or [`Decode`], where the the length
//! marker is the number of *items*. The `encode_items_opaque_*` and `decode_items_opaque_*`
//! functions encode or decode a sequence of values which implement [`Encode`] or [`Decode`] as
//! opaque vectors, so the length marker is the number of *bytes* occupied by the encoded
//! representation of the concatenated values. Finally, the `encode_opaque_*` and `decode_opaque_*`
//! functions allow encoding and decoding sequences of [`u8`] as opaque vectors.
//!
//! It is very tempting to try to express the {encode,decode}_items_opaque_*,
//! {encode,decode}_opaque_*, {encode,decode}_items_* and corresponding decode_* functions
//! generically over the type of the length prefix. Unfortunately, const generics and const
//! expressions are not mature enough to do this gracefully, and since we only have to provide a
//! small number of specializations for u8, u16 and maybe u24, we do it by hand.

use std::{
    convert::TryInto,
    io::{Cursor, Read},
    mem::size_of,
};

/// Describes how to decode an object from a byte sequence.
pub trait Decode<D>: Sized {
    /// Type of errors returned by the [`decode`] method.
    type Error;

    /// Read and decode an encoded object from `bytes`. `decoding_parameter` provides details of the
    /// wire encoding such as lengths of different portions of the message.
    fn decode(decoding_parameter: &D, bytes: &mut Cursor<&[u8]>) -> Result<Self, Self::Error>;

    /// Convenience method to get decoded value.
    fn get_decoded(decoding_parameter: &D, bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(bytes);
        Self::decode(decoding_parameter, &mut cursor)
    }
}

/// Describes how to encode objects into a byte sequence.
pub trait Encode {
    /// Append the encoded form of this object to the end of `bytes`, growing the vector as needed.
    fn encode(&self, bytes: &mut Vec<u8>);

    /// Convenience method to get encoded value.
    fn get_encoded(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        self.encode(&mut ret);
        ret
    }
}

impl Decode<()> for u8 {
    type Error = std::io::Error;

    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, Self::Error> {
        let mut value = [0u8; size_of::<u8>()];
        bytes.read_exact(&mut value)?;
        Ok(value[0])
    }
}

impl Encode for u8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.push(*self);
    }
}

impl Decode<()> for u16 {
    type Error = std::io::Error;

    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, Self::Error> {
        let mut value = [0u8; size_of::<u16>()];
        bytes.read_exact(&mut value)?;
        Ok(u16::from_be_bytes(value))
    }
}

impl Encode for u16 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&u16::to_be_bytes(*self));
    }
}

impl Decode<()> for u64 {
    type Error = std::io::Error;

    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, Self::Error> {
        let mut value = [0u8; size_of::<u64>()];
        bytes.read_exact(&mut value)?;
        Ok(u64::from_be_bytes(value))
    }
}

impl Encode for u64 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&u64::to_be_bytes(*self));
    }
}

/// Encode `items` into `bytes` as a variable-length opaque vector with a
/// maximum length of `0xff`
pub fn encode_items_opaque_u8<E: Encode>(bytes: &mut Vec<u8>, items: &[E]) {
    let len_offset = bytes.len();
    bytes.push(0);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 1;
    debug_assert!(len <= 0xff);
    bytes[len_offset] = len as u8;
}

/// Decode `bytes` into a vector of `D` values, treating `bytes` as an opaque
/// byte string of maximum length `0xff`.
pub fn decode_items_opaque_u8<P, E: From<std::io::Error>, D: Decode<P, Error = E>>(
    decoding_parameter: &P,
    bytes: &mut Cursor<&[u8]>,
) -> Result<Vec<D>, D::Error> {
    // Read one byte to get length of opaque byte vector
    let length = usize::from(u8::decode(&(), bytes)?);

    decode_items_opaque(length, decoding_parameter, bytes)
}

/// Encode `items` into `bytes` as a variable-length opaque vector with a
/// maximum length of `0xffff`
pub fn encode_items_opaque_u16<E: Encode>(bytes: &mut Vec<u8>, items: &[E]) {
    let len_offset = bytes.len();
    bytes.extend(&[0, 0]);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 2;
    debug_assert!(len <= 0xffff);
    let out: &mut [u8; 2] = (&mut bytes[len_offset..len_offset + 2]).try_into().unwrap();
    *out = u16::to_be_bytes(len as u16);
}

/// Decode `bytes` into a vector of `D` values, treating `bytes` as an opaque
/// byte string of maximum length `0xffff`.
pub fn decode_items_opaque_u16<P, E: From<std::io::Error>, D: Decode<P, Error = E>>(
    decoding_parameter: &P,
    bytes: &mut Cursor<&[u8]>,
) -> Result<Vec<D>, D::Error> {
    // Read two bytes to get length of opaque byte vector
    let length = usize::from(u16::decode(&(), bytes)?);

    decode_items_opaque(length, decoding_parameter, bytes)
}

/// Decode the next `length` bytes from `bytes` into as many instances of `D` as
/// possible.
fn decode_items_opaque<P, E: From<std::io::Error>, D: Decode<P, Error = E>>(
    length: usize,
    decoding_parameter: &P,
    bytes: &mut Cursor<&[u8]>,
) -> Result<Vec<D>, D::Error> {
    let mut decoded = Vec::new();
    let initial_position = bytes.position() as usize;

    // Create cursor over specified portion of provided cursor to ensure we
    // can't read past len
    let mut sub = Cursor::new(&bytes.get_ref()[initial_position..initial_position + length]);

    while sub.position() < length as u64 {
        decoded.push(D::decode(decoding_parameter, &mut sub)?);
    }

    // Advance outer cursor by the amount read in the inner cursor
    bytes.set_position(initial_position as u64 + sub.position());

    Ok(decoded)
}

/// Encode the `items` into `bytes` as a vector of `items.len()` items, up to
/// `0xff`.
pub fn encode_items_u8<E: Encode>(bytes: &mut Vec<u8>, items: &[E]) {
    assert!(items.len() <= 0xff);
    bytes.push(items.len().try_into().unwrap());

    for i in items {
        i.encode(bytes);
    }
}

/// Decode `bytes` into a vector of `D` values, treating `bytes` as a vector of
/// encoded `D`s of maximum length `0xff`.
pub fn decode_items_u8<P, E: From<std::io::Error>, D: Decode<P, Error = E>>(
    decoding_parameter: &P,
    bytes: &mut Cursor<&[u8]>,
) -> Result<Vec<D>, D::Error> {
    let elements = usize::from(u8::decode(&(), bytes)?);
    decode_items(elements, decoding_parameter, bytes)
}

/// Encode the `items` into `bytes` as a vector of `items.len()` items, up to
/// `0xffff`.
pub fn encode_items_u16<E: Encode>(bytes: &mut Vec<u8>, items: &[E]) {
    assert!(items.len() <= 0xffff);
    bytes.extend_from_slice(&u16::to_be_bytes(items.len().try_into().unwrap()));

    for i in items {
        i.encode(bytes);
    }
}

/// Decode `bytes` into a vector of `D` values, treating `bytes` as a vector of
/// encoded `D`s of maximum length `0xffff`.
pub fn decode_items_u16<P, E: From<std::io::Error>, D: Decode<P, Error = E>>(
    decoding_parameter: &P,
    bytes: &mut Cursor<&[u8]>,
) -> Result<Vec<D>, D::Error> {
    let elements = usize::from(u16::decode(&(), bytes)?);
    decode_items(elements, decoding_parameter, bytes)
}

/// Decode `elements` instances of `D` from `bytes`.
fn decode_items<P, E: From<std::io::Error>, D: Decode<P, Error = E>>(
    elements: usize,
    decoding_parameter: &P,
    bytes: &mut Cursor<&[u8]>,
) -> Result<Vec<D>, D::Error> {
    let mut decoded = Vec::new();

    while decoded.len() < elements {
        decoded.push(D::decode(decoding_parameter, bytes)?);
    }

    Ok(decoded)
}

/// Encode `opaque` into `bytes` as a variable-length vector of `opaque.len()` opaque bytes, up to
/// `0xff`.
pub fn encode_opaque_u8(bytes: &mut Vec<u8>, opaque: &[u8]) {
    assert!(opaque.len() <= 0xff);
    bytes.push(opaque.len() as u8);
    bytes.extend_from_slice(opaque);
}

/// Decode `bytes` into a vector of bytes, treating `bytes` as a variable-length vector of up to
/// `0xff` bytes.
pub fn decode_opaque_u8(bytes: &mut Cursor<&[u8]>) -> Result<Vec<u8>, <u8 as Decode<()>>::Error> {
    let length = usize::from(u8::decode(&(), bytes)?);
    let mut ret = vec![0u8; length];
    bytes.read_exact(&mut ret)?;

    Ok(ret)
}

/// Encode `opaque` into `bytes` as a variable-length vector of `opaque.len()` opaque bytes, up to
/// `0xffff`.
pub fn encode_opaque_u16(bytes: &mut Vec<u8>, opaque: &[u8]) {
    assert!(opaque.len() <= 0xffff);
    bytes.extend_from_slice(&u16::to_be_bytes(opaque.len().try_into().unwrap()));
    bytes.extend_from_slice(opaque);
}

/// Decode `bytes` into a vector of bytes, treating `bytes` as a variable-length vector of up to
/// `0xffff` bytes.
pub fn decode_opaque_u16(bytes: &mut Cursor<&[u8]>) -> Result<Vec<u8>, <u8 as Decode<()>>::Error> {
    let length = usize::from(u16::decode(&(), bytes)?);
    let mut ret = vec![0u8; length];
    bytes.read_exact(&mut ret)?;

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u8() {
        let value = 100u8;

        let mut bytes = vec![];
        value.encode(&mut bytes);
        assert_eq!(bytes.len(), 1);

        let decoded = u8::decode(&(), &mut Cursor::new(&bytes)).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn roundtrip_u16() {
        let value = 1000u16;

        let mut bytes = vec![];
        value.encode(&mut bytes);
        assert_eq!(bytes.len(), 2);

        let decoded = u16::decode(&(), &mut Cursor::new(&bytes)).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn roundtrip_u64() {
        let value = 1_000_000u64;

        let mut bytes = vec![];
        value.encode(&mut bytes);
        assert_eq!(bytes.len(), 8);

        let decoded = u64::decode(&(), &mut Cursor::new(&bytes)).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn roundtrip_variable_len_opaque_u8() {
        let value = vec![1, 2, 3, 4, 5];

        let mut bytes = vec![];
        encode_opaque_u8(&mut bytes, &value);
        // Encoding should be one length byte + 5 content bytes
        assert_eq!(bytes.len(), 6);

        let decoded = decode_opaque_u8(&mut Cursor::new(&bytes)).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn roundtrip_variable_len_opaque_u16() {
        let value = vec![1, 2, 3, 4, 5];

        let mut bytes = vec![];
        encode_opaque_u16(&mut bytes, &value);
        // Encoding should be two length bytes + 5 content bytes
        assert_eq!(bytes.len(), 7);

        let decoded = decode_opaque_u16(&mut Cursor::new(&bytes)).unwrap();
        assert_eq!(value, decoded);
    }

    #[derive(Debug, Eq, PartialEq)]
    struct TestMessage {
        field_u8: u8,
        field_u16: u16,
        field_u64: u64,
        variable_len_opaque: Vec<u8>,
    }

    impl Encode for TestMessage {
        fn encode(&self, bytes: &mut Vec<u8>) {
            self.field_u8.encode(bytes);
            self.field_u16.encode(bytes);
            self.field_u64.encode(bytes);
            encode_opaque_u8(bytes, &self.variable_len_opaque);
        }
    }

    impl Decode<()> for TestMessage {
        type Error = std::io::Error;

        fn decode(
            _decoding_parameter: &(),
            bytes: &mut Cursor<&[u8]>,
        ) -> Result<Self, Self::Error> {
            let field_u8 = u8::decode(&(), bytes)?;
            let field_u16 = u16::decode(&(), bytes)?;
            let field_u64 = u64::decode(&(), bytes)?;
            let variable_len_opaque = decode_opaque_u8(bytes)?;

            Ok(TestMessage {
                field_u8,
                field_u16,
                field_u64,
                variable_len_opaque,
            })
        }
    }

    #[test]
    fn roundtrip_message() {
        let value = TestMessage {
            field_u8: 0,
            field_u16: 300,
            field_u64: 1_000_000,
            variable_len_opaque: vec![1, 2, 3, 4, 5],
        };

        let mut bytes = vec![];
        value.encode(&mut bytes);
        assert_eq!(
            bytes.len(),
            // u8 field
            1 +
            // u16 field
            2 +
            // u64 field
            8 +
            // 1 length byte + 5 content bytes
            6
        );

        let decoded = TestMessage::decode(&(), &mut Cursor::new(&bytes)).unwrap();
        assert_eq!(value, decoded);
    }

    fn messages_vec() -> Vec<TestMessage> {
        vec![
            TestMessage {
                field_u8: 0,
                field_u16: 300,
                field_u64: 1_000_000,
                variable_len_opaque: vec![1, 2, 3, 4, 5],
            },
            TestMessage {
                field_u8: 0,
                field_u16: 300,
                field_u64: 1_000_000,
                variable_len_opaque: vec![1, 2, 3, 4, 5],
            },
            TestMessage {
                field_u8: 0,
                field_u16: 300,
                field_u64: 1_000_000,
                variable_len_opaque: vec![1, 2, 3, 4, 5],
            },
        ]
    }

    #[test]
    fn roundtrip_message_vec_opaque() {
        let values = messages_vec();
        let mut bytes = vec![];
        encode_items_opaque_u8(&mut bytes, &values);

        assert_eq!(
            bytes.len(),
            // Length of opaque vector
            1 +
            // 3 TestMessage values
            3 *
            // Length of fields of each TestMessage
            (1 + 2 + 8 + 6)
        );

        let decoded = decode_items_opaque_u8(&(), &mut Cursor::new(&bytes)).unwrap();
        assert_eq!(values, decoded);
    }

    #[test]
    fn roundtrip_message_vec_typed() {
        let values = messages_vec();
        let mut bytes = vec![];
        encode_items_u8(&mut bytes, &values);
        assert_eq!(
            bytes.len(),
            // Length of vector of TestMessages
            1 +
            // 3 TestMessage values
            3 *
            // Length of fields of each TestMessage
            (1 + 2 + 8 + 6)
        );

        let decoded = decode_items_u8(&(), &mut Cursor::new(&bytes)).unwrap();
        assert_eq!(values, decoded);
    }
}
