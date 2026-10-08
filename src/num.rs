//! Big-endian integer trait for fixed-width primitives.
//!
//! [`Integer`] is implemented for all standard integer and float types and is
//! a convenience for users writing custom packet field codecs that need
//! generic big-endian byte conversion.

/// A type that can be serialized to and from a fixed-length big-endian byte sequence.
pub trait Integer: Sized + Copy {
    /// Serialize to big-endian bytes.
    fn to_bytes(self) -> Vec<u8>;

    /// Deserialize from big-endian bytes.
    ///
    /// # Panics
    ///
    /// Panics if `bytes.len()` is not exactly [`byte_len`](Integer::byte_len).
    fn from_bytes(bytes: &[u8]) -> Self;

    /// The byte length of the serialized form.
    fn byte_len() -> usize;
}

macro_rules! impl_integer {
    ($t:ty) => {
        impl Integer for $t {
            #[inline]
            fn to_bytes(self) -> Vec<u8> {
                self.to_be_bytes().to_vec()
            }

            #[inline]
            fn from_bytes(bytes: &[u8]) -> Self {
                let arr: [u8; std::mem::size_of::<$t>()] =
                    bytes.try_into().expect("byte slice has wrong length");
                <$t>::from_be_bytes(arr)
            }

            #[inline]
            fn byte_len() -> usize {
                std::mem::size_of::<$t>()
            }
        }
    };
}

impl_integer!(i8);
impl_integer!(i16);
impl_integer!(i32);
impl_integer!(i64);
impl_integer!(i128);
impl_integer!(u8);
impl_integer!(u16);
impl_integer!(u32);
impl_integer!(u64);
impl_integer!(u128);
impl_integer!(f32);
impl_integer!(f64);
