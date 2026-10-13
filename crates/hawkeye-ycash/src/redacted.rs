//! [`Redacted`]: a secret whose `Debug` never prints it (audit 05/I-1).
//!
//! Config and auth types derive `Debug` (for `anyhow` contexts and tests); a field holding a
//! secret — the member key's hex, an RPC password — is wrapped so a `debug!(?settings)` or a
//! formatted error can never write it into the log stream. Read the value with
//! [`Redacted::expose`] (or through `Deref`) where it is used.

use core::fmt;
use core::ops::Deref;

use serde::{Deserialize, Deserializer};

/// A value whose `Debug` prints `<redacted>`. Deserializes transparently.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wrap a secret.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// The secret itself.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Unwrap the secret.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T> Deref for Redacted<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Redacted<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        T::deserialize(d).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::Redacted;

    #[test]
    fn debug_never_prints_the_secret() {
        let r = Redacted::new("hunter2".to_owned());
        assert_eq!(format!("{r:?}"), "<redacted>");
        assert_eq!(format!("{:?}", Some(r.clone())), "Some(<redacted>)");
        assert_eq!(r.expose(), "hunter2");
        assert_eq!(r.len(), 7, "Deref to the secret");
        let d: Redacted<String> = serde_json::from_str("\"s3cret\"").unwrap();
        assert_eq!(d.into_inner(), "s3cret");
    }
}
