//! Exact YEC amounts.
//!
//! The node prints amounts as fixed-point decimals with eight places (`ValueFromAmount`,
//! ycash-dd `src/rpc/server.cpp:131`) and parses them with `ParseFixedPoint(.., 8)`
//! (`AmountFromValue`, `src/rpc/server.cpp:119`), which accepts a JSON number **or a string**.
//! [`Amount`] holds integer zatoshi and never goes through `f64`: responses are read with
//! [`crate::json::from_str`], which keeps every decimal literal's text, and requests carry
//! amounts as decimal strings.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Zatoshi per YEC.
pub const COIN: i64 = 100_000_000;
/// The money range (`MAX_MONEY`, ycash-dd `src/amount.h`).
pub const MAX_MONEY: i64 = 21_000_000 * COIN;

/// An amount in zatoshi (1 YEC = 100,000,000 zatoshi), signed like the node's `CAmount`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(pub i64);

/// A YEC decimal that is not an exact zatoshi amount.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid YEC amount {text:?}: {why}")]
pub struct AmountError {
    pub text: String,
    pub why: &'static str,
}

impl Amount {
    pub const ZERO: Amount = Amount(0);

    pub const fn from_zat(zat: i64) -> Self {
        Amount(zat)
    }

    pub const fn zat(self) -> i64 {
        self.0
    }

    /// Whole YEC, checked.
    pub fn from_yec(yec: i64) -> Option<Self> {
        yec.checked_mul(COIN).map(Amount)
    }

    /// Within `0..=MAX_MONEY` (`MoneyRange`).
    pub fn in_money_range(self) -> bool {
        (0..=MAX_MONEY).contains(&self.0)
    }

    pub fn checked_add(self, o: Amount) -> Option<Amount> {
        self.0.checked_add(o.0).map(Amount)
    }

    pub fn checked_sub(self, o: Amount) -> Option<Amount> {
        self.0.checked_sub(o.0).map(Amount)
    }

    /// Parse a JSON-number-shaped decimal exactly (`-`? digits (`.` digits)? (`e` exponent)?).
    pub fn parse_decimal(text: &str) -> Result<Self, AmountError> {
        let err = |why| AmountError {
            text: text.to_owned(),
            why,
        };
        let s = text.trim();
        let (neg, s) = match s.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, s.strip_prefix('+').unwrap_or(s)),
        };
        let (mantissa, exp) = match s.find(['e', 'E']) {
            Some(i) => {
                let e: i32 = s[i + 1..].parse().map_err(|_| err("bad exponent"))?;
                (&s[..i], e)
            }
            None => (s, 0),
        };
        let (int_part, frac_part) = match mantissa.find('.') {
            Some(i) => (&mantissa[..i], &mantissa[i + 1..]),
            None => (mantissa, ""),
        };
        if int_part.is_empty() && frac_part.is_empty() {
            return Err(err("no digits"));
        }
        if !int_part.bytes().all(|b| b.is_ascii_digit())
            || !frac_part.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(err("not a decimal number"));
        }
        // value = digits * 10^(exp - frac_len); zatoshi = digits * 10^(exp - frac_len + 8)
        let digits = format!("{int_part}{frac_part}");
        let digits = digits.trim_start_matches('0');
        let mut scale: i64 = i64::from(exp) - frac_part.len() as i64 + 8;
        let mut digits = digits.to_owned();
        while scale < 0 {
            match digits.pop() {
                Some('0') => scale += 1,
                Some(_) => return Err(err("more than 8 decimal places")),
                None => {
                    scale = 0;
                    break;
                }
            }
        }
        if digits.is_empty() {
            return Ok(Amount(0));
        }
        if digits.len() as i64 + scale > 19 {
            return Err(err("out of range"));
        }
        let mut v: i128 = digits.parse().map_err(|_| err("out of range"))?;
        for _ in 0..scale {
            v *= 10;
        }
        if neg {
            v = -v;
        }
        i64::try_from(v)
            .map(Amount)
            .map_err(|_| err("out of range"))
    }
}

impl fmt::Display for Amount {
    /// `ValueFromAmount`'s format: `[-]<int>.<8 digits>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let neg = self.0 < 0;
        let abs = self.0.unsigned_abs();
        let coin = COIN as u64;
        write!(
            f,
            "{}{}.{:08}",
            if neg { "-" } else { "" },
            abs / coin,
            abs % coin
        )
    }
}

impl FromStr for Amount {
    type Err = AmountError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Amount::parse_decimal(s)
    }
}

impl From<Amount> for i64 {
    fn from(a: Amount) -> i64 {
        a.0
    }
}

impl Serialize for Amount {
    /// As the decimal string the node prints (`AmountFromValue` accepts strings).
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Amount;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a YEC amount as a decimal string or an integer (read through hawkeye_ycash::json)")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Amount, E> {
                Amount::parse_decimal(v).map_err(E::custom)
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Amount, E> {
                Amount::from_yec(v).ok_or_else(|| E::custom("amount out of range"))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Amount, E> {
                i64::try_from(v)
                    .ok()
                    .and_then(Amount::from_yec)
                    .ok_or_else(|| E::custom("amount out of range"))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Amount, E> {
                Err(E::custom(
                    "a YEC amount arrived as a binary float; parse responses with hawkeye_ycash::json::from_str",
                ))
            }
        }
        d.deserialize_any(V)
    }
}

/// `Option<Amount>` helpers are plain serde; this module reads `f64` fields (difficulty,
/// verification progress) that [`crate::json`] turned into strings.
pub mod lenient_f64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_f64(*v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum N {
            F(f64),
            S(String),
        }
        match N::deserialize(d)? {
            N::F(f) => Ok(f),
            N::S(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exactly() {
        let cases = [
            ("0", 0),
            ("1", COIN),
            ("1.00000000", COIN),
            ("0.00000001", 1),
            ("20999999.99999999", 2_099_999_999_999_999),
            ("21000000.00000000", MAX_MONEY),
            ("-0.00010000", -10_000),
            ("0.1", 10_000_000),
            ("1e-8", 1),
            ("1.5E2", 15_000_000_000),
            ("123.4500000000", 12_345_000_000),
            (".5", 50_000_000),
            ("5.", 500_000_000),
            ("0.30000000", 30_000_000), // 0.3 is not a binary fraction: exactness matters
        ];
        for (t, z) in cases {
            assert_eq!(Amount::parse_decimal(t).unwrap(), Amount(z), "{t}");
        }
        for bad in [
            "",
            "-",
            ".",
            "1.000000001",
            "1e-9",
            "abc",
            "1.2.3",
            "99999999999999999999",
            "1e30",
            "0x10",
        ] {
            assert!(Amount::parse_decimal(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn displays_like_value_from_amount() {
        assert_eq!(Amount(0).to_string(), "0.00000000");
        assert_eq!(Amount(1).to_string(), "0.00000001");
        assert_eq!(Amount(-10_000).to_string(), "-0.00010000");
        assert_eq!(Amount(MAX_MONEY).to_string(), "21000000.00000000");
        assert_eq!(Amount(i64::MIN).to_string(), "-92233720368.54775808");
        for z in [0, 1, 7, 99_999_999, 100_000_001, MAX_MONEY, -5] {
            assert_eq!(Amount(z).to_string().parse::<Amount>().unwrap(), Amount(z));
        }
    }

    #[test]
    fn serde() {
        assert_eq!(
            serde_json::to_string(&Amount(150_000_000)).unwrap(),
            "\"1.50000000\""
        );
        let a: Amount = serde_json::from_str("\"0.30000000\"").unwrap();
        assert_eq!(a, Amount(30_000_000));
        let a: Amount = serde_json::from_str("3").unwrap();
        assert_eq!(a, Amount(300_000_000));
        assert!(
            serde_json::from_str::<Amount>("0.3").is_err(),
            "floats are refused"
        );
    }
}
