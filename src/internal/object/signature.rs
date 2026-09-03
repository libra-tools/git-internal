//! In a Git commit, the author signature contains the name, email address, timestamp, and timezone
//! of the person who authored the commit. This information is stored in a specific format, which
//! consists of the following fields:
//!
//! - Name: The name of the author, encoded as a UTF-8 string.
//! - Email: The email address of the author, encoded as a UTF-8 string.
//! - Timestamp: The timestamp of when the commit was authored, encoded as a decimal number of seconds
//!   since the Unix epoch (January 1, 1970, 00:00:00 UTC).
//! - Timezone: The timezone offset of the author's local time from Coordinated Universal Time (UTC),
//!   encoded as a string in the format "+HHMM" or "-HHMM".
//!
use std::{fmt::Display, str::FromStr};

use bstr::ByteSlice;
use chrono::Offset;

use crate::errors::GitError;

/// In addition to the author signature, Git also includes a "committer" signature, which indicates
/// who committed the changes to the repository. The committer signature is similar in structure to
/// the author signature, but includes the name, email address, and timestamp of the committer instead.
/// This can be useful in situations where multiple people are working on a project and changes are
/// being reviewed and merged by someone other than the original author.
///
/// In the following example, it's has the only one who authored and committed.
/// ```bash
/// author Eli Ma <eli@patch.sh> 1678102132 +0800
/// committer Quanyi Ma <eli@patch.sh> 1678102132 +0800
/// ```
///
/// So, we design a `SignatureType` enum to indicate the signature type.
#[derive(
    PartialEq,
    Eq,
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum SignatureType {
    Author,
    Committer,
    Tagger,
}

impl Display for SignatureType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SignatureType::Author => write!(f, "author"),
            SignatureType::Committer => write!(f, "committer"),
            SignatureType::Tagger => write!(f, "tagger"),
        }
    }
}
impl FromStr for SignatureType {
    type Err = GitError;
    /// The `from_str` method is used to convert a string to a `SignatureType` enum.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "author" => Ok(SignatureType::Author),
            "committer" => Ok(SignatureType::Committer),
            "tagger" => Ok(SignatureType::Tagger),
            _ => Err(GitError::InvalidSignatureType(s.to_string())),
        }
    }
}
impl SignatureType {
    /// The `from_data` method is used to convert a `Vec<u8>` to a `SignatureType` enum.
    pub fn from_data(data: Vec<u8>) -> Result<Self, GitError> {
        let s = String::from_utf8(data.to_vec())
            .map_err(|e| GitError::ConversionError(e.to_string()))?;
        SignatureType::from_str(s.as_str())
    }

    /// The `to_bytes` method is used to convert a `SignatureType` enum to a `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SignatureType::Author => "author".to_string().into_bytes(),
            SignatureType::Committer => "committer".to_string().into_bytes(),
            SignatureType::Tagger => "tagger".to_string().into_bytes(),
        }
    }
}

/// Represents a Git signature, including the author's name, email, timestamp, and timezone.
#[derive(
    PartialEq,
    Eq,
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct Signature {
    pub signature_type: SignatureType,
    pub name: String,
    pub email: String,
    pub timestamp: usize,
    pub timezone: String,
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "{} <{}>", self.name, self.email).unwrap();
        // format the timestamp to a human-readable date format
        let date =
            chrono::DateTime::<chrono::Utc>::from_timestamp(self.timestamp as i64, 0).unwrap();
        writeln!(f, "Date: {} {}", date, self.timezone)
    }
}

/// Format a UTC offset in seconds as Git's canonical `[+-]HHMM` timezone.
///
/// The sign is applied once to the whole offset, so negative half-hour zones
/// render as `-0230` (never `-02-30`), matching what
/// [`Signature::from_data`] accepts.
pub fn format_timezone(offset_seconds: i32) -> String {
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let total_minutes = offset_seconds.unsigned_abs() / 60;
    format!("{sign}{:02}{:02}", total_minutes / 60, total_minutes % 60)
}

impl Signature {
    /// The `from_data` method is used to convert a `Vec<u8>` to a `Signature` struct.
    ///
    /// Parses `<role> <name> <<email>> <timestamp> <tz>`. Every structural
    /// problem (missing role/`<`/`>`/space separators, non-UTF-8 text, a
    /// non-numeric timestamp, a timezone that is not `[+-]HHMM`) fails closed
    /// with [`GitError::InvalidSignatureType`] instead of panicking, so callers
    /// such as `Commit::from_bytes` can reject a malformed object body. An
    /// empty name (`author <mail> 1 +0000`) is accepted, as in Git.
    pub fn from_data(data: Vec<u8>) -> Result<Signature, GitError> {
        let sign = data;
        let malformed = |what: &str| {
            GitError::InvalidSignatureType(format!(
                "malformed signature line ({what}): {:?}",
                String::from_utf8_lossy(&sign)
            ))
        };
        let utf8 = |bytes: &[u8], what: &str| -> Result<String, GitError> {
            std::str::from_utf8(bytes)
                .map(str::to_string)
                .map_err(|_| malformed(what))
        };

        // `<role>` up to the first space.
        let name_start = sign
            .find_byte(0x20)
            .ok_or_else(|| malformed("missing role separator"))?;
        let role = utf8(&sign[..name_start], "role")?;
        let signature_type = SignatureType::from_str(&role)?;

        // `<name> <<email>>`: `<` must follow the role separator; the name is the text
        // between them minus its single trailing space (it may be empty).
        let email_start = sign
            .find_byte(0x3C)
            .filter(|&i| i > name_start)
            .ok_or_else(|| malformed("missing '<' before email"))?;
        let email_end = sign
            .find_byte(0x3E)
            .filter(|&i| i > email_start)
            .ok_or_else(|| malformed("missing '>' after email"))?;
        // A non-empty name must be followed by exactly one space before `<`.
        let name_bytes = &sign[name_start + 1..email_start];
        let name_bytes = match name_bytes.strip_suffix(b" ") {
            Some(stripped) => stripped,
            None if name_bytes.is_empty() => name_bytes,
            None => return Err(malformed("missing space before '<'")),
        };
        let name = utf8(name_bytes, "name")?;
        let email = utf8(&sign[email_start + 1..email_end], "email")?;

        // `> <timestamp> <tz>`: exactly one space after `>`, a decimal timestamp and a
        // non-empty timezone.
        if sign.get(email_end + 1) != Some(&0x20) {
            return Err(malformed("missing space after email"));
        }
        let rest = &sign[email_end + 2..];
        let timestamp_split = rest
            .find_byte(0x20)
            .ok_or_else(|| malformed("missing timezone separator"))?;
        let timestamp = utf8(&rest[..timestamp_split], "timestamp")?
            .parse::<usize>()
            .map_err(|_| malformed("non-numeric timestamp"))?;
        // Timezone must be Git's canonical `[+-]HHMM` (what `git fsck` calls a
        // well-formed timezone); anything else is rejected.
        let timezone = utf8(&rest[timestamp_split + 1..], "timezone")?;
        let tz = timezone.as_bytes();
        let tz_ok = tz.len() == 5
            && (tz[0] == b'+' || tz[0] == b'-')
            && tz[1..].iter().all(u8::is_ascii_digit);
        if !tz_ok {
            return Err(malformed("timezone is not [+-]HHMM"));
        }

        // Return a Result object indicating success
        Ok(Signature {
            signature_type,
            name,
            email,
            timestamp,
            timezone,
        })
    }

    /// The `to_data` method is used to convert a `Signature` struct to a `Vec<u8>`.
    pub fn to_data(&self) -> Result<Vec<u8>, GitError> {
        // Create a new empty vector to store the encoded data.
        let mut sign = Vec::new();

        // Append the author name bytes to the data vector, followed by a space byte.
        sign.extend_from_slice(&self.signature_type.to_bytes());
        sign.extend_from_slice(&[0x20]);

        // Append the name bytes to the data vector, followed by a space byte.
        sign.extend_from_slice(self.name.as_bytes());
        sign.extend_from_slice(&[0x20]);

        // Append the email address bytes to the data vector, enclosed in angle brackets.
        sign.extend_from_slice(format!("<{}>", self.email).as_bytes());
        sign.extend_from_slice(&[0x20]);

        // Append the timestamp integer bytes to the data vector, followed by a space byte.
        sign.extend_from_slice(self.timestamp.to_string().as_bytes());
        sign.extend_from_slice(&[0x20]);

        // Append the timezone string bytes to the data vector.
        sign.extend_from_slice(self.timezone.as_bytes());

        // Return the data vector as a Result object indicating success.
        Ok(sign)
    }

    /// Represents a signature with author, email, timestamp, and timezone information.
    pub fn new(sign_type: SignatureType, author: String, email: String) -> Signature {
        // Get the current local time (with timezone)
        let local_time = chrono::Local::now();

        // Get the offset from UTC in minutes (local time - UTC time)
        let offset = local_time.offset().fix().local_minus_utc();

        // Format the offset as Git's canonical `[+-]HHMM` (e.g., "+0800", "-0230").
        let offset_str = format_timezone(offset);

        // Return the Signature struct with the provided information
        Signature {
            signature_type: sign_type, // The type of signature (e.g., commit, merge)
            name: author,              // The author's name
            email,                     // The author's email
            timestamp: chrono::Utc::now().timestamp() as usize, // The timestamp of the signature (seconds since Unix epoch)
            timezone: offset_str, // The timezone offset (e.g., "+0800")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use chrono::DateTime;

    use crate::internal::object::signature::{Signature, SignatureType};

    /// Test conversion from string to SignatureType enum.
    #[test]
    fn test_signature_type_from_str() {
        assert_eq!(
            SignatureType::from_str("author").unwrap(),
            SignatureType::Author
        );

        assert_eq!(
            SignatureType::from_str("committer").unwrap(),
            SignatureType::Committer
        );
    }

    /// Test conversion from SignatureType enum to string.
    #[test]
    fn test_signature_type_from_data() {
        assert_eq!(
            SignatureType::from_data("author".to_string().into_bytes()).unwrap(),
            SignatureType::Author
        );

        assert_eq!(
            SignatureType::from_data("committer".to_string().into_bytes()).unwrap(),
            SignatureType::Committer
        );
    }

    /// Test conversion from SignatureType enum to bytes.
    #[test]
    fn test_signature_type_to_bytes() {
        assert_eq!(
            SignatureType::Author.to_bytes(),
            "author".to_string().into_bytes()
        );

        assert_eq!(
            SignatureType::Committer.to_bytes(),
            "committer".to_string().into_bytes()
        );
    }

    /// Test conversion from data bytes to Signature struct.
    #[test]
    fn test_signature_new_from_data() {
        let sign = Signature::from_data(
            "author Quanyi Ma <eli@patch.sh> 1678101573 +0800"
                .to_string()
                .into_bytes(),
        )
        .unwrap();

        assert_eq!(sign.signature_type, SignatureType::Author);
        assert_eq!(sign.name, "Quanyi Ma");
        assert_eq!(sign.email, "eli@patch.sh");
        assert_eq!(sign.timestamp, 1678101573);
        assert_eq!(sign.timezone, "+0800");
    }

    /// Test conversion from Signature struct to data bytes.
    #[test]
    fn test_signature_to_data() {
        let sign = Signature::from_data(
            "committer Quanyi Ma <eli@patch.sh> 1678101573 +0800"
                .to_string()
                .into_bytes(),
        )
        .unwrap();

        let dest = sign.to_data().unwrap();

        assert_eq!(
            dest,
            "committer Quanyi Ma <eli@patch.sh> 1678101573 +0800"
                .to_string()
                .into_bytes()
        );
    }

    /// When the test case run in the GitHub Action, the timezone is +0000, so we ignore it.
    #[test]
    fn test_signature_with_time() {
        let sign = Signature::new(
            SignatureType::Author,
            "MEGA".to_owned(),
            "admin@mega.com".to_owned(),
        );
        assert_eq!(sign.signature_type, SignatureType::Author);
        assert_eq!(sign.name, "MEGA");
        assert_eq!(sign.email, "admin@mega.com");
        // assert_eq!(sign.timezone, "+0800");//it depends on the local timezone

        let naive_datetime = DateTime::from_timestamp(sign.timestamp as i64, 0).unwrap();
        println!("Formatted DateTime: {}", naive_datetime.naive_local());
    }

    /// `format_timezone` always yields canonical `[+-]HHMM`, including negative half-hour zones.
    #[test]
    fn signature_format_timezone_is_canonical() {
        use crate::internal::object::signature::format_timezone;
        assert_eq!(format_timezone(0), "+0000");
        assert_eq!(format_timezone(8 * 3600), "+0800");
        assert_eq!(format_timezone(5 * 3600 + 30 * 60), "+0530");
        assert_eq!(format_timezone(-(2 * 3600 + 30 * 60)), "-0230");
        assert_eq!(format_timezone(-3600), "-0100");
        assert_eq!(format_timezone(-(9 * 3600 + 30 * 60)), "-0930");
        assert_eq!(format_timezone(12 * 3600 + 45 * 60), "+1245");
    }

    /// `Signature::new` output must always be accepted by the strict `from_data` parser.
    #[test]
    fn signature_new_round_trips_through_from_data() {
        for role in [
            SignatureType::Author,
            SignatureType::Committer,
            SignatureType::Tagger,
        ] {
            let sig = Signature::new(role, "n m".to_string(), "e@x".to_string());
            let parsed = Signature::from_data(sig.to_data().unwrap()).unwrap();
            assert_eq!(parsed.to_data().unwrap(), sig.to_data().unwrap());
            assert_eq!(parsed.timezone.len(), 5);
        }
        // Non-UTF-8 role is reported as InvalidSignatureType.
        let mut bad = vec![0xffu8, 0xfe, b' '];
        bad.extend(b"n <e> 1 +0000");
        assert!(matches!(
            Signature::from_data(bad),
            Err(crate::errors::GitError::InvalidSignatureType(_))
        ));
    }
}
