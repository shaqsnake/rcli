use std::fmt::Debug;

use anyhow::Result;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

const SECRET: &str = "my_secret";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,

    #[serde(with = "jwt_numeric_time")]
    exp: OffsetDateTime,
}

impl Claims {
    pub fn new(iss: String, sub: String, aud: String, exp: OffsetDateTime) -> Self {
        Self { iss, sub, aud, exp }
    }
}

mod jwt_numeric_time {
    use serde::Deserialize;
    use time::OffsetDateTime;

    pub fn serialize<S>(time: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let timestamp = time.unix_timestamp();
        serializer.serialize_i64(timestamp)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        OffsetDateTime::from_unix_timestamp(i64::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Unix timestamp value"))
    }
}

pub fn process_jwt_sign(iss: &str, sub: &str, aud: &str, exp: OffsetDateTime) -> Result<String> {
    let claims = Claims::new(iss.into(), sub.into(), aud.into(), exp);
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET.as_ref()),
    )
    .expect("Failed to encode claims");

    Ok(token)
}

pub fn process_jwt_verify(token: &str) -> Result<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_aud = false;
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET.as_ref()),
        &validation,
    )?;

    let claims = serde_json::to_string(&token_data.claims)?;
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECT_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0X2lzcyIsInN1YiI6InRlc3Rfc3ViIiwiYXVkIjoidGVzdF9hdWQiLCJleHAiOjMyNTAzNjgwMDAwfQ.dmgSId3vVeREZIwrDuvc97dRoeos6nv2MaqgC0ZBqmo";

    #[test]
    fn test_jwt_sign() {
        let iss = "test_iss";
        let sub = "test_sub";
        let aud = "test_aud";
        let exp: OffsetDateTime = OffsetDateTime::from_unix_timestamp(32503680000).unwrap();
        let token = process_jwt_sign(iss, sub, aud, exp);
        assert!(token.is_ok());
        assert_eq!(&token.unwrap(), EXPECT_TOKEN);
    }

    #[test]
    fn test_jwt_verif() {
        let decoded = process_jwt_verify(EXPECT_TOKEN).expect("Failed to decode token");
        assert_eq!(
            decoded,
            "{\"iss\":\"test_iss\",\"sub\":\"test_sub\",\"aud\":\"test_aud\",\"exp\":32503680000}"
        );
    }
}
