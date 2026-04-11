use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use color_eyre::eyre::{eyre, Context, Result};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct HashedPassword {
    pub password: String,
}

impl HashedPassword {
    pub async fn parse_str(input: &str) -> Result<HashedPassword> {
        Self::parse(input.to_owned()).await
    }

    pub async fn parse(input: String) -> Result<HashedPassword> {
        if input.len() >= 8 {
            if let Ok(password_hash) = compute_password_hash(input.as_ref()).await {
                Ok(HashedPassword {
                    password: password_hash,
                })
            } else {
                Err(eyre!("Failed to hash password"))
            }
        } else {
            Err(eyre!("Failed to parse string to a HashedPassword type"))
        }
    }

    pub fn parse_password_hash(hash: String) -> Result<HashedPassword> {
        if let Ok(hashed_string) = PasswordHash::new(hash.as_ref()) {
            Ok(HashedPassword {
                password: hashed_string.to_string(),
            })
        } else {
            Err(eyre!("Failed to parse string to a HashedPassword type"))
        }
    }

    #[tracing::instrument(name = "Verify raw password", skip_all)]
    pub async fn verify_raw_password(&self, password_candidate: &str) -> Result<()> {
        let current_span: tracing::Span = tracing::Span::current();
        let password_hash = self.as_ref().to_string();
        let password_candidate = password_candidate.to_string();
        let result = tokio::task::spawn_blocking(move || {
            current_span.in_scope(|| {
                let expected_password_hash: PasswordHash<'_> = PasswordHash::new(&password_hash)?;

                Argon2::default()
                    .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                    .wrap_err("failed to verify password hash")
            })
        })
        .await;
        result?
    }
}

impl AsRef<str> for HashedPassword {
    fn as_ref(&self) -> &str {
        &self.password
    }
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
pub async fn compute_password_hash(password: &str) -> Result<String> {
    let current_span: tracing::Span = tracing::Span::current();
    let password = password.to_string();
    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt: SaltString = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15_000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

            Ok(password_hash)
        })
    })
    .await?;

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Algorithm, Argon2, Params, PasswordHasher, Version,
    };
    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use quickcheck::Gen;
    use rand::SeedableRng;

    #[tokio::test]
    async fn should_reject_short_passwords() {
        let test_cases = ["", "012345", "123456", "1234567", "qW%f3_a"];
        for test_case in test_cases.iter() {
            let result_str = HashedPassword::parse_str(test_case).await;
            let result = HashedPassword::parse(test_case.to_string()).await;
            assert!(result_str.is_err());
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn should_not_store_password_in_plaintext() {
        let test_case = "TestPassword123";
        let result_str = HashedPassword::parse_str(test_case).await;
        let result = HashedPassword::parse(test_case.to_string()).await;
        assert!(result_str.is_ok());
        assert!(result.is_ok());
        assert_ne!(result.unwrap().password.as_str(), test_case);
    }

    #[test]
    fn can_parse_valid_argon2_hash() {
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15_000, 2, 1, None).unwrap(),
        );
        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hash_password = HashedPassword::parse_password_hash(hash_string.clone()).unwrap();

        assert_eq!(hash_password.as_ref(), hash_string.as_str());
        assert!(hash_password.as_ref().starts_with("$argon2id$v=19$"));
    }

    #[tokio::test]
    async fn can_verify_password_hash() {
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15_000, 2, 1, None).unwrap(),
        );
        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hash_password = HashedPassword::parse_password_hash(hash_string.clone()).unwrap();

        assert_eq!(hash_password.as_ref(), hash_string.as_str());
        assert!(hash_password.as_ref().starts_with("$argon2id$v=19$m=15000"));

        let result = hash_password
            .verify_raw_password(raw_password)
            .await
            .unwrap();
        assert_eq!(result, ());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub String);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let password = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(password)
        }
    }

    #[tokio::test]
    #[quickcheck_macros::quickcheck]
    async fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        HashedPassword::parse(valid_password.0).await.is_ok()
    }
}
