use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use color_eyre::eyre::{eyre, Context, Result};
use secrecy::{ExposeSecret, SecretString};

#[derive(Clone, Debug, Default)]
pub struct HashedPassword(SecretString);

impl PartialEq for HashedPassword {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl HashedPassword {
    pub async fn parse_str(input: &str) -> Result<HashedPassword> {
        Self::parse(SecretString::new(input.to_owned().into_boxed_str())).await
    }

    #[tracing::instrument(name = "HashedPassword parse", skip_all)]
    pub async fn parse(input: SecretString) -> Result<HashedPassword> {
        if input.expose_secret().len() >= 8 {
            if let Ok(password_hash) = compute_password_hash(&input).await {
                Ok(Self(password_hash))
            } else {
                Err(eyre!("Failed to hash password"))
            }
        } else {
            Err(eyre!("Failed to parse string to a HashedPassword type"))
        }
    }

    #[tracing::instrument(name = "HashedPassword parse password hash", skip_all)]
    pub fn parse_password_hash(hash: SecretString) -> Result<HashedPassword> {
        if let Ok(hashed_string) = PasswordHash::new(hash.expose_secret().as_ref()) {
            Ok(Self(SecretString::new(
                hashed_string.to_string().into_boxed_str(),
            )))
        } else {
            Err(eyre!("Failed to parse string to a HashedPassword type"))
        }
    }

    #[tracing::instrument(name = "HashedPassword verify raw password", skip_all)]
    pub async fn verify_raw_password(&self, password_candidate: &SecretString) -> Result<()> {
        let current_span: tracing::Span = tracing::Span::current();
        let password_hash = self.as_ref().expose_secret().to_string();
        let password_candidate = password_candidate.expose_secret().to_string();
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

impl AsRef<SecretString> for HashedPassword {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
pub async fn compute_password_hash(password: &SecretString) -> Result<SecretString> {
    let current_span: tracing::Span = tracing::Span::current();
    let password = password.expose_secret().to_string();
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

            Ok(SecretString::new(password_hash.into_boxed_str()))
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
            let result =
                HashedPassword::parse(SecretString::new(test_case.to_string().into_boxed_str()))
                    .await;
            assert!(result_str.is_err());
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn should_not_store_password_in_plaintext() {
        let test_case = "TestPassword123";
        let result_str = HashedPassword::parse_str(test_case).await;
        let result =
            HashedPassword::parse(SecretString::new(test_case.to_string().into_boxed_str())).await;
        assert!(result_str.is_ok());
        assert!(result.is_ok());
        assert_ne!(result.unwrap().0.expose_secret(), test_case);
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
        let hash_string: SecretString = SecretString::new(
            argon2
                .hash_password(raw_password.as_bytes(), &salt)
                .unwrap()
                .to_string()
                .into_boxed_str(),
        );

        let hash_password = HashedPassword::parse_password_hash(hash_string.clone()).unwrap();

        assert_eq!(hash_password.0.expose_secret(), hash_string.expose_secret());
        assert!(hash_password
            .0
            .expose_secret()
            .starts_with("$argon2id$v=19$m=15000,t=2,p=1$"));
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
        let hash_string = SecretString::new(
            argon2
                .hash_password(raw_password.as_bytes(), &salt)
                .unwrap()
                .to_string()
                .into_boxed_str(),
        );

        let hash_password = HashedPassword::parse_password_hash(hash_string.clone()).unwrap();

        assert_eq!(hash_password.0.expose_secret(), hash_string.expose_secret());
        assert!(hash_password
            .0
            .expose_secret()
            .starts_with("$argon2id$v=19$m=15000,t=2,p=1$"));

        let result = hash_password
            .verify_raw_password(&SecretString::new(
                raw_password.to_string().into_boxed_str(),
            ))
            .await
            .unwrap();
        assert_eq!(result, ());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub SecretString);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let password: String = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(SecretString::new(password.into_boxed_str()))
        }
    }

    #[tokio::test]
    #[quickcheck_macros::quickcheck]
    async fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        HashedPassword::parse(valid_password.0).await.is_ok()
    }
}
