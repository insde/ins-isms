use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::error::AppError;

pub const MIN_PASSWORD_LEN: usize = 12;
pub const MAX_PASSWORD_LEN: usize = 128;

pub fn validate_password_policy(password: &str) -> Result<(), AppError> {
    let len = password.chars().count();
    if len < MIN_PASSWORD_LEN {
        return Err(AppError::Validation(vec![format!(
            "Das Passwort muss mindestens {MIN_PASSWORD_LEN} Zeichen lang sein."
        )]));
    }
    if len > MAX_PASSWORD_LEN {
        return Err(AppError::Validation(vec![format!(
            "Das Passwort darf maximal {MAX_PASSWORD_LEN} Zeichen lang sein."
        )]));
    }
    Ok(())
}

pub async fn hash_password(password: &str) -> Result<String, AppError> {
    validate_password_policy(password)?;
    let password_owned = password.to_owned();

    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password_owned.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| AppError::Internal(format!("Passwort-Hashing fehlgeschlagen: {e}")))
    })
    .await
    .map_err(|e| AppError::Internal(format!("Passwort-Hashing Task-Fehler: {e}")))?
}

pub async fn verify_password(password: &str, password_hash: &str) -> Result<bool, AppError> {
    if password.chars().count() > MAX_PASSWORD_LEN {
        return Ok(false);
    }
    let password_owned = password.to_owned();
    let hash_owned = password_hash.to_owned();

    tokio::task::spawn_blocking(move || {
        let parsed = match PasswordHash::new(&hash_owned) {
            Ok(h) => h,
            Err(_) => return Ok(false),
        };
        Ok(Argon2::default()
            .verify_password(password_owned.as_bytes(), &parsed)
            .is_ok())
    })
    .await
    .map_err(|e| AppError::Internal(format!("Passwort-Verifikation Task-Fehler: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_too_short_and_too_long_passwords() {
        assert!(validate_password_policy("kurz123!").is_err());
        assert!(validate_password_policy(&"a".repeat(129)).is_err());
        assert!(validate_password_policy("SicheresPasswort12!").is_ok());
    }

    #[tokio::test]
    async fn hashes_and_verifies_password() {
        let hash = hash_password("SicheresPasswort12!").await.unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("SicheresPasswort12!", &hash).await.unwrap());
        assert!(!verify_password("FalschesPasswort12!", &hash).await.unwrap());
    }
}
