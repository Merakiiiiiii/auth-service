use crate::application::AuthError;

pub fn normalize_email(raw: &str) -> Result<String, AuthError> {
    let value = raw.trim().to_lowercase();
    let valid = value.len() <= 320
        && value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'));
    valid.then_some(value).ok_or(AuthError::InvalidEmail)
}

pub fn normalize_display_name(raw: &str) -> Result<String, AuthError> {
    bounded_required(raw, 120, AuthError::InvalidDisplayName)
}

pub fn normalize_avatar_url(raw: &str) -> Result<String, AuthError> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    let parsed = url::Url::parse(value).map_err(|_| AuthError::InvalidAvatarUrl)?;
    let valid = matches!(parsed.scheme(), "http" | "https") && value.len() <= 2_048;
    valid
        .then_some(value.to_owned())
        .ok_or(AuthError::InvalidAvatarUrl)
}

pub fn normalize_bio(raw: &str) -> Result<String, AuthError> {
    bounded_optional(raw, 500, AuthError::InvalidBio)
}

pub fn normalize_locale(raw: &str) -> Result<String, AuthError> {
    let value = raw.trim();
    let value = if value.is_empty() { "en" } else { value };
    let valid = value.len() <= 35
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-');
    valid
        .then_some(value.to_owned())
        .ok_or(AuthError::InvalidLocale)
}

pub fn normalize_timezone(raw: &str) -> Result<String, AuthError> {
    let value = raw.trim();
    let value = if value.is_empty() { "UTC" } else { value };
    let valid = value.len() <= 64
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '/' | '_' | '-' | '+')
        });
    valid
        .then_some(value.to_owned())
        .ok_or(AuthError::InvalidTimezone)
}

pub fn validate_password(raw: &str) -> Result<(), AuthError> {
    let acceptable = (10..=1_024).contains(&raw.len())
        && raw.chars().any(char::is_alphabetic)
        && raw.chars().any(char::is_numeric);
    acceptable.then_some(()).ok_or(AuthError::PasswordPolicy)
}

fn bounded_required(raw: &str, max: usize, error: AuthError) -> Result<String, AuthError> {
    let value = raw.trim();
    if value.is_empty() || value.chars().count() > max {
        return Err(error);
    }
    Ok(value.to_owned())
}

fn bounded_optional(raw: &str, max: usize, error: AuthError) -> Result<String, AuthError> {
    let value = raw.trim();
    if value.chars().count() > max {
        return Err(error);
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_is_stable() {
        let email = normalize_email(" User@Example.com ");
        assert!(email.is_ok());
        assert_eq!(email.ok().as_deref(), Some("user@example.com"));
        assert!(normalize_avatar_url("https://example.com/avatar.png").is_ok());
        assert!(normalize_locale("vi-VN").is_ok());
        assert!(normalize_timezone("Asia/Bangkok").is_ok());
        assert!(validate_password("password123").is_ok());
    }
}
