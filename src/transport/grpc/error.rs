use crate::application::AuthError;
use tonic::Status;

pub fn status(error: AuthError) -> Status {
    match error {
        AuthError::InvalidEmail
        | AuthError::InvalidDisplayName
        | AuthError::InvalidAvatarUrl
        | AuthError::InvalidBio
        | AuthError::InvalidLocale
        | AuthError::InvalidTimezone
        | AuthError::PasswordPolicy
        | AuthError::InvalidVerificationToken
        | AuthError::InvalidEmailChangeToken
        | AuthError::InvalidResetToken => Status::invalid_argument(error.to_string()),
        AuthError::EmailAlreadyExists => Status::already_exists(error.to_string()),
        AuthError::InvalidCredentials
        | AuthError::InvalidRefreshToken
        | AuthError::InvalidToken
        | AuthError::SessionRevoked => Status::unauthenticated(error.to_string()),
        AuthError::EmailNotVerified | AuthError::AccountLocked => {
            Status::failed_precondition(error.to_string())
        }
        AuthError::VersionConflict => Status::aborted(error.to_string()),
        AuthError::UserNotFound | AuthError::SessionNotFound => {
            Status::not_found(error.to_string())
        }
        AuthError::RepositoryUnavailable => Status::unavailable(error.to_string()),
        AuthError::Internal => Status::internal(error.to_string()),
    }
}
