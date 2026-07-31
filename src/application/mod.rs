mod account;
mod auth;
mod authentication;
mod authentication_helpers;
mod error;
mod models;
mod password;
mod policy;
mod ports;
mod registration;
mod sessions;
mod validation;

pub use auth::AuthApplication;
pub use error::AuthError;
pub use models::{
    AccessClaims, IssuedAccessToken, LoginContext, NewUserAccount, NotificationKind,
    NotificationMessage, RegistrationInput, SessionPatch, TokenResult, UserProfilePatch,
};
pub use policy::AuthPolicy;
pub use ports::{
    AccessTokenPort, AccountLifecycleStore, AuthRepository, EmailChangeStore, HealthProbe,
    NotificationStore, PasswordPort, ProfileStore, RecoveryStore, SecretPort, SessionStore,
    UserStore,
};
pub use validation::{
    normalize_avatar_url, normalize_bio, normalize_display_name, normalize_email, normalize_locale,
    normalize_timezone, validate_password,
};
