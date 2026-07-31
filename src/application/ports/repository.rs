use super::{
    AccountLifecycleStore, EmailChangeStore, HealthProbe, NotificationStore, ProfileStore,
    RecoveryStore, SessionStore, UserStore,
};

pub trait AuthRepository:
    UserStore
    + ProfileStore
    + EmailChangeStore
    + AccountLifecycleStore
    + SessionStore
    + RecoveryStore
    + NotificationStore
    + HealthProbe
{
}

impl<T> AuthRepository for T where
    T: UserStore
        + ProfileStore
        + EmailChangeStore
        + AccountLifecycleStore
        + SessionStore
        + RecoveryStore
        + NotificationStore
        + HealthProbe
{
}
