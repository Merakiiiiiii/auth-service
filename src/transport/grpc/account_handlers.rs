use super::{
    mapping::{actor_ids, expected_version, operation, status, user_profile},
    service::GrpcAuthService,
};
use crate::application::UserProfilePatch;
use platform_proto::{
    ActorRequest, ConfirmEmailChangeRequest, DeleteCurrentUserRequest, OperationResult,
    RequestEmailChangeRequest, UpdateCurrentUserRequest, UserProfile,
};
use tonic::Status;

impl GrpcAuthService {
    pub async fn handle_get_user(&self, request: ActorRequest) -> Result<UserProfile, Status> {
        let actor = actor_ids(request.actor)?;
        self.application
            .get_user(actor.user_id)
            .await
            .map(user_profile)
            .map_err(status)
    }

    pub async fn handle_update_user(
        &self,
        request: UpdateCurrentUserRequest,
    ) -> Result<UserProfile, Status> {
        let actor = actor_ids(request.actor)?;
        let patch = UserProfilePatch {
            display_name: request.display_name,
            avatar_url: request.avatar_url,
            bio: request.bio,
            locale: request.locale,
            timezone: request.timezone,
            expected_version: expected_version(request.expected_version)?,
        };
        self.application
            .update_user(actor.user_id, patch)
            .await
            .map(user_profile)
            .map_err(status)
    }

    pub async fn handle_request_email_change(
        &self,
        request: RequestEmailChangeRequest,
    ) -> Result<OperationResult, Status> {
        let actor = actor_ids(request.actor)?;
        self.application
            .request_email_change(actor.user_id, request.new_email, request.current_password)
            .await
            .map_err(status)?;
        Ok(operation(actor.user_id.to_string(), 0))
    }

    pub async fn handle_confirm_email_change(
        &self,
        request: ConfirmEmailChangeRequest,
    ) -> Result<UserProfile, Status> {
        self.application
            .confirm_email_change(request.token)
            .await
            .map(user_profile)
            .map_err(status)
    }

    pub async fn handle_delete_user(
        &self,
        request: DeleteCurrentUserRequest,
    ) -> Result<OperationResult, Status> {
        let actor = actor_ids(request.actor)?;
        let version = self
            .application
            .delete_user(
                actor.user_id,
                request.current_password,
                expected_version(request.expected_version)?,
            )
            .await
            .map_err(status)?;
        Ok(operation(actor.user_id.to_string(), version))
    }
}
