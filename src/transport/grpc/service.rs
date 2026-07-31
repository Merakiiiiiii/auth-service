use crate::application::AuthApplication;
use platform_proto::{
    ActorRequest, ChangePasswordRequest, ConfirmEmailChangeRequest, DeleteCurrentUserRequest,
    Empty, ForgotPasswordRequest, GetSessionRequest, ListSessionsResponse, LoginRequest,
    LogoutRequest, OperationResult, RefreshSessionRequest, RegisterRequest, RegisterResponse,
    RequestEmailChangeRequest, ResetPasswordRequest, RevokeSessionRequest, SessionInfo,
    SigningKeysResponse, TokenPair, UpdateCurrentUserRequest, UpdateSessionRequest, UserProfile,
    ValidateAccessTokenRequest, ValidateAccessTokenResponse, VerifyEmailRequest,
    auth_service_server::AuthService,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct GrpcAuthService {
    pub(super) application: Arc<AuthApplication>,
}

impl GrpcAuthService {
    pub const fn new(application: Arc<AuthApplication>) -> Self {
        Self { application }
    }
}

#[tonic::async_trait]
impl AuthService for GrpcAuthService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        self.handle_register(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn verify_email(
        &self,
        request: Request<VerifyEmailRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        self.handle_verify_email(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn login(&self, request: Request<LoginRequest>) -> Result<Response<TokenPair>, Status> {
        self.handle_login(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn refresh_session(
        &self,
        request: Request<RefreshSessionRequest>,
    ) -> Result<Response<TokenPair>, Status> {
        self.handle_refresh(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        self.handle_logout(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn logout_all(
        &self,
        request: Request<ActorRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        self.handle_logout_all(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn forgot_password(
        &self,
        request: Request<ForgotPasswordRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        self.handle_forgot_password(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn reset_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        self.handle_reset_password(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        self.handle_change_password(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn get_current_user(
        &self,
        request: Request<ActorRequest>,
    ) -> Result<Response<UserProfile>, Status> {
        self.handle_get_user(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn update_current_user(
        &self,
        request: Request<UpdateCurrentUserRequest>,
    ) -> Result<Response<UserProfile>, Status> {
        self.handle_update_user(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn request_email_change(
        &self,
        request: Request<RequestEmailChangeRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        self.handle_request_email_change(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn confirm_email_change(
        &self,
        request: Request<ConfirmEmailChangeRequest>,
    ) -> Result<Response<UserProfile>, Status> {
        self.handle_confirm_email_change(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn delete_current_user(
        &self,
        request: Request<DeleteCurrentUserRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        self.handle_delete_user(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn validate_access_token(
        &self,
        request: Request<ValidateAccessTokenRequest>,
    ) -> Result<Response<ValidateAccessTokenResponse>, Status> {
        self.handle_validate_token(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn get_signing_keys(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<SigningKeysResponse>, Status> {
        Ok(Response::new(
            self.handle_signing_keys(request.into_inner()),
        ))
    }
    async fn get_session(
        &self,
        request: Request<GetSessionRequest>,
    ) -> Result<Response<SessionInfo>, Status> {
        self.handle_get_session(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn list_sessions(
        &self,
        request: Request<ActorRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        self.handle_list_sessions(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn update_session(
        &self,
        request: Request<UpdateSessionRequest>,
    ) -> Result<Response<SessionInfo>, Status> {
        self.handle_update_session(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn revoke_session(
        &self,
        request: Request<RevokeSessionRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        self.handle_revoke_session(request.into_inner())
            .await
            .map(Response::new)
    }
}
