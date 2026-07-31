use super::{
    mapping::{actor_ids, operation, signing_key, status, token_pair, validated_token},
    service::GrpcAuthService,
};
use crate::application::{LoginContext, RegistrationInput};
use platform_proto::{
    ActorRequest, ChangePasswordRequest, Empty, ForgotPasswordRequest, LoginRequest, LogoutRequest,
    OperationResult, RefreshSessionRequest, RegisterRequest, RegisterResponse,
    ResetPasswordRequest, SigningKeysResponse, TokenPair, ValidateAccessTokenRequest,
    ValidateAccessTokenResponse, VerifyEmailRequest,
};
use tonic::Status;

impl GrpcAuthService {
    pub async fn handle_register(
        &self,
        request: RegisterRequest,
    ) -> Result<RegisterResponse, Status> {
        let user = self
            .application
            .register(RegistrationInput {
                email: request.email,
                password: request.password,
                display_name: request.display_name,
                locale: request.locale,
                timezone: request.timezone,
            })
            .await
            .map_err(status)?;
        Ok(RegisterResponse {
            user_id: user.id.to_string(),
            verification_required: user.status == "pending_verification",
            user: Some(super::mapping::user_profile(user)),
        })
    }

    pub async fn handle_verify_email(
        &self,
        request: VerifyEmailRequest,
    ) -> Result<OperationResult, Status> {
        self.application
            .verify_email(request.token)
            .await
            .map_err(status)?;
        Ok(operation("", 0))
    }

    pub async fn handle_login(&self, request: LoginRequest) -> Result<TokenPair, Status> {
        let context = LoginContext {
            device_name: request.device_name,
            user_agent: request.user_agent,
            ip_address: request.ip_address,
        };
        self.application
            .login(request.email, request.password, context)
            .await
            .map(token_pair)
            .map_err(status)
    }

    pub async fn handle_refresh(
        &self,
        request: RefreshSessionRequest,
    ) -> Result<TokenPair, Status> {
        self.application
            .refresh_session(request.refresh_token)
            .await
            .map(token_pair)
            .map_err(status)
    }

    pub async fn handle_logout(&self, request: LogoutRequest) -> Result<OperationResult, Status> {
        self.application
            .logout(request.refresh_token)
            .await
            .map_err(status)?;
        Ok(operation("", 0))
    }

    pub async fn handle_logout_all(
        &self,
        request: ActorRequest,
    ) -> Result<OperationResult, Status> {
        let actor = actor_ids(request.actor)?;
        self.application
            .logout_all(actor.user_id)
            .await
            .map_err(status)?;
        Ok(operation(actor.user_id.to_string(), 0))
    }

    pub async fn handle_forgot_password(
        &self,
        request: ForgotPasswordRequest,
    ) -> Result<OperationResult, Status> {
        self.application
            .forgot_password(request.email)
            .await
            .map_err(status)?;
        Ok(operation("", 0))
    }

    pub async fn handle_reset_password(
        &self,
        request: ResetPasswordRequest,
    ) -> Result<OperationResult, Status> {
        self.application
            .reset_password(request.token, request.new_password)
            .await
            .map_err(status)?;
        Ok(operation("", 0))
    }

    pub async fn handle_change_password(
        &self,
        request: ChangePasswordRequest,
    ) -> Result<OperationResult, Status> {
        let actor = actor_ids(request.actor)?;
        self.application
            .change_password(
                actor.user_id,
                request.current_password,
                request.new_password,
            )
            .await
            .map_err(status)?;
        Ok(operation(actor.user_id.to_string(), 0))
    }

    pub async fn handle_validate_token(
        &self,
        request: ValidateAccessTokenRequest,
    ) -> Result<ValidateAccessTokenResponse, Status> {
        self.application
            .validate_access_token(request.access_token)
            .await
            .map(validated_token)
            .map_err(status)
    }

    pub fn handle_signing_keys(&self, _: Empty) -> SigningKeysResponse {
        SigningKeysResponse {
            keys: self
                .application
                .signing_keys()
                .into_iter()
                .map(signing_key)
                .collect(),
        }
    }
}
