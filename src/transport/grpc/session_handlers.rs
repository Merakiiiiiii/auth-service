use super::{
    mapping::{actor_ids, expected_version, operation, parse_id, session_info, status},
    service::GrpcAuthService,
};
use crate::application::SessionPatch;
use platform_proto::{
    ActorRequest, GetSessionRequest, ListSessionsResponse, OperationResult, RevokeSessionRequest,
    SessionInfo, UpdateSessionRequest,
};
use tonic::Status;

impl GrpcAuthService {
    pub async fn handle_get_session(
        &self,
        request: GetSessionRequest,
    ) -> Result<SessionInfo, Status> {
        let actor = actor_ids(request.actor)?;
        let session_id = parse_id(&request.session_id, "AUTH_INVALID_SESSION_ID")?;
        self.application
            .get_session(actor.user_id, session_id)
            .await
            .map(|session| session_info(session, actor.session_id))
            .map_err(status)
    }

    pub async fn handle_list_sessions(
        &self,
        request: ActorRequest,
    ) -> Result<ListSessionsResponse, Status> {
        let actor = actor_ids(request.actor)?;
        let sessions = self
            .application
            .list_sessions(actor.user_id)
            .await
            .map_err(status)?
            .into_iter()
            .map(|session| session_info(session, actor.session_id))
            .collect();
        Ok(ListSessionsResponse { sessions })
    }

    pub async fn handle_update_session(
        &self,
        request: UpdateSessionRequest,
    ) -> Result<SessionInfo, Status> {
        let actor = actor_ids(request.actor)?;
        let session_id = parse_id(&request.session_id, "AUTH_INVALID_SESSION_ID")?;
        let patch = SessionPatch {
            device_name: request.device_name,
            expected_version: expected_version(request.expected_version)?,
        };
        self.application
            .update_session(actor.user_id, session_id, patch)
            .await
            .map(|session| session_info(session, actor.session_id))
            .map_err(status)
    }

    pub async fn handle_revoke_session(
        &self,
        request: RevokeSessionRequest,
    ) -> Result<OperationResult, Status> {
        let actor = actor_ids(request.actor)?;
        let session_id = parse_id(&request.session_id, "AUTH_INVALID_SESSION_ID")?;
        self.application
            .revoke_session(actor.user_id, session_id)
            .await
            .map_err(status)?;
        Ok(operation(session_id.to_string(), 0))
    }
}
