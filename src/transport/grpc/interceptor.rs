use std::sync::Arc;
use subtle::ConstantTimeEq;
use tonic::{Request, Status, service::Interceptor};

#[derive(Clone)]
pub struct InternalGrpcAuth {
    expected: Arc<Vec<u8>>,
}

impl InternalGrpcAuth {
    pub fn new(token: String) -> Self {
        Self {
            expected: Arc::new(token.into_bytes()),
        }
    }
}

impl Interceptor for InternalGrpcAuth {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let supplied = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("INTERNAL_GRPC_UNAUTHENTICATED"))?;
        if supplied.as_bytes().ct_eq(self.expected.as_slice()).into() {
            Ok(request)
        } else {
            Err(Status::unauthenticated("INTERNAL_GRPC_UNAUTHENTICATED"))
        }
    }
}
