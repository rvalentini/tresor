use derive_more::Display;
use actix_web::{ResponseError, HttpResponse};

#[derive(Debug, Display)]
pub enum DatabaseError {
    #[display(fmt = "Could not acquire data base connection from pool")]
    ConnectionError,
    #[display(fmt = "Encountered the following Diesel operation error: {}", _0)]
    DieselOperationError(diesel::result::Error),
    #[display(fmt = "Problem with Actix threadpool")]
    ExecutionError,
}

impl ResponseError for DatabaseError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::InternalServerError().finish()
    }
}

#[derive(Debug, Display)]
pub enum OIDCError {
    #[display(fmt = "Could not exchange OIDC access token for authorization code at OpenId Provider")]
    ExchangeTokenError,
    #[display(fmt = "OpenIdProvider response did not contain an ID token")]
    EmptyIdTokenError,
    #[display(fmt = "Verification of OIDC claims received from OpenIdProvider failed")]
    ClaimsVerificationError,
    #[display(fmt = "Received claims did not contain an access token hash")]
    MissingTokenHashError,
    #[display(fmt = "Unsupported signing algorithm used for signing the access token hash")]
    SigningError,
    #[display(fmt = "Access token hash presented by OIDProvider does not fit the access token")]
    AccessTokenVerificationError,
    #[display(fmt = "Claim does not contain all necessary identity information for user {}", _0)]
    ClaimsContentError(String),
    #[display(fmt = "Client session-cookie does not contain any csrf_state")]
    CsrfStateError,
}

impl ResponseError for OIDCError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::InternalServerError().finish()
    }
}

#[derive(Debug, Display)]
pub enum SessionError {
    #[display(fmt = "Could not read from session-cookie for user {}", _0)]
    ReadSessionError(String),
    #[display(fmt = "Could not write to session-cookie for user{}", _0)]
    WriteSessionError(String),
}

impl ResponseError for SessionError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::InternalServerError().finish()
    }
}

#[derive(Debug, Display)]
pub enum ConfigurationError {
    #[display(fmt = "Error while constructing settings from file and environment:{}", _0)]
    SettingsInitializationError(String)
}
