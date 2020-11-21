mod settings;

extern crate openssl;
extern crate diesel;
#[macro_use]
extern crate log;

use actix_web::middleware::Logger;
use actix_web::{HttpServer, HttpResponse, get, put, App, web, Error, ResponseError};
use diesel::pg::PgConnection;
use tresor_backend::{find_all_secrets, insert};
use tresor_backend::models::{Secret, NewSecret, Identity, User, OpCallback, OpenIdConnectState, Role};
use diesel::r2d2::ConnectionManager;
use r2d2::Pool;
use actix_web::error::BlockingError;
use crate::settings::Settings;
use actix_session::{CookieSession, Session};
use serde::{Serialize, Deserialize};
use openidconnect::{IssuerUrl, ClientId, RedirectUrl, PkceCodeChallenge, CsrfToken, Nonce, Scope, Client, AuthorizationCode, AsyncCodeTokenRequest, AccessTokenHash, AdditionalClaims, IdTokenFields, StandardErrorResponse, StandardTokenResponse, EmptyExtraTokenFields};
use openidconnect::reqwest::async_http_client;
use openidconnect::core::{CoreProviderMetadata, CoreAuthenticationFlow, CoreAuthDisplay, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey, CoreAuthPrompt};
use std::sync::Arc;
use oauth2::TokenResponse;
use oauth2::basic::{BasicErrorResponseType, BasicTokenType};
use derive_more::Display;

type OidcClient = Client<TresorClaims, CoreAuthDisplay, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey, CoreAuthPrompt, StandardErrorResponse<BasicErrorResponseType>, StandardTokenResponse<IdTokenFields<TresorClaims, EmptyExtraTokenFields, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType>, BasicTokenType>, BasicTokenType>;

#[get("/")]
async fn hello(session: Session) -> Result<HttpResponse, Error> {
    if let Some(identity) = session.get::<Identity>("identity")
        .map_err(|_| SessionError::ReadSessionError("unknown".to_string()))? {
        Ok(HttpResponse::Ok().body(format!("Tresor says: Hey ho! Your identity is: {:?}", &identity.user)))
    } else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}

#[get("/login")]
async fn login(session: Session, data: web::Data<AppState>) -> Result<HttpResponse, Error> {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = data.oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random)
        .add_scope(Scope::new("tresor".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let oidc_state = OpenIdConnectState {
        pkce_verifier,
        csrf_token,
        nonce,
    };

    session.set("oidc_state", &oidc_state)
        .map_err(|_| SessionError::WriteSessionError("unknown".to_string()))?;

    //redirect to OpenIdProvider for authentication
    Ok(HttpResponse::SeeOther().header("Location", auth_url.as_str()).finish())
}

#[get("/logout")]
async fn logout(session: Session) -> Result<HttpResponse, Error> {
    if let Some(identity) = session.get::<Identity>("identity")
        .map_err(|_| SessionError::ReadSessionError("unknown".to_string()))? {
        info!("Clearing Tresor session for user {}", &identity.user.id);
        session.purge();
        info!("Redirecting to OpenID Connect Provider for session logout");
        Ok(HttpResponse::SeeOther().header("Location", "http://127.0.0.1:8080/auth/realms/master/protocol/openid-connect/logout?redirect_uri=http://127.0.0.1:8084/login").finish())
    } else {
        warn!("/logout called without valid session information");
        Ok(HttpResponse::Unauthorized().finish())
    }
}

#[derive(Debug, Display)]
pub enum DatabaseError {
    #[display(fmt = "Encountered the following Diesel operation error: {}", _0)]
    DieselOperationError(diesel::result::Error),
    #[display(fmt = "Problem with Actix threadpool")]
    ExecutionError
}

impl ResponseError for DatabaseError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::InternalServerError().finish()
    }
}

impl ResponseError for OIDCError {
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

impl ResponseError for SessionError {
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

#[get("/callback")]
async fn callback(session: Session, data: web::Data<AppState>, authorization_info: web::Query<OpCallback>) -> Result<HttpResponse, Error> {
    if let Some(oidc_state) = session.get::<OpenIdConnectState>("oidc_state")? {
        let token_response = data.oidc_client.exchange_code(
            AuthorizationCode::new(authorization_info.into_inner().code.to_string())
        ).set_pkce_verifier(oidc_state.pkce_verifier)
            .request_async(async_http_client)
            .await
            .map_err(|_| OIDCError::ExchangeTokenError)?;

        let id_token = token_response.extra_fields().id_token()
            .ok_or_else(|| OIDCError::EmptyIdTokenError)?;

        let claims = id_token.claims(
            &data.oidc_client.id_token_verifier(),
            &oidc_state.nonce)
            .map_err(|_| OIDCError::ClaimsVerificationError)?;

        match claims.access_token_hash() {
            None => { Err(OIDCError::MissingTokenHashError) }
            Some(given_token_hash) => {
                let calculated_token_hash = AccessTokenHash::from_token(
                    token_response.access_token(),
                    &id_token.signing_alg().map_err(|_| OIDCError::SigningError)?,
                ).map_err(|_| OIDCError::SigningError)?;

                if calculated_token_hash != *given_token_hash {
                    Err(OIDCError::AccessTokenVerificationError)
                } else {
                    Ok(())
                }
            }
        }?;

        let user_id = claims.subject().to_string();

        if let (Some(id), Some(role), Some(mail)) =
        (&claims.additional_claims().tresor_id,
         &claims.additional_claims().tresor_role,
         &claims.email().map(|mail| mail.as_str())) {
            let role = Role::from_string(role)?;
            let identity = Identity {
                user: User {
                    id: user_id.clone(),
                    tresor_id: id.to_string(),
                    tresor_role: role,
                    email: mail.to_string(),
                },
            };
            session.set("identity", identity)
                .map_err(|_| SessionError::WriteSessionError(user_id.clone()))?;
        } else {
            return Err(Error::from(OIDCError::ClaimsContentError(user_id.clone())));
        }
        session.remove("oidc_state");
        info!("Successfully authenticated user {}", &user_id);
    } else {
        return Err(Error::from(OIDCError::CsrfStateError));
    }
    Ok(HttpResponse::Ok().body("Success"))
}


#[get("/secrets")]
async fn get_secrets(session: Session, data: web::Data<AppState>) -> Result<HttpResponse, Error> {
    if let Some(identity) = session.get::<Identity>("identity")? {
        //TODO use identity
        let connection = data.connection_pool
            .get()
            .expect("Could not get DB connection from pool!");

        //web::block() is used to offload the blocking DB operations without blocking the server thread.
        let secrets: Vec<Secret> = web::block(move || find_all_secrets(&connection))
            .await
            .map_err(|err| match err {
                BlockingError::Error(err) => { DatabaseError::DieselOperationError(err) }
                BlockingError::Canceled => { DatabaseError::ExecutionError }
            })?;

        match secrets.as_slice() {
            [] => { Ok(HttpResponse::NotFound().body("No secrets found!")) }  //TODO restrict to specific user later
            _ => { Ok(HttpResponse::Ok().json(secrets)) }
        }
    } else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}

#[put("/secret")]
async fn put_secret(session: Session, data: web::Data<AppState>, query: web::Query<NewSecret>) -> Result<HttpResponse, Error> {
    //TODO do not handle payload via query params
    //TODO use identity
    //TODO improve error handling
    if let Some(identity) = session.get::<Identity>("identity")? {
        let connection = data.connection_pool
            .get()
            .expect("Could not get DB connection from pool!"); //TODO make error

        //web::block() is used to offload the blocking DB operations without blocking the server thread.
        let secret: Secret = web::block(move || insert(&connection, &query.into_inner()))
            .await
            .map_err(|err| match err {
                BlockingError::Error(err) => { DatabaseError::DieselOperationError(err) }
                BlockingError::Canceled => { DatabaseError::ExecutionError }
            })?;

        Ok(HttpResponse::Ok().json(secret))
    } else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}

//TODO implement DELETE, UPDATE for secret/secrets

//TODO implement /login for keycloak callback

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let settings = Settings::init().unwrap();

    env_logger::builder().parse_filters(&settings.logging.level).init();
    info!("Tresor is starting up");

    let listen_interface = &settings.server.interface;
    let listen_port = &settings.server.port;

    let connection_pool = build_db_connection_pool(&settings);

    //build OpenId Connect client
    let meta_data = CoreProviderMetadata::discover_async(
        IssuerUrl::new("http://127.0.0.1:8080/auth/realms/master".to_string()) //TODO configurable
            .expect("IssuerUrl for OpenID provider must be set"),
        async_http_client).await.unwrap();

    //TODO make everythin configurable
    let client: OidcClient = Client::new(ClientId::new("tresor-backend".to_string()),
                                         Option::None,
                                         IssuerUrl::new("http://127.0.0.1:8080/auth/realms/master".to_string())
                                             .expect("IssuerUrl for OpenID provider must be set"),
                                         meta_data.authorization_endpoint().clone(),
                                         meta_data.token_endpoint().cloned(),
                                         meta_data.userinfo_endpoint().cloned(),
                                         meta_data.jwks().to_owned());


    let client: Arc<OidcClient> = Arc::new(client.set_redirect_uri(RedirectUrl::new("http://127.0.0.1:8084/callback".to_string()).unwrap()));


    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(CookieSession::private(&[0; 32]) //TODO generate key?
                .secure(false)) //TODO enable TLS
            .data(AppState {
                connection_pool: connection_pool.clone(),
                oidc_client: client.clone(),
            })
            .service(hello)
            .service(login)
            .service(logout)
            .service(callback)
            .service(get_secrets)
            .service(put_secret)
    })
        .bind(format!("{}:{}", &listen_interface, &listen_port))?
        .run()
        .await
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
struct TresorClaims {
    tresor_role: Option<String>,
    tresor_id: Option<String>,
}

impl AdditionalClaims for TresorClaims {}


struct AppState {
    connection_pool: Pool<ConnectionManager<PgConnection>>,
    oidc_client: Arc<OidcClient>,
}

fn build_db_connection_pool(settings: &Settings) -> Pool<ConnectionManager<PgConnection>> {
    let database_url = &settings.database.url;
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create DB connection pool, please check the database url!")
}

