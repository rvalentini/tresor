mod settings;

extern crate openssl;
extern crate diesel;
#[macro_use]
extern crate log;

use actix_web::middleware::Logger;
use actix_web::{HttpServer, HttpResponse, get, put, App, web, Error};
use diesel::pg::PgConnection;
use tresor_backend::{find_all_secrets, insert};
use tresor_backend::models::{Secret, NewSecret, Identity, User, OpCallback, OpenIdConnectState, Role};
use actix_web::dev::{Body};
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

type OidcClient = Client<TresorClaims, CoreAuthDisplay, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey, CoreAuthPrompt, StandardErrorResponse<BasicErrorResponseType>, StandardTokenResponse<IdTokenFields<TresorClaims, EmptyExtraTokenFields, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType>, BasicTokenType>, BasicTokenType>;

#[get("/")]
async fn hello(session: Session) -> Result<HttpResponse, Error> {
    if let Some(identity) = session.get::<Identity>("identity")? {
        Ok(HttpResponse::Ok().body(format!("Tresor says: Hey ho! Your identity is: {:?}", &identity.user)))
    } else {
       Ok( HttpResponse::SeeOther().header("Location", "/login").finish())
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

    match session.set("oidc_state", &oidc_state) {
        Ok(_) => {} //all fine
        Err(_) => {
            error!("Could not persist oidc-state to cookie for auth request");
            return Ok(HttpResponse::InternalServerError().finish());
        }
    }
    Ok(HttpResponse::SeeOther().header("Location", auth_url.as_str()).finish())
}

#[get("/logout")]
async fn logout(session: Session) -> Result<HttpResponse, Error> {
    if let Some(identity) = session.get::<Identity>("identity")? {
        info!("Clearing Tresor session for user {}", &identity.user.id);
        session.purge();
        info!("Redirecting to OpenID Connect Provider for session logout");
        Ok(HttpResponse::SeeOther().header("Location", "http://127.0.0.1:8080/auth/realms/master/protocol/openid-connect/logout?redirect_uri=http://127.0.0.1:8084").finish())
    } else {
        error!("Logout called without valid session - shouldn't happen");
        Ok(HttpResponse::Unauthorized().finish())
    }

}

//TODO use ? operator and move error-handling to separate function
#[get("/callback")]
async fn callback(session: Session, data: web::Data<AppState>, authorization_info: web::Query<OpCallback>) -> Result<HttpResponse, Error> {
    if let Some(oidc_state) = session.get::<OpenIdConnectState>("oidc_state")? {
        let token_response = data.oidc_client.exchange_code(
            AuthorizationCode::new(authorization_info.into_inner().code.to_string())
        ).set_pkce_verifier(oidc_state.pkce_verifier)
            .request_async(async_http_client)
            .await
            .map_err(|err| {
                error!("Could not exchange access token for authorization code at OpenId Provider: {}", err);
                HttpResponse::InternalServerError()
            })?;

        let id_token = token_response.extra_fields().id_token()
            .ok_or_else(|| {
                error!("OpenId Provider did not return a well formatted ID token");
                HttpResponse::InternalServerError().finish()
            })?;

        let claims = id_token.claims(
            &data.oidc_client.id_token_verifier(),
            &oidc_state.nonce)
            .map_err(|err| {
                error!("Returned claims from OpenId Provider could not be verified: {}", err);
                HttpResponse::InternalServerError()
            })?;


        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                &id_token.signing_alg().map_err(|err| {
                    error!("Unsupported signing algorithm used for ID token {}", err);
                    HttpResponse::InternalServerError()
                })?,
            ).map_err(|err| {
                error!("Could not calculate AccessTokenHash: {}", err);
                HttpResponse::InternalServerError()
            })?;
            if actual_access_token_hash != *expected_access_token_hash {
                error!("Actual and expected access_token hashes do not match");
                return Ok(HttpResponse::InternalServerError().finish());
            }
        }

        let user_id = claims.subject().to_string();

        if let (Some(id), Some(role), Some(mail)) =
        (&claims.additional_claims().tresor_id,
         &claims.additional_claims().tresor_role,
         &claims.email().map(|mail| mail.as_str())) {
            match Role::from_string(role) {
                Ok(role) => {
                    let identity = Identity {
                        user: User {
                            id: user_id.clone(),
                            tresor_id: id.to_string(),
                            tresor_role: role,
                            email: mail.to_string(),
                        },
                    };
                    match session.set("identity", identity) {
                        Ok(_) => {} //all fine
                        Err(_) => {
                            error!("Could not persist identity to cookie for user {}", &user_id);
                            return Ok(HttpResponse::InternalServerError().finish());
                        }
                    }
                }
                Err(err) => {
                    error!("Identity for user {} contains an unknown role: {}", user_id, err);
                    return Ok(HttpResponse::InternalServerError().finish());
                }
            }
        } else {
            error!("Received identity for user {} is invalid", user_id);
            return Ok(HttpResponse::InternalServerError().finish());
        }
        session.remove("oidc_state");
        info!("Successfully authenticated user {}", claims.subject().as_str());
    } else {
        error!("No csrf_state found! Cannot process OpenID Provider callback! \
        Could also be simply an unauthorized call to /callback! Returning 401 ...");
        return Ok(HttpResponse::Unauthorized().finish());
    }
    //redirect to root for now - later maybe just 200 - Success?
    Ok(HttpResponse::SeeOther().header("Location", "/").finish())
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
            .map_err(handle_internal_server_error)?;

        match secrets.as_slice() {
            [] => { Ok(HttpResponse::NotFound().body("No secrets found!")) }  //TODO restrict to specific user later
            _ => { Ok(HttpResponse::Ok().json(secrets)) }
        }
    } else {
        Ok(HttpResponse::SeeOther().header("Location", "/login").finish())
    }
}

#[put("/secret")]
async fn put_secret(session: Session, data: web::Data<AppState>, query: web::Query<NewSecret>) -> Result<HttpResponse, Error> {
    //TODO do not handle payload via query params
    //TODO use identity
    if let Some(identity) = session.get::<Identity>("identity")? {
        let connection = data.connection_pool
            .get()
            .expect("Could not get DB connection from pool!");

        //web::block() is used to offload the blocking DB operations without blocking the server thread.
        let secret: Secret = web::block(move || insert(&connection, &query.into_inner()))
            .await
            .map_err(handle_internal_server_error)?;

        Ok(HttpResponse::Ok().json(secret))
    } else {
        Ok(HttpResponse::SeeOther().header("Location", "/login").finish())
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

fn handle_internal_server_error(error: BlockingError<diesel::result::Error>) -> HttpResponse<Body> {
    error!("{}", error);
    HttpResponse::InternalServerError().finish()
}
