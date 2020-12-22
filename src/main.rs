mod settings;
mod error;

mod routes {
    pub mod oidc;
    pub mod tresor;
}

extern crate openssl;
extern crate diesel;
#[macro_use]
extern crate log;

use crate::error::ConfigurationError::SettingsInitializationError;
use crate::settings::Settings;
use actix_web::middleware::Logger;
use actix_web::{HttpServer, App};
use diesel::pg::PgConnection;
use diesel::r2d2::ConnectionManager;
use r2d2::Pool;
use actix_session::CookieSession;
use serde::{Serialize, Deserialize};
use openidconnect::{IssuerUrl, ClientId, RedirectUrl, Client, AdditionalClaims, IdTokenFields, StandardErrorResponse, StandardTokenResponse, EmptyExtraTokenFields};
use openidconnect::reqwest::async_http_client;
use openidconnect::core::{CoreProviderMetadata, CoreAuthDisplay, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey, CoreAuthPrompt};
use std::sync::Arc;
use oauth2::ClientSecret;
use oauth2::basic::{BasicErrorResponseType, BasicTokenType};
use routes::oidc::{login, logout, callback, test_login};
use routes::tresor::{whoami, get_secret, delete_secret, get_secrets, put_secret};

const IDENTITY_SESSION_KEY: &str = "identity";

type OidcClient = Client<TresorClaims, CoreAuthDisplay, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJsonWebKey, CoreAuthPrompt, StandardErrorResponse<BasicErrorResponseType>, StandardTokenResponse<IdTokenFields<TresorClaims, EmptyExtraTokenFields, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType>, BasicTokenType>, BasicTokenType>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let settings = Arc::new(Settings::init()
        .map_err(|err| SettingsInitializationError(err.to_string()))
        .expect("Configuration is invalid"));

    env_logger::builder().parse_filters(&settings.logging.level).init();
    info!("Tresor is starting up");
    info!("Tresor run mode is: {:?}", &settings.server.runmode);

    let listen_interface = settings.server.interface.clone();
    let listen_port = settings.server.port.clone();

    let connection_pool = build_db_connection_pool(&settings);

    //build OpenId Connect client
    let meta_data = CoreProviderMetadata::discover_async(
        IssuerUrl::new(settings.auth.issuerurl.clone())
            .expect("IssuerUrl for OpenID provider must be set"),
        async_http_client).await.unwrap();

    let client: OidcClient = Client::new(ClientId::new(settings.auth.clientid.clone()),
                                         Some(ClientSecret::new(settings.auth.clientsecret.clone())),
                                         IssuerUrl::new(settings.auth.issuerurl.clone())
                                             .expect("IssuerUrl for OpenID provider must be set"),
                                         meta_data.authorization_endpoint().clone(),
                                         meta_data.token_endpoint().cloned(),
                                         meta_data.userinfo_endpoint().cloned(),
                                         meta_data.jwks().to_owned());


    let client: Arc<OidcClient> = Arc::new(
        client.set_redirect_uri(
            RedirectUrl::new(
                format!("http://{}:{}/callback",
                        &settings.server.interface,
                        &settings.server.port).to_string()).unwrap()));


    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(CookieSession::private(&settings.server.cookiemasterkey.as_bytes())
                .secure(false)) //TODO enable TLS
            .data(AppState {
                connection_pool: connection_pool.clone(),
                oidc_client: client.clone(),
                settings: settings.clone(),
            })
            .service(whoami)
            .service(login)
            .service(test_login)
            .service(logout)
            .service(callback)
            .service(get_secret)
            .service(get_secrets)
            .service(delete_secret)
            .service(put_secret)
    })
        .bind(format!("{}:{}", &listen_interface, &listen_port))?
        .run()
        .await
}

pub struct AppState {
    connection_pool: Pool<ConnectionManager<PgConnection>>,
    oidc_client: Arc<OidcClient>,
    settings: Arc<Settings>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
struct TresorClaims {
    tresor_role: Option<String>,
    tresor_id: Option<String>,
}

impl AdditionalClaims for TresorClaims {}

fn build_db_connection_pool(settings: &Settings) -> Pool<ConnectionManager<PgConnection>> {
    let database_url = &settings.database.url;
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create DB connection pool, please check the database url!")
}

