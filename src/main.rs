mod settings;

extern crate openssl;
extern crate diesel;
#[macro_use]
extern crate log;

use actix_web::middleware::Logger;
use actix_web::{HttpServer, HttpResponse, Responder, get, put, post, App, web, Error};
use diesel::pg::PgConnection;
use tresor_backend::{find_all_secrets, insert};
use tresor_backend::models::{Secret, NewSecret, Identity, User};
use actix_web::dev::Body;
use diesel::r2d2::ConnectionManager;
use r2d2::Pool;
use actix_web::error::BlockingError;
use crate::settings::Settings;
use futures::io::ErrorKind;
use actix_session::{CookieSession, Session};
use serde::{Serialize, Deserialize};

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[derive(Deserialize)]
struct Info {
    name: String,
}

//test-route for cookie management
#[get("/cookie")]
async fn cookie(session: Session, info: web::Query<Info>) -> Result<HttpResponse, Error> {
    if let Some(identity) = session.get::<Identity>("identity")? {
        info!("Found identity data in cookie: {:?}", identity);
        Ok(HttpResponse::Ok().json(&identity))

    } else {
        info!("No identity found! Setting '{}'", &info.name);
        let id = Identity {
            token: "some_token".to_string(),
            user: User {
                id: 100,
                last_name: "Parker".to_string(),
                first_name: info.name.clone(),
                email: "parker@daily-bugle.com".to_string()
            }
        };
        session.set("identity", &id);
        Ok(HttpResponse::Ok().json(&id))
    }
}


#[get("/secrets")]
async fn get_secrets(data: web::Data<AppState>) -> Result<HttpResponse, Error> {
    //TODO move connection to application state
    let connection = data.connection_pool
        .get()
        .expect("Could not get DB connection from pool!");

    //web::block() is used to offload the blocking DB operations without blocking the server thread.
    let secrets: Vec<Secret> = web::block(move || find_all_secrets(&connection))
        .await
        .map_err(handle_internal_server_error)?;

    match secrets.as_slice() {
        [] => { Ok(HttpResponse::NotFound().body("No secrets found!")) }   //TODO restrict to specific user later
        _ => { Ok(HttpResponse::Ok().json(secrets)) }
    }
}

#[put("/secret")]
async fn put_secret(data: web::Data<AppState>, query: web::Query<NewSecret>) -> Result<HttpResponse, Error> {
    //TODO do not handle payload via query params
    let connection = data.connection_pool
        .get()
        .expect("Could not get DB connection from pool!");

    //web::block() is used to offload the blocking DB operations without blocking the server thread.
    let secret: Secret = web::block(move || insert(&connection, &query.into_inner()))
        .await
        .map_err(handle_internal_server_error)?;

    Ok(HttpResponse::Ok().json(secret))
}

//TODO implement DELETE, UPDATE for secret/secrets

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let settings = Settings::init()
        .map_err(|err| std::io::Error::new(ErrorKind::Other, err))?;

    env_logger::builder().parse_filters(&settings.logging.level).init();
    info!("Tresor is starting up");

    let listen_interface = &settings.server.interface;
    let listen_port = &settings.server.port;

    let connection_pool = build_db_connection_pool(&settings);

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(CookieSession::private(&[0; 32]) //TODO generate key?
                .secure(false)) //TODO enable TLS
            .data(AppState {
                connection_pool: connection_pool.clone()
            })
            .service(hello)
            .service(cookie)
            .service(get_secrets)
            .service(put_secret)
    })
        .bind(format!("{}:{}", &listen_interface, &listen_port))?
        .run()
        .await
}

struct AppState {
    connection_pool: Pool<ConnectionManager<PgConnection>>
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