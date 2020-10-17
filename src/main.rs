#[macro_use]
extern crate log;
extern crate diesel;
extern crate dotenv;

use env_logger::Env;
use actix_web::middleware::Logger;
use actix_web::{HttpServer, HttpResponse, Responder, get, put, App, web, Error};
use diesel::pg::PgConnection;
use dotenv::dotenv;
use std::env;
use tresor_backend::{find_all_secrets, insert};
use tresor_backend::models::{Secret, NewSecret};
use actix_web::dev::Body;
use diesel::r2d2::ConnectionManager;
use r2d2::Pool;
use actix_web::error::BlockingError;

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
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
    env_logger::from_env(Env::default().default_filter_or("info")).init();
    info!("Tresor is starting up");

    let connection_pool = build_db_connection_pool();

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .data(AppState {
                connection_pool: connection_pool.clone()
            })
            .service(hello)
            .service(get_secrets)
            .service(put_secret)
    })
        .bind("127.0.0.1:8084")?
        .run()
        .await
}

struct AppState {
    connection_pool: Pool<ConnectionManager<PgConnection>>
}

fn build_db_connection_pool() -> Pool<ConnectionManager<PgConnection>> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL")
        .expect("Database URL for Postgres connection must be set!");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    r2d2::Pool::builder().build(manager).expect("Failed to create DB connection pool!")
}

fn handle_internal_server_error(error: BlockingError<diesel::result::Error>) -> HttpResponse<Body> {
    error!("{}", error);
    HttpResponse::InternalServerError().finish()
}