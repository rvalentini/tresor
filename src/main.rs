#[macro_use]
extern crate log;
extern crate diesel;
extern crate dotenv;

use env_logger::Env;
use actix_web::middleware::Logger;
use actix_web::{HttpServer, HttpResponse, Responder, get, put, App, web};
use diesel::prelude::*;
use diesel::pg::PgConnection;
use dotenv::dotenv;
use std::env;
use tresor_backend::{fetch_secrets, create_secret};
use tresor_backend::models::Secret;

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[get("/secrets")]
async fn get_secrets() -> impl Responder {
    //TODO move connection to application state
    let connection =  establish_db_connection();
    let secrets = fetch_secrets(&connection);
    web::Json(secrets)
}

#[put("/secret")]
async fn put_secret(query: web::Query<Secret>) -> impl Responder {
    //TODO do not handle payload via query params
    //TODO move connection to application state
    let connection =  establish_db_connection();
    //TODO implement proper error handling and error response
    let secret = create_secret(&connection, &query.into_inner());
    web::Json(secret)
}

//TODO implement DELETE, UPDATE for secret/secrets

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    env_logger::from_env(Env::default().default_filter_or("info")).init();
    info!("Tresor is starting up");

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(hello)
            .service(get_secrets)
            .service(put_secret)
    })
        .bind("127.0.0.1:8084")?
        .run()
        .await
}

fn establish_db_connection() -> PgConnection {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL")
        .expect("Database URL for Postgres connection must be set!");

    PgConnection::establish(&database_url)
        .expect(&format!("ERROR connecting to {}", &database_url))
}