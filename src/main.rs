use actix_web::{HttpServer, HttpResponse, Responder, get, App};
use actix_web::middleware::Logger;
use env_logger::Env;
#[macro_use]
extern crate log;


#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    env_logger::from_env(Env::default().default_filter_or("info")).init();
    info!("Tresor is starting up");

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(hello)
    })
        .bind("127.0.0.1:8084")?
        .run()
        .await
}