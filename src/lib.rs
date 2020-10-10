#[macro_use]
extern crate diesel;

pub mod schema;
pub mod models;

use schema::*;
use models::*;
use diesel::prelude::*;

pub fn fetch_secrets(connection: &PgConnection) -> Vec<Secret>{
    use schema::secrets::dsl::*;
    secrets
        .limit(5)
        .load::<Secret>(connection)
        .expect("Error loading secrets!")
}

pub fn create_secret(connection: &PgConnection, secret: &Secret) -> Secret {
    diesel::insert_into(secrets::table)
        .values(secret)
        .get_result(connection)
        .expect("Error saving secret!")
}