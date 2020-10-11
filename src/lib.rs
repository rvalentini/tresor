#[macro_use]
extern crate diesel;
pub mod schema;
pub mod models;

use schema::*;
use models::*;
use diesel::prelude::*;
use diesel::result::Error;
use r2d2::PooledConnection;
use diesel::r2d2::ConnectionManager;

type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

pub fn fetch_all_secrets(connection: &DbConnection)
    -> Result<Option<Vec<Secret>>, Error >{
    use schema::secrets::dsl::*;
    let results = secrets
        .limit(100)
        .load::<Secret>(connection)
        .optional()?;
    Ok(results)
}

pub fn insert_secret(connection: &DbConnection, secret: &Secret)
                     -> Result<Secret, Error> {
    let secret = diesel::insert_into(secrets::table)
        .values(secret)
        .get_result(connection)?;
    Ok(secret)
}

pub fn insert_secrets(connection: &DbConnection, secrets: Vec<&Secret>)
    -> Result<Vec<Secret>, Error > {
    unimplemented!()
}

pub fn find_secret_by_id(connection: &DbConnection, id: i32)
    -> Result<Option<Secret>, Error> {
    unimplemented!()
}

pub fn find_secret_by_name(connection: &DbConnection, name: String)
    -> Result<Option<Secret>, Error>{
    unimplemented!()
}

pub fn update_secret_by_id(connection: &DbConnection, id: i32)
    -> Result<Option<Secret>, Error> {
    unimplemented!()
}

pub fn delete_secret_by_id(connection: &DbConnection, id: i32)
    -> Result<Option<bool>, Error> {
    unimplemented!()
}
