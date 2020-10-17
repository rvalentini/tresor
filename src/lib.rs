#[macro_use]
extern crate diesel;

pub mod schema;
pub mod models;

use schema::*;
use models::*;
use diesel::prelude::*;
use diesel::result::Error;
use diesel::{insert_into, update, delete};
use r2d2::PooledConnection;
use diesel::r2d2::ConnectionManager;

type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

//TODO make this "find all secrets for user"
pub fn find_all_secrets(connection: &DbConnection)
                        -> Result<Vec<Secret>, Error> {
    use schema::secrets::dsl::*;
    secrets
        .limit(100)
        .load::<Secret>(connection)
}

pub fn insert(connection: &DbConnection, secret: &NewSecret)
                               -> Result<Secret, Error> {
    use schema::secrets::dsl::*;
    insert_into(secrets)
        .values(secret)
        .get_result(connection)
}

//TODO necessary? when?
pub fn insert_or_update_secret(connection: &DbConnection, secret: &NewSecret)
                               -> Result<Secret, Error> {
    use schema::secrets::dsl::*;
    insert_into(secrets)
        .values(secret)
        .on_conflict(client_id)
        .do_update()
        .set(secret)
        .get_result(connection)
}

pub fn insert_all_secrets(connection: &DbConnection, secrets: Vec<&NewSecret>)
                          -> Result<Vec<Secret>, Error> {
    insert_into(secrets::table)
        .values(secrets)
        .get_results(connection)
}

pub fn find_secret_by_id(connection: &DbConnection, sec_id: i32)
                         -> Result<Option<Secret>, Error> {
    use schema::secrets::dsl::*;
    secrets
        .find(sec_id)
        .first(connection)
        .optional()
}

pub fn find_secret_by_name(connection: &DbConnection, sec_name: &String)
                           -> Result<Option<Secret>, Error> {
    use schema::secrets::dsl::*;
    secrets.filter(name.eq(sec_name))
        .first(connection)
        .optional()

}

pub fn update_secret_by_id(connection: &DbConnection, sec_id: i32, secret: &NewSecret)
                           -> Result<Option<Secret>, Error> {
    use schema::secrets::dsl::*;
    update(secrets.find(sec_id))
        .set(secret)
        .get_result::<Secret>(connection)
        .optional()
}

pub fn delete_secret_by_id(connection: &DbConnection, sec_id: i32)
                           -> Result<Option<usize>, Error> {
    use schema::secrets::dsl::*;
    delete(secrets.find(sec_id))
        .execute(connection)
        .optional()
}

//TODO delete all secrets for user
//TODO find all secrets for user
//TODO find all users for secret
//TODO get id for client_id (user_id + client_id -> id) - necessary for delete/update/find_secret_by_id

