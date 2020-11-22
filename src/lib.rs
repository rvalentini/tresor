#[macro_use]
extern crate diesel;

pub mod schema;
pub mod models;

use models::*;
use diesel::prelude::*;
use diesel::result::Error;
use diesel::{insert_into, update, delete};
use r2d2::PooledConnection;
use diesel::r2d2::ConnectionManager;

type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

pub fn find_all_secrets(connection: &DbConnection, identity: Identity)
                        -> Result<Vec<Secret>, Error> {
    use schema::secrets::dsl::*;
    use schema::user_secret::dsl::*;
    user_secret.inner_join(secrets)
        .filter(user_id.eq(&identity.user.id))
        .select((id, client_side_id, name, content, url))
        .load::<Secret>(connection)  //TODO does this "cast" work?
}

pub fn is_owner_of_secret(connection: &DbConnection, identity: Identity, client_side_id: &str)
                          -> Result<bool, Error> {
    use schema::user_secret::dsl::*;
    user_secret
        .filter(secret_id_client_side.eq(client_side_id))
        .filter(user_id.eq(&identity.user.id))
        .first(connection)
        .optional()
        .map(|res: Option<UserSecret>| match res {
            Some(_) => true,
            None => false
        })
}

pub fn insert_secret(connection: &DbConnection, identity: Identity, secret: &NewSecret)
                     -> Result<Secret, Error> {
    use schema::secrets::dsl::*;
    use schema::user_secret::dsl::*;
    connection.transaction::<Secret, _, _>(|| {
        let inserted_sec =
            insert_into(secrets)
                .values(secret)
                .get_result::<Secret>(connection)?;
        let user_secret_entry = UserSecret {
            user_id: identity.user.id,
            secret_id: inserted_sec.id,
            secret_id_client_side: secret.client_side_id.clone(),
        };
        insert_into(user_secret)
            .values(user_secret_entry)
            .get_result::<UserSecret>(connection)?;
        Ok(inserted_sec)
    })
}

pub fn find_secret_by_client_side_id(connection: &DbConnection, sec_id: &str)
                                     -> Result<Option<Secret>, Error> {
    use schema::secrets::dsl::*;
    secrets
        .filter(client_side_id.eq(sec_id))
        .first(connection)
        .optional()
}


//TODO methods below not used yet
pub fn find_secret_by_name(connection: &DbConnection, sec_name: &String)
                           -> Result<Option<Secret>, Error> {
    use schema::secrets::dsl::*;
    secrets
        .filter(name.eq(sec_name))
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

pub fn delete_secret_by_client_side_id(connection: &DbConnection, sec_id: &String)
                                       -> Result<Option<usize>, Error> {
    use schema::secrets::dsl::*;
    delete(secrets
        .filter(client_side_id.eq(sec_id)))
        .execute(connection)
        .optional()
}

//TODO delete all secrets for user
//TODO find all secrets for user
//TODO find all users for secret
//TODO get id for client_id (user_id + client_id -> id) - necessary for delete/update/find_secret_by_id

