use serde::{Serialize, Deserialize};
use super::schema::secrets;

// secrets

#[derive(Queryable, Insertable, Serialize)]  //TODO write custom serializer to drop 'id' field -> client should never be aware of DB id
pub struct Secret {
    pub id: i32,
    pub client_id: i32,
    pub name: String,
    pub content: String,
    pub url: Option<String>
}

#[derive(Queryable, Insertable, AsChangeset, Deserialize)]
#[table_name="secrets"]
pub struct NewSecret {
    pub client_id: i32,
    pub name: String,
    pub content: String,
    pub url: Option<String>
}

// user-management

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub id: u32,
    pub last_name: String,
    pub first_name: String,
    pub email: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Identity {
    pub token: String,
    pub user: User
}



