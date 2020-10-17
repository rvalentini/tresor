use serde::{Serialize, Deserialize};
use super::schema::secrets;

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

