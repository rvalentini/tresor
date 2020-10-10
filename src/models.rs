use serde::{Serialize, Deserialize};
use super::schema::secrets;

#[derive(Queryable, Insertable, Serialize, Deserialize)]
#[table_name="secrets"]
pub struct Secret {
    pub id: i32,
    pub name: String,
    pub content: String,
    pub url: Option<String>
}

