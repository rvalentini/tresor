use serde::{Serialize, Deserialize};
use super::schema::secrets;
use openidconnect::{PkceCodeVerifier, Nonce, CsrfToken};
use std::fmt;
use serde::export::Formatter;

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
    pub id: String,
    pub tresor_id: String,
    pub tresor_role: Role,
    pub email: String
}

#[derive(Serialize, Deserialize, Debug)]
pub enum  Role {
    Admin,
    User
}

impl Role {
    pub fn from_string(role: &str) -> Result<Role, UnknownRoleError> {
        match role {
            "admin" => Ok(Role::Admin),
            "user" => Ok(Role::User),
            _ => Err(UnknownRoleError::new(role))
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Identity {
    pub user: User
}

// OpenID Connect

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenIdConnectState {
    pub pkce_verifier: PkceCodeVerifier,
    pub csrf_token: CsrfToken,
    pub nonce: Nonce
}

#[derive(Deserialize, Debug)]
pub struct OpCallback {
    pub state: String,
    pub session_state: String,
    pub code: String
}

// Error types

#[derive(Debug)]
pub struct UnknownRoleError {
    description: String
}

impl UnknownRoleError {
    fn new(unknown_role: &str) -> Self {
        UnknownRoleError {
            description: format!("The role '{}' is not defined", unknown_role) }
    }
}

impl fmt::Display for UnknownRoleError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}


