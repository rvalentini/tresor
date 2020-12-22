use serde::{Serialize, Deserialize};
use openidconnect::{PkceCodeVerifier, Nonce, CsrfToken};
use std::fmt;
use serde::export::Formatter;
use actix_web::{ResponseError, HttpResponse};
use uuid::Uuid;
use crate::schema::secrets;
use crate::schema::user_secret;

// database

#[derive(Queryable, Insertable, Serialize)]
pub struct Secret {
    #[serde(skip_serializing)]
    pub id: i32,
    pub client_side_id: String,
    pub name: String,
    pub content: String,
    pub url: Option<String>
}

#[derive(Queryable, Insertable, AsChangeset, Deserialize, Debug)]
#[table_name="secrets"]
pub struct NewSecret {
    #[serde(default = "random_uuid")]
    pub client_side_id: String,
    pub name: String,
    pub content: String,
    pub url: Option<String>
}

fn random_uuid() -> String {
    Uuid::new_v4().to_string()
}

#[derive(Queryable, Insertable, AsChangeset)]
#[table_name="user_secret"]
pub struct UserSecret {
    pub user_id: String,
    pub secret_id: i32,
    pub secret_id_client_side: String
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

//TODO this will become a enum sooner or later
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

impl ResponseError for UnknownRoleError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::InternalServerError().finish()
    }
}


impl fmt::Display for UnknownRoleError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}


