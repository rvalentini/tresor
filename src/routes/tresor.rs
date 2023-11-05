use actix_session::Session;
use actix_web::{HttpResponse, Error, web, get, put, delete};
use crate::models::{Identity, Secret, NewSecret};
use crate::{IDENTITY_SESSION_KEY, AppState};
use crate::database::{find_secret_by_client_side_id, is_owner_of_secret, delete_secret_by_client_side_id, find_all_secrets, insert_secret};
use crate::error::{DatabaseError, SessionError};

//TODO implement UPDATE for secret/secrets

#[get("/whoami")]
pub async fn whoami(session: Session) -> Result<HttpResponse, Error> {
    if let Some(identity) = session.get::<Identity>(IDENTITY_SESSION_KEY)
        .map_err(|_| SessionError::ReadSessionError("unknown".to_string()))? {
        Ok(HttpResponse::Ok().json(&identity.user))
    } else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}

#[get("/secret/{secret_id_client_side}")]
pub async fn get_secret(session: Session, data: web::Data<AppState>, secret_id_client_side: web::Path<String>) -> Result<HttpResponse, Error> {
    if let Some(identity) = session.get::<Identity>(IDENTITY_SESSION_KEY)? {
        let connection = data.connection_pool
            .get()
            .map_err(|_| DatabaseError::ConnectionError)?;

        let maybe_secret: Option<Secret> = web::block(move || {
            if is_owner_of_secret(&connection, identity, &secret_id_client_side)? {
                if let Some(secret) = find_secret_by_client_side_id(&connection, &secret_id_client_side)? {
                    return Ok(Some(secret));
                }
            }
            Ok(None)
        }).await
            .map_err(|_| DatabaseError::ExecutionError)?
            .map_err(DatabaseError::DieselOperationError)?;
        match maybe_secret {
            None => { Ok(HttpResponse::NotFound().body(format!("Requested secret does not exist"))) }
            Some(secret) => { Ok(HttpResponse::Ok().json(secret)) }
        }
    } else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}

#[get("/secrets")]
pub async fn get_secrets(session: Session, data: web::Data<AppState>) -> Result<HttpResponse, Error> {
    if let Some(identity) = session.get::<Identity>(IDENTITY_SESSION_KEY)? {
        let connection = data.connection_pool
            .get()
            .map_err(|_| DatabaseError::ConnectionError)?;

        //web::block() is used to offload the blocking DB operations without blocking the server thread.
        let secrets: Vec<Secret> = web::block(move || find_all_secrets(&connection, identity))
            .await
            .map_err(|_| DatabaseError::ExecutionError)?
            .map_err(DatabaseError::DieselOperationError)?;

        match secrets.as_slice() {
            [] => { Ok(HttpResponse::NotFound().body("No secrets found!")) }
            _ => { Ok(HttpResponse::Ok().json(secrets)) }
        }
    } else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}

#[put("/secret")]
pub async fn put_secret(session: Session, data: web::Data<AppState>, payload: web::Json<NewSecret>) -> Result<HttpResponse, Error> {
    if let Some(identity) = session.get::<Identity>(IDENTITY_SESSION_KEY)? {
        let connection = data.connection_pool
            .get()
            .map_err(|_| DatabaseError::ConnectionError)?;

        //web::block() is used to offload the blocking DB operations without blocking the server thread.
        let secret: Secret = web::block(move || insert_secret(&connection, identity, &payload))
            .await
            .map_err(|_| DatabaseError::ExecutionError)?
            .map_err(DatabaseError::DieselOperationError)?;
        Ok(HttpResponse::Ok().json(secret))
    } else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}


#[delete("/secret/{secret_id_client_side}")]
pub async fn delete_secret(session: Session, data: web::Data<AppState>, secret_id_client_side: web::Path<String>) -> Result<HttpResponse, Error> {
    if let Some(identity) = session.get::<Identity>(IDENTITY_SESSION_KEY)? {
        let connection = data.connection_pool
            .get()
            .map_err(|_| DatabaseError::ConnectionError)?;

        let delete_success: bool = web::block(move || {
            if is_owner_of_secret(&connection, identity, &secret_id_client_side)? {
                if let Some(_) = delete_secret_by_client_side_id(&connection, &secret_id_client_side)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }).await
        .map_err(|_| DatabaseError::ExecutionError)?
        .map_err(DatabaseError::DieselOperationError)?;
        match delete_success {
            false => { Ok(HttpResponse::NotFound().body(format!("Cannot delete, secret does not exist"))) }
            true => { Ok(HttpResponse::NoContent().finish()) }
        }
    } else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}


