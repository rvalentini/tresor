use actix_session::Session;
use actix_web::{web, get, HttpResponse, Error};
use openidconnect::{PkceCodeChallenge, CsrfToken, Nonce, Scope, AuthorizationCode, AsyncCodeTokenRequest, AccessTokenHash};
use openidconnect::core::CoreAuthenticationFlow;
use openidconnect::reqwest::async_http_client;
use oauth2::TokenResponse;
use crate::{AppState, IDENTITY_SESSION_KEY};
use crate::error::{OIDCError, SessionError};
use crate::models::{OpenIdConnectState, Identity, OpCallback, Role, User};

const OIDC_SESSION_KEY: &str = "oidc_state";

#[get("/login")]
pub async fn login(session: Session, data: web::Data<AppState>) -> Result<HttpResponse, Error> {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = data.oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random)
        .add_scope(Scope::new(data.settings.auth.scope.clone()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let oidc_state = OpenIdConnectState {
        pkce_verifier,
        csrf_token,
        nonce,
    };

    session.set(OIDC_SESSION_KEY, &oidc_state)
        .map_err(|_| SessionError::WriteSessionError("unknown".to_string()))?;

    //redirect to OpenIdProvider for authentication
    Ok(HttpResponse::SeeOther().header("Location", auth_url.as_str()).finish())
}

#[get("/callback")]
pub async fn callback(session: Session, data: web::Data<AppState>, authorization_info: web::Query<OpCallback>) -> Result<HttpResponse, Error> {
    if let Some(oidc_state) = session.get::<OpenIdConnectState>(OIDC_SESSION_KEY)? {
        let token_response = data.oidc_client.exchange_code(
            AuthorizationCode::new(authorization_info.into_inner().code.to_string())
        ).set_pkce_verifier(oidc_state.pkce_verifier)
            .request_async(async_http_client)
            .await
            .map_err(|_| OIDCError::ExchangeTokenError)?;

        let id_token = token_response.extra_fields().id_token()
            .ok_or_else(|| OIDCError::EmptyIdTokenError)?;

        let claims = id_token.claims(
            &data.oidc_client.id_token_verifier(),
            &oidc_state.nonce)
            .map_err(|err| {
                println!("Error is: {:?}", err);
                OIDCError::ClaimsVerificationError //TODO check what exactly happens here / which error is thrown
            })?;
        match claims.access_token_hash() {
            None => { Err(OIDCError::MissingTokenHashError) }
            Some(given_token_hash) => {
                let calculated_token_hash = AccessTokenHash::from_token(
                    token_response.access_token(),
                    &id_token.signing_alg().map_err(|_| OIDCError::SigningError)?,
                ).map_err(|_| OIDCError::SigningError)?;

                if calculated_token_hash != *given_token_hash {
                    Err(OIDCError::AccessTokenVerificationError)
                } else {
                    Ok(())
                }
            }
        }?;

        let user_id = claims.subject().to_string();

        if let (Some(id), Some(role), Some(mail)) =
        (&claims.additional_claims().tresor_id,
         &claims.additional_claims().tresor_role,
         &claims.email().map(|mail| mail.as_str())) {
            let role = Role::from_string(role)?;
            let identity = Identity {
                user: User {
                    id: user_id.clone(),
                    tresor_id: id.to_string(),
                    tresor_role: role,
                    email: mail.to_string(),
                },
            };
            session.set(IDENTITY_SESSION_KEY, identity)
                .map_err(|_| SessionError::WriteSessionError(user_id.clone()))?;
        } else {
            return Err(Error::from(OIDCError::ClaimsContentError(user_id.clone())));
        }
        session.remove(OIDC_SESSION_KEY);
        info!("Successfully authenticated user {}", &user_id);
    } else {
        return Err(Error::from(OIDCError::CsrfStateError));
    }
    Ok(HttpResponse::Ok().body("Success"))
}

#[get("/testlogin")]
pub async fn test_login(session: Session, data: web::Data<AppState>) -> Result<HttpResponse, Error> {
    if data.settings.auth.enabletestlogin {
        let user_id = "this_is_a_test_user_id".to_string();
        let identity = Identity {
            user: User {
                id: user_id.clone(),
                tresor_id: "1000".to_string(),
                tresor_role: Role::User,
                email: "test.user@some-service.com".to_string(),
            },
        };
        session.set(IDENTITY_SESSION_KEY, identity)
            .map_err(|_| SessionError::WriteSessionError(user_id.clone()))?;
        Ok(HttpResponse::Ok().body("Success"))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[get("/logout")]
pub async fn logout(session: Session, data: web::Data<AppState>) -> Result<HttpResponse, Error> {
    if let Some(identity) = session.get::<Identity>(IDENTITY_SESSION_KEY)
        .map_err(|_| SessionError::ReadSessionError("unknown".to_string()))? {
        info!("Clearing Tresor session for user {}", &identity.user.id);
        session.purge();
        info!("Redirecting to OpenID Connect Provider for session logout");
        Ok(HttpResponse::SeeOther().header("Location", format!("{}/protocol/openid-connect/logout?redirect_uri=http://{}:{}/login",
                                                               &data.settings.build_issuer_redirect_url(),
                                                               &data.settings.server.redirecthost,
                                                               &data.settings.server.port)).finish())
    } else {
        warn!("/logout called without valid session information");
        Ok(HttpResponse::Unauthorized().finish())
    }
}

