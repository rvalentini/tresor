# tresor-backend

Backend web-server application for secrets storage

## Build dependencies

For Ubuntu
```
sudo apt install libssl-dev libpq-dev
```

## Usage

Run Tresor Backend application locally (see local test setup first)
```
cargo run release
``` 
Note: Authentication via KeyCloak is activated by default. For testing purposes, it might make sense to disable
the authentication. This can be achieved by running the Tresor Backend with the following `ENV` variable set:
```
TRESOR_BACKEND_RUNMODE=debug
```
This will enable the `/testlogin` endpoint for an easy authentication. Technically it does not disable
the authentication, but makes it very easy to just sign in as a test user.

Note: application will be reachable on port `8084` by default

## Routes

All routes except `/login` and `/testlogin` return a Httpstatus `401 - Unauthorized` by default. 

* `GET /login` performs an OpenId Connect authentication (Authentication Flow) via KeyCloak
* `GET /testlogin` performs an automatic test-user login without credentials. 
  Note: this endpoint is only available when the Tresor Backend is started in `debug` run mode.  
* `GET /logout` performs logout operation (Keycloak & Cookie-Session state)
* `GET /whoami` fetches the user's identity attributes as stored in KeyCloak 
* `GET /secrets` fetches all the secrets 
* `GET /secret/{id}` fetches the secret with given `id` 
* `PUT /secret/` stores the secret with given `id` - on success, returns the secret together with the `id` 
* `DELETE /secret/{id}` deletes the secret with given `id` 


Note: the directory /postman contains a collection of Postman request for easy testing
## Configuration

TODO

## Local test setup (manual)

The tresor-backend application relies on two other services:
1) `Postgres` instance for secrets storage
2) `Keycloak` for authentication via OpenId Connect 

The following manual explains how to setup a local testing environment containing the two applications.


### 1) Postgres
Spin up a local Postgres instance by running
```
docker run --name tresor-postgres -p 5432:5432 -e POSTGRES_PASSWORD=aintsecure -d postgres
```
Note: default user is `postgres`

Setup tresor database


This project uses the `Diesel` crate for all Postgres interactions. 
The database setup for the tresor-backend application can be done via the Diesel CLI.
(see http://diesel.rs/guides/getting-started/ for details).

The directory `/migrations` contains all SQL migrations scripts necessary for the setup.

Install Diesel CLI first:
```
cargo install diesel_cli

```
Run migration
```
diesel migration run --database-url postgres://postgres:aintsecure@localhost/tresor
```
### 2) Keycloak

Setup keycloak
```
docker run -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=password --name tresor-keycloak -p 8080:8080 jboss/keycloak
```
TODO document manual steps within KeyCloak

## Local test setup (docker-compose)

TODO Postres & KeyCloak scripted
