# tresor-backend

Backend web-server application for secrets storage

## Build dependencies

For Ubuntu
```
sudo apt install libssl-dev libpq-dev
```

## Usage

Run Tresor backend application locally (see local testing first)
```
cargo run 
``` 

Note: application will be reachable on port `8084` by default

### Routes

`GET /secrets` fetches all the secrets :) 


`PUT /secret` creates a new secret


## Configuration

TODO

## Local testing

The tresor-backend application relies on two other services:
1) Postgres instance for secrets storage
2) Keycloak for authentication

The following manual explains how to setup a local testing environment.

### Manual

#### 1) Postgres
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
#### 2) Keycloak

Setup keycloak
```
docker run -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=password --name tresor-keycloak -p 8080:8080 jboss/keycloak
```
TODO Configure Keycloak

### Docker-compose

TODO
