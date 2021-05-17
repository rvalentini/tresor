# Tresor

This is an example CRUD-application written in Rust that showcases how to use OpenID Connect authentication with Keycloak 
as identity provider.

Used technologies:

* [Actix-Web](https://github.com/actix/actix-web) as web framework 
* [Diesel](https://diesel.rs/) crate for Postgres operations
* [openidconnect-rs](https://github.com/ramosbugs/openidconnect-rs) for OpenID Connect protocol implementation
* [Keycloak](https://www.keycloak.org/) as identity provider

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

All routes except `/login` and `/testlogin` return a Httpstatus `401 - Unauthorized` by default without valid user login. 

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

## Local test setup (docker-compose)

Inside the directory `local-testing` you will a preconfigured test setup that includes all three applications:
1) `Tresor backend`
2) `Postgres`
3) `Keycloak`

The only thing you have to do for setup is to run 
```
./init.sh
```
This will start all three applications in a Docker environment.
Available endpoints after statup are:
1) Tresor backend: `127.0.0.1:8084`
2) Postgres: `127.0.0.1:5432`
1) Keycloak: `127.0.0.1:8080`

The admin console login for <b>Keycloak</b> is
```
user: admin
password: aintsecure
```
There is a user for the realm `tresor` preconfigured, which you can use for the Tresor login via `127.0.0.1:8084/login`:
```
user: holger@tresor.de
password: aintsecure
```

Note: The `/testlogin` route is also available in the docker-compose setup, so you can also use Postman (see the `postman` directory for a configuration file)
to test the routes. When using `/testlogin` you are logged in as a different test-user. This works completely without Keycloak.

Note: State changes of <b>Postgres</b> and <b>Keycloak</b> are currently <b>NOT</b> persisted. Everytime you run `./init.sh` you will end up with the same, fresh test setup.


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

#### Setup keycloak
```
docker run -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=password --name tresor-keycloak -p 8080:8080 jboss/keycloak
```

Manual steps used for the local-tests setup:
```
1) create new client "tresor-backend"
1.1) set valid re-direct url http://127.0.0.1:8084/*
2) add client scope "tresor"
3) for each custom user field add a new mapper to the client scope
    * mapper type == user attribute (NOT property!!!)
    * claim JSON type == String
4) add user 
5) set a non temporary password for the user
6) add attributes to the user e.g. tresor_id, tresor_role
7) add client scope "tresor" to client (to "Assigned Default Client Scopes")
```


#### Keycloak realm export
The Keycloak realm export is only necessary for the docker-compose environment configuration. The whole realm `tresor` is exported as JSON
and can be injected then during docker-compose init.

1) Start a Keycloak docker instance that has the `/tmp` directory mounted to the host machine - this will be used for the JSON export
```
# The docker container must have a volume mapping to access the exports in the end
docker run -d -p 8080:8080 -e KEYCLOAK_USER=admin -e \
KEYCLOAK_PASSWORD=admin -v $(pwd):/tmp --name kc \
jboss/keycloak
```
2) Configure the Keycloak instance manually the way you want it.
3) Run the following command so the whole real is exported as JSON file.
```
# Execute this command to create a new JSON file containing the complete real export in the mounted directory
docker exec -it kc /opt/jboss/keycloak/bin/standalone.sh \
-Djboss.socket.binding.port-offset=100 -Dkeycloak.migration.action=export \
-Dkeycloak.migration.provider=singleFile \
-Dkeycloak.migration.realmName=tresor \
-Dkeycloak.migration.usersExportStrategy=REALM_FILE \
-Dkeycloak.migration.file=/tmp/tresor.json
```

