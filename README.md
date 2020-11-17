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
### Manual
Spin up a local Postgres instance by running
```
docker run --name tresor-postgres -p 5432:5432 -e POSTGRES_PASSWORD=aintsecure -d postgres
```
Note: default user is `postgres`

Setup tresor database
```
$ docker exec -it tresor-postgres bash
root@2934e699b4d7:/# su - postgres
postgres@2934e699b4d7:~$ psql
psql (12.3 (Debian 12.3-1.pgdg100+1))
Type "help" for help.
postgres=# create database tresor;
CREATE DATABASE
postgres=# \q
postgres@2934e699b4d7:~$ exit
logout
root@2934e699b4d7:/# exit
exit
```

Setup keycloak
```
docker run -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=password --name tresor-keycloak -p 8080:8080 jboss/keycloak
```


### Docker-compose

TODO