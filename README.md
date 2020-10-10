# tresor-backend

Backend web-server application for secrets storage

## Usage

Run Tresor backend application locally 
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


### Docker-compose

TODO