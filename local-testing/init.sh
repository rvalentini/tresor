#!/bin/bash

echo "Building tresor-backend image..."
../docker/build-docker.sh

echo "Building Postgres migration image based on diesel-CLI"
sudo docker build --tag diesel-migration ./diesel-cli/

echo "Launching services..."
# Clear Postgres data -> /nothing is mapped to /var/lib/postgresql/data
# this ensures that each compose up produces a fresh DB
sudo rm -r -f ./nothing
docker-compose rm -f
docker-compose up




