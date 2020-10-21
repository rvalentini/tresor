#!/bin/bash

pushd ..
#building for alpine linux with target musl
sudo docker run --rm -it -v "$(pwd)":/home/rust/src ekidd/rust-musl-builder cargo build --release
cp target/x86_64-unknown-linux-musl/release/tresor_backend docker/tresor_backend
cp -R config/ docker/config
popd || exit
sudo docker build --tag tresor_backend .
rm ./tresor_backend
rm -R ./config