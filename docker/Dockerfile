FROM alpine

RUN apk update
RUN apk add bash

COPY ./tresor_backend ./tresor_backend
COPY ./config ./config
COPY ./wait-for-it.sh ./wait-for-it.sh

ENV TRESOR_SERVER_INTERFACE=0.0.0.0
ENV TRESOR_SERVER_PORT=8084
ENV TRESOR_LOGGING_LEVEL=info

ENTRYPOINT ./tresor_backend
EXPOSE 8084
