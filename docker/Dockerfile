FROM alpine

COPY ./tresor_backend ./tresor_backend
COPY ./config ./config

ENV TRESOR_SERVER_INTERFACE=0.0.0.0
ENV TRESOR_SERVER_PORT=8084
ENV TRESOR_LOGGING_LEVEL=info

ENTRYPOINT ./tresor_backend
EXPOSE 8084