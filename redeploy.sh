#!/bin/sh

CONTAINER_NAME="battlebit-telemetry"

git pull
docker build -t bbtel .

docker rm -f "$CONTAINER_NAME"
docker run -d --name "$CONTAINER_NAME" -p 65500:65500 -p 65501:65501 bbtel -verbose
docker logs -f "$CONTAINER_NAME"