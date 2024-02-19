FROM golang:1.21 AS build-env
COPY * /src
WORKDIR /src
RUN go install .
RUN go build -o /bin/eth2-val-tools

FROM debian:stable-slim
WORKDIR /app
COPY --from=build-env /bin/eth2-val-tools /app/
ENTRYPOINT ["./eth2-val-tools"]
