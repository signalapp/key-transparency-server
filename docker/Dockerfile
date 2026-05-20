ARG GO_VERSION
FROM --platform=linux/amd64 golang:${GO_VERSION}-alpine AS build
COPY . /src
WORKDIR /src/cmd/kt-server
RUN go build

FROM --platform=linux/amd64 alpine:latest AS run
COPY --from=build /src/cmd/kt-server/kt-server /bin/kt-server
ENTRYPOINT ["/bin/kt-server"]
