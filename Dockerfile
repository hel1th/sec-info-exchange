FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
RUN CGO_ENABLED=0 go build -trimpath -o /server ./cmd/server

FROM scratch
COPY --from=build /server /server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]
