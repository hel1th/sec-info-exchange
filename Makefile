OAPI_CODEGEN_VERSION := v2.8.1
COMPOSE := docker compose
TOOLS := $(COMPOSE) run --rm tools

.PHONY: run up down logs generate lint fmt build test vet check demo test-race test-integration

run: up

up:
	$(COMPOSE) up --build -d

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f api

generate:
	$(TOOLS) go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION) --config oapi-codegen.yaml openapi.yaml

lint:
	$(COMPOSE) run --rm lint

fmt:
	$(COMPOSE) run --rm lint golangci-lint fmt --config .golangci.yaml

build:
	$(COMPOSE) build api

test:
	$(TOOLS) go test ./...

vet:
	$(TOOLS) go vet ./...

check: build test vet lint

demo:
	$(TOOLS) go run ./cmd/demo

test-race:
	$(TOOLS) go test -race ./...

test-integration:
	$(COMPOSE) run --rm integration
