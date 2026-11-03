# Information Exchange Service

API для обмена информацией об угрозах на Go с PostgreSQL и маршрутизацией chi.
Реализованы `GET /info/{md5}`, `POST /info`, `PUT /info/{md5}`, `GET /healthz` и `GET /readyz`.

## Запуск

Скопируйте `.env.example` в `.env` и задайте ключи `API_READER_KEY`/`API_WRITER_KEY`

```sh
docker compose up --build -d
docker compose ps
docker compose logs -f api
```

API доступен по адресу `http://localhost:8080`. Публичные проверки состояния:
`http://localhost:8080/healthz` и `http://localhost:8080/readyz`.

Встроенные goose-миграции применяются автоматически перед запуском HTTP,
с учётом версий и PostgreSQL advisory lock. Ожидание БД и миграций ограничено
одной минутой. При ошибке сервер не запускается. Данные сохраняются в named volume.

Остановка с сохранением данных:

```sh
docker compose down
```

## Проверки и генерация

```sh
docker compose build api
docker compose run --rm tools go vet ./...
docker compose run --rm tools go test ./...
docker compose run --rm tools go test -race ./...
docker compose run --rm lint
docker compose run --rm lint golangci-lint fmt --config .golangci.yaml
docker compose run --rm tools go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.1 --config oapi-codegen.yaml openapi.yaml
```

## Интеграционные тесты PostgreSQL

```sh
docker compose run --rm integration
```

Команда запускает БД, ждёт её готовности и передаёт `TEST_DATABASE_URL` тестам.
Обычный запуск тестов через tools пропускает тесты БД. Каждый интеграционный тест
создаёт случайную схему и удаляет только её. Пользователю нужны права `CREATE SCHEMA`.
Проверяются миграции, конкурентное создание, чтение, обновление и отмена контекста.

## Makefile

GNU Make необязателен: цели вызывают те же Docker Compose команды.

| Цель | Действие |
| --- | --- |
| `make run` / `make up` | Собрать и запустить API и БД в фоне |
| `make down` | Остановить сервисы с сохранением данных |
| `make logs` | Следить за логами API |
| `make build` | Собрать образ API |
| `make test` / `make test-race` | Запустить тесты / тесты с race detector |
| `make test-integration` | Запустить тесты с PostgreSQL |
| `make vet` / `make lint` | Выполнить статические проверки |
| `make fmt` / `make generate` | Форматировать код / генерировать DTO |
| `make check` | Собрать образ, выполнить тесты, vet и линтер |
| `make demo` | Проверить уже запущенный API |

API требует `X-API-Key`. Роли, лимиты и демонстрация описаны в
[docs/security.md](docs/security.md). CI настроен в `.github/workflows/ci.yml`.
