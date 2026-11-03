-- +goose Up
-- +goose StatementBegin
CREATE TABLE threats (
    md5 text PRIMARY KEY CHECK (md5 ~ '^[a-f0-9]{32}$'),
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 255),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 4096),
    severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    tags text[] NOT NULL DEFAULT '{}' CHECK (cardinality(tags) <= 20),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
-- TODO index
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS threats;
-- +goose StatementEnd
