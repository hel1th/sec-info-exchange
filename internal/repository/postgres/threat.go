// Package postgres implements usecase.Repository using PostgreSQL and pgx.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hel1th/sec-info-exchange/internal/domain"
	"github.com/hel1th/sec-info-exchange/internal/usecase"
)

const columns = "md5, name, description, severity, tags, created_at, updated_at"

// Repository persists threats in PostgreSQL.
type Repository struct{ pool *pgxpool.Pool }

var _ usecase.Repository = (*Repository)(nil)

// New creates a repository using the application's connection pool.
func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

// Create atomically inserts a threat; the primary key enforces uniqueness.
func (r *Repository) Create(ctx context.Context, t domain.Threat) (domain.Threat, error) {
	row := r.pool.QueryRow(ctx, `INSERT INTO threats (`+columns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+columns,
		t.MD5, t.Name, t.Description, string(t.Severity), t.Tags, t.CreatedAt, t.UpdatedAt)
	return scanThreat(row)
}

// Get retrieves a threat by its canonical MD5.
func (r *Repository) Get(ctx context.Context, md5 string) (domain.Threat, error) {
	return scanThreat(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM threats WHERE md5 = $1`, md5))
}

// Update replaces mutable fields while preserving the identifier and creation time.
func (r *Repository) Update(
	ctx context.Context, md5 string, data domain.ThreatData, now time.Time,
) (domain.Threat, error) {
	row := r.pool.QueryRow(ctx, `UPDATE threats SET name=$2, description=$3, severity=$4,
		tags=$5, updated_at=GREATEST($6, created_at, updated_at) WHERE md5=$1 RETURNING `+columns,
		md5, data.Name, data.Description, string(data.Severity), data.Tags, now)
	return scanThreat(row)
}

func scanThreat(row pgx.Row) (domain.Threat, error) {
	var t domain.Threat
	var severity string
	err := row.Scan(&t.MD5, &t.Name, &t.Description, &severity, &t.Tags, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Threat{}, usecase.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "threats_pkey" {
		return domain.Threat{}, usecase.ErrConflict
	}
	if err != nil {
		return domain.Threat{}, fmt.Errorf("query threat: %w", err)
	}
	t.Severity = domain.Severity(severity)
	return t, nil
}
