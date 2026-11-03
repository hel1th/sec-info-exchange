// Package usecase defines application operations and the dependencies they consume.
package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/hel1th/sec-info-exchange/internal/domain"
)

var (
	ErrNotFound = errors.New("threat not found")
	ErrConflict = errors.New("threat already exists")
)

// Repository is the persistence contract consumed by threat use cases.
// Implementations return ErrNotFound for missing records and ErrConflict for
// duplicate MD5 values. Update replaces attributes and updated_at atomically,
// preserving md5 and created_at. Inputs must satisfy domain invariants.
type Repository interface {
	Create(context.Context, domain.Threat) (domain.Threat, error)
	Get(context.Context, string) (domain.Threat, error)
	Update(context.Context, string, domain.ThreatData, time.Time) (domain.Threat, error)
}
