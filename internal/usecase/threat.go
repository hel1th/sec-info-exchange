package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/hel1th/sec-info-exchange/internal/domain"
)

// ThreatService implements threat operations using the consumer-owned repository contract.
type ThreatService struct {
	repo Repository
	now  func() time.Time
}

// NewThreatService creates a service backed by repo.
func NewThreatService(repo Repository) *ThreatService {
	return &ThreatService{repo: repo, now: time.Now}
}

// Create validates and normalizes an entity before persistence.
func (s *ThreatService) Create(ctx context.Context, in CreateThreatInput) (CreateThreatOutput, error) {
	t, err := domain.NewThreat(in.MD5, toDomainData(in.Data), s.now())
	if err != nil {
		return CreateThreatOutput{}, err
	}
	created, err := s.repo.Create(ctx, t)
	if err != nil {
		return CreateThreatOutput{}, fmt.Errorf("create threat: %w", err)
	}
	return CreateThreatOutput(toThreatOutput(created)), nil
}

// Get resolves a threat by its canonical MD5.
func (s *ThreatService) Get(ctx context.Context, in GetThreatInput) (GetThreatOutput, error) {
	id, err := domain.NormalizeMD5(in.MD5)
	if err != nil {
		return GetThreatOutput{}, err
	}
	t, err := s.repo.Get(ctx, id)
	if err != nil {
		return GetThreatOutput{}, fmt.Errorf("get threat: %w", err)
	}
	return GetThreatOutput(toThreatOutput(t)), nil
}

// Update replaces all mutable attributes; omitted optional fields are cleared.
func (s *ThreatService) Update(ctx context.Context, in UpdateThreatInput) (UpdateThreatOutput, error) {
	id, err := domain.NormalizeMD5(in.MD5)
	if err != nil {
		return UpdateThreatOutput{}, err
	}
	data, err := toDomainData(in.Data).Normalized()
	if err != nil {
		return UpdateThreatOutput{}, err
	}
	t, err := s.repo.Update(ctx, id, data, s.now().UTC())
	if err != nil {
		return UpdateThreatOutput{}, fmt.Errorf("update threat: %w", err)
	}
	return UpdateThreatOutput(toThreatOutput(t)), nil
}
