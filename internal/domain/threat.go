// Package domain contains threat entities and their invariants.
package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrInvalid identifies a violated domain invariant.
var ErrInvalid = errors.New("invalid threat")

// Severity describes the impact of a threat.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ThreatData contains the replaceable attributes of a threat.
type ThreatData struct {
	Name        string
	Description string
	Severity    Severity
	Tags        []string
}

// Normalized returns a validated copy with trimmed name and tags.
// The returned tags do not share storage with the input.
func (d ThreatData) Normalized() (ThreatData, error) {
	d.Name = strings.TrimSpace(d.Name)
	tags := make([]string, len(d.Tags))
	for i, tag := range d.Tags {
		tags[i] = strings.TrimSpace(tag)
	}
	d.Tags = tags
	if err := d.Validate(); err != nil {
		return ThreatData{}, err
	}
	return d, nil
}

// Validate checks attributes without changing them. Lengths are Unicode code points.
func (d ThreatData) Validate() error {
	if !utf8.ValidString(d.Name) || strings.TrimSpace(d.Name) == "" || utf8.RuneCountInString(d.Name) > 255 {
		return fmt.Errorf("%w: name must contain 1–255 characters", ErrInvalid)
	}
	if !utf8.ValidString(d.Description) || utf8.RuneCountInString(d.Description) > 4096 {
		return fmt.Errorf("%w: description must contain at most 4096 characters", ErrInvalid)
	}

	switch d.Severity {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
	default:
		return fmt.Errorf("%w: unknown severity", ErrInvalid)
	}

	if len(d.Tags) > 20 {
		return fmt.Errorf("%w: at most 20 tags allowed", ErrInvalid)
	}

	seen := make(map[string]struct{}, len(d.Tags))
	for _, tag := range d.Tags {
		if !utf8.ValidString(tag) || strings.TrimSpace(tag) == "" || utf8.RuneCountInString(tag) > 64 {
			return fmt.Errorf("%w: tags must contain 1–64 characters", ErrInvalid)
		}
		if _, ok := seen[tag]; ok {
			return fmt.Errorf("%w: duplicate tag", ErrInvalid)
		}
		seen[tag] = struct{}{}
	}
	return nil
}

// NormalizeMD5 validates the identifier and returns its canonical lowercase form.
func NormalizeMD5(md5 string) (string, error) {
	if len(md5) != 32 {
		return "", fmt.Errorf("%w: MD5 must contain 32 hex characters", ErrInvalid)
	}
	for _, c := range md5 {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return "", fmt.Errorf("%w: MD5 must contain only hex characters", ErrInvalid)
		}
	}
	return strings.ToLower(md5), nil
}

// Threat is a domain entity, independent of transport and persistence formats.
// Call Validate at boundaries when constructing entities without NewThreat.
type Threat struct {
	MD5 string
	ThreatData
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewThreat normalizes input and creates a valid entity with server-provided time.
// It copies tags so subsequent changes to input do not change the entity.
func NewThreat(md5 string, data ThreatData, now time.Time) (Threat, error) {
	id, err := NormalizeMD5(md5)
	if err != nil {
		return Threat{}, err
	}
	data, err = data.Normalized()
	if err != nil {
		return Threat{}, err
	}

	t := Threat{
		MD5:        id,
		ThreatData: data,
		CreatedAt:  now.UTC(),
		UpdatedAt:  now.UTC(),
	}
	if err := t.Validate(); err != nil {
		return Threat{}, err
	}
	return t, nil
}

// Validate checks a complete entity, including canonical identifier and timestamps.
func (t Threat) Validate() error {
	id, err := NormalizeMD5(t.MD5)
	if err != nil {
		return err
	}
	if id != t.MD5 {
		return fmt.Errorf("%w: MD5 must be lowercase", ErrInvalid)
	}
	if err := t.ThreatData.Validate(); err != nil {
		return err
	}
	if t.CreatedAt.IsZero() || t.UpdatedAt.IsZero() || t.UpdatedAt.Before(t.CreatedAt) {
		return fmt.Errorf("%w: invalid timestamps", ErrInvalid)
	}
	return nil
}
