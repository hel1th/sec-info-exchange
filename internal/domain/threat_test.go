package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewThreatNormalizesAndOwnsTags(t *testing.T) {
	tags := []string{" malware "}
	now := time.Now()
	entity, err := NewThreat(strings.Repeat("A", 32), ThreatData{Name: " Trojan ", Severity: SeverityHigh, Tags: tags}, now)
	if err != nil {
		t.Fatal(err)
	}
	tags[0] = "changed"
	if entity.MD5 != strings.Repeat("a", 32) || entity.Name != "Trojan" || entity.Tags[0] != "malware" {
		t.Fatalf("unexpected normalized entity: %+v", entity)
	}
	if !entity.CreatedAt.Equal(now) || !entity.UpdatedAt.Equal(now) {
		t.Fatal("timestamps differ from supplied time")
	}
}

func TestNewThreatRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ThreatData)
	}{
		{"empty name", func(d *ThreatData) { d.Name = "  " }},
		{"long name", func(d *ThreatData) { d.Name = strings.Repeat("я", 256) }},
		{"invalid utf8", func(d *ThreatData) { d.Description = string([]byte{0xff}) }},
		{"long description", func(d *ThreatData) { d.Description = strings.Repeat("a", 4097) }},
		{"severity", func(d *ThreatData) { d.Severity = "unknown" }},
		{"duplicate normalized tags", func(d *ThreatData) { d.Tags = []string{"a", " a "} }},
		{"empty tag", func(d *ThreatData) { d.Tags = []string{" "} }},
		{"long tag", func(d *ThreatData) { d.Tags = []string{strings.Repeat("a", 65)} }},
		{"too many tags", func(d *ThreatData) { d.Tags = make([]string, 21) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ThreatData{Name: "Trojan", Severity: SeverityHigh}
			tc.change(&d)
			_, err := NewThreat(strings.Repeat("a", 32), d, time.Now())
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected ErrInvalid, got %v", err)
			}
		})
	}
}

func TestThreatIdentifierAndTimeInvariants(t *testing.T) {
	d := ThreatData{Name: strings.Repeat("я", 255), Severity: SeverityLow}
	for _, id := range []string{"", strings.Repeat("a", 31), strings.Repeat("g", 32)} {
		if _, err := NewThreat(id, d, time.Now()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted invalid MD5 %q", id)
		}
	}
	if _, err := NewThreat(strings.Repeat("a", 32), d, time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("accepted zero time")
	}
	entity, err := NewThreat(strings.Repeat("a", 32), d, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	entity.UpdatedAt = entity.CreatedAt.Add(-time.Second)
	if !errors.Is(entity.Validate(), ErrInvalid) {
		t.Fatal("accepted update before creation")
	}
}
