package domain

import (
	"testing"
	"time"
)

func FuzzNewThreat(f *testing.F) {
	f.Add("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Trojan", "high", "tag")
	f.Add("invalid", "", "", "")
	f.Fuzz(func(t *testing.T, md5, name, severity, tag string) {
		entity, err := NewThreat(md5, ThreatData{Name: name, Severity: Severity(severity), Tags: []string{tag}},
			time.Unix(1, 0))
		if err != nil {
			return
		}
		if err = entity.Validate(); err != nil {
			t.Fatalf("constructor returned invalid entity: %v", err)
		}
		normalized, err := entity.Normalized()
		if err != nil || normalized.Name != entity.Name || normalized.Tags[0] != entity.Tags[0] {
			t.Fatal("normalization is not idempotent")
		}
	})
}
