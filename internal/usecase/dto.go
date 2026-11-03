package usecase

import "time"

// ThreatData is the application input for replaceable threat attributes.
type ThreatData struct {
	Name        string
	Description string
	Severity    string
	Tags        []string
}

// CreateThreatInput describes a create operation.
type CreateThreatInput struct {
	MD5  string
	Data ThreatData
}

// GetThreatInput identifies the threat to retrieve.
type GetThreatInput struct{ MD5 string }

// UpdateThreatInput describes a complete replacement of mutable attributes.
type UpdateThreatInput struct {
	MD5  string
	Data ThreatData
}

// ThreatOutput is the application representation of a persisted threat.
type ThreatOutput struct {
	MD5         string
	Name        string
	Description string
	Severity    string
	Tags        []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CreateThreatOutput contains the created threat.
type CreateThreatOutput ThreatOutput

// GetThreatOutput contains the retrieved threat.
type GetThreatOutput ThreatOutput

// UpdateThreatOutput contains the updated threat.
type UpdateThreatOutput ThreatOutput
