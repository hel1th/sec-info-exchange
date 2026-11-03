package usecase

import "github.com/hel1th/sec-info-exchange/internal/domain"

func toDomainData(data ThreatData) domain.ThreatData {
	return domain.ThreatData{
		Name: data.Name, Description: data.Description,
		Severity: domain.Severity(data.Severity), Tags: append([]string{}, data.Tags...),
	}
}

func toThreatOutput(entity domain.Threat) ThreatOutput {
	return ThreatOutput{
		MD5: entity.MD5, Name: entity.Name, Description: entity.Description,
		Severity: string(entity.Severity), Tags: append([]string{}, entity.Tags...),
		CreatedAt: entity.CreatedAt, UpdatedAt: entity.UpdatedAt,
	}
}
