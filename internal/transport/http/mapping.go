package httptransport

import (
	"github.com/hel1th/sec-info-exchange/internal/api/generated"
	"github.com/hel1th/sec-info-exchange/internal/usecase"
)

func toCreateInput(req generated.ThreatCreateRequest) usecase.CreateThreatInput {
	return usecase.CreateThreatInput{
		MD5:  req.Md5,
		Data: toThreatData(req.Name, string(req.Severity), req.Description, req.Tags),
	}
}

func toUpdateInput(md5 string, req generated.ThreatUpdateRequest) usecase.UpdateThreatInput {
	return usecase.UpdateThreatInput{
		MD5: md5, Data: toThreatData(req.Name, string(req.Severity), req.Description, req.Tags),
	}
}

func toThreatData(name, severity string, description *string, tags *[]string) usecase.ThreatData {
	data := usecase.ThreatData{Name: name, Severity: severity}
	if description != nil {
		data.Description = *description
	}
	if tags != nil {
		data.Tags = append([]string{}, (*tags)...)
	}
	return data
}

func toThreatResponse(t usecase.ThreatOutput) generated.ThreatResponse {
	return generated.ThreatResponse{
		Md5: t.MD5, Name: t.Name, Description: t.Description,
		Severity: generated.ThreatResponseSeverity(t.Severity),
		Tags:     append([]string{}, t.Tags...), CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}
}
